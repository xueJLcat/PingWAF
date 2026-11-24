use bytes::Bytes;
use http::{Method, header};
use pingap_core::{Ctx, HttpResponse, ModifyResponseBody};
use pingora::{http::ResponseHeader, proxy::Session};
use pingwaf_content::protection::{
    MAX_PAGE_BYTES, Policy, Rule, public_request, public_response,
};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct Selected {
    policy: Arc<Policy>,
    rule: Rule,
}

pub(crate) fn select(session: &mut Session, policy: Option<&Arc<Policy>>) {
    let Some(policy) = policy else { return };
    let req = session.req_header();
    let Some(rule) = policy.paths.get(req.uri.path()) else {
        return;
    };
    if let Err(reason) =
        public_request(&req.method, &req.headers, req.uri.query().is_some())
    {
        policy.event(rule, "skipped", reason);
        return;
    }
    session.req_header_mut().extensions_mut().insert(Selected {
        policy: policy.clone(),
        rule: rule.clone(),
    });
}

pub(crate) fn selected(session: &Session) -> Option<Selected> {
    session.req_header().extensions.get::<Selected>().cloned()
}

pub(crate) fn unavailable(session: &Session) {
    if let Some(page) = selected(session) {
        page.policy.event(&page.rule, "unavailable", "upstream");
    }
}

impl Selected {
    fn representation(
        &self,
        header: &ResponseHeader,
    ) -> Option<(String, String)> {
        if header.status.is_server_error() {
            self.policy.event(
                &self.rule,
                "unavailable",
                header.status.as_str(),
            );
            return None;
        }
        if let Err(reason) = public_response(header.status, &header.headers) {
            self.policy.event(&self.rule, "skipped", reason);
            return None;
        }
        let media = header
            .headers
            .get(header::CONTENT_TYPE)?
            .to_str()
            .ok()?
            .to_owned();
        let encoding = header
            .headers
            .get(header::CONTENT_ENCODING)
            .map_or(Ok(""), |h| h.to_str())
            .ok()?
            .to_ascii_lowercase();
        if header
            .headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .count()
            > 1
            || !matches!(
                encoding.as_str(),
                "" | "identity" | "gzip" | "deflate" | "br"
            )
        {
            self.policy.event(&self.rule, "skipped", "encoding");
            return None;
        }
        Some((media, encoding))
    }
}

struct Pending {
    page: Selected,
    media: String,
    encoding: String,
    buffered: Vec<u8>,
    passthrough: bool,
}

impl ModifyResponseBody for Pending {
    fn handle(
        &mut self,
        _: &Session,
        chunk: &mut Option<Bytes>,
        end: bool,
    ) -> pingora::Result<()> {
        if self.passthrough {
            return Ok(());
        }
        if let Some(bytes) = chunk.take() {
            if self.buffered.len().saturating_add(bytes.len()) > MAX_PAGE_BYTES
            {
                self.passthrough = true;
                self.page.policy.event(&self.page.rule, "skipped", "size");
                self.buffered.extend_from_slice(&bytes);
                *chunk = Some(std::mem::take(&mut self.buffered).into());
                return Ok(());
            }
            self.buffered.extend_from_slice(&bytes);
        }
        if end {
            let original = std::mem::take(&mut self.buffered);
            *chunk = Some(
                self.page
                    .policy
                    .compare(
                        &self.page.rule,
                        &self.media,
                        &self.encoding,
                        &original,
                    )
                    .unwrap_or(original)
                    .into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn start(
    session: &Session,
    ctx: &mut Ctx,
    header: &mut ResponseHeader,
) {
    let Some(page) = selected(session) else {
        return;
    };
    if ctx.upstream.stripped_managed_set_cookie {
        page.policy.event(&page.rule, "skipped", "set_cookie");
        return;
    }
    let Some((media, encoding)) = page.representation(header) else {
        return;
    };
    if page.rule.trusted_copy
        && let Some(approved) = &page.rule.approved
    {
        // Only relabel a representation when the complete identity body fits,
        // so a decoding or size fallback never receives the approved MIME type.
        if approved.media_type != media {
            let bounded = header
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .is_some_and(|n| n <= MAX_PAGE_BYTES);
            if !bounded
                || !matches!(encoding.as_str(), "" | "identity")
                || pingwaf_content::protection::body_digest(&approved.body)
                    != approved.digest
            {
                page.policy.event(
                    &page.rule,
                    "detection_failed",
                    "media_type_changed",
                );
                return;
            }
            let _ = header.insert_header(
                header::CONTENT_TYPE,
                approved.media_type.as_str().to_owned(),
            );
        }
        for name in [
            header::CONTENT_LENGTH,
            header::ETAG,
            header::LAST_MODIFIED,
            header::ACCEPT_RANGES,
        ] {
            header.remove_header(&name);
        }
        header.remove_header("content-digest");
        let _ =
            header.insert_header(header::CACHE_CONTROL, "private, no-store");
    }
    if session.req_header().method == Method::HEAD {
        return;
    }
    ctx.add_modify_body_handler(
        "page_integrity",
        Box::new(Pending {
            page,
            media,
            encoding,
            buffered: Vec::new(),
            passthrough: false,
        }),
    );
}

pub(crate) fn local(
    session: &Session,
    response: &mut HttpResponse,
) -> pingora::Result<()> {
    let Some(page) = selected(session) else {
        return Ok(());
    };
    let header = response.new_response_header()?;
    let Some((media, encoding)) = page.representation(&header) else {
        return Ok(());
    };
    if let Some(bytes) =
        page.policy
            .compare(&page.rule, &media, &encoding, &response.body)
    {
        let headers = response.headers.get_or_insert_with(Vec::new);
        headers.retain(|(name, _)| {
            !matches!(
                name.as_str(),
                "content-type"
                    | "content-length"
                    | "cache-control"
                    | "last-modified"
                    | "etag"
                    | "content-digest"
                    | "accept-ranges"
            )
        });
        if let Some(approved) = page.rule.approved {
            if let Ok(value) = http::HeaderValue::from_str(&approved.media_type)
            {
                headers.push((header::CONTENT_TYPE, value));
            }
        }
        headers.push((
            header::CACHE_CONTROL,
            http::HeaderValue::from_static("private, no-store"),
        ));
        response.body = bytes.into();
    }
    Ok(())
}
