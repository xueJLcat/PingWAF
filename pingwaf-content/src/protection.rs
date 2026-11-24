//! Eligibility and integrity decisions shared by static and proxied pages.
use http::{HeaderMap, Method, StatusCode, header};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

pub const MAX_PAGE_BYTES: usize = 512 * 1024;

pub fn public_request(
    method: &Method,
    headers: &HeaderMap,
    has_query: bool,
) -> Result<(), &'static str> {
    if method != Method::GET && method != Method::HEAD {
        return Err("method");
    }
    if has_query {
        return Err("query");
    }
    if [
        header::COOKIE,
        header::AUTHORIZATION,
        header::PROXY_AUTHORIZATION,
    ]
    .iter()
    .any(|h| headers.contains_key(h))
    {
        return Err("credentials");
    }
    if headers.contains_key(header::RANGE) {
        return Err("range");
    }
    if [
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-forwarded-user",
        "x-auth-request-user",
        "x-client-cert",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
    {
        return Err("credentials");
    }
    Ok(())
}

pub fn public_response(
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<(), &'static str> {
    if status != StatusCode::OK {
        return Err("status");
    }
    if headers.contains_key(header::SET_COOKIE) {
        return Err("set_cookie");
    }
    if headers.contains_key(header::CONTENT_RANGE) {
        return Err("range");
    }
    if headers.contains_key(header::CONTENT_DISPOSITION) {
        return Err("disposition");
    }
    for value in headers.get_all(header::CACHE_CONTROL) {
        if value
            .to_str()
            .map_err(|_| "cache_control")?
            .split(',')
            .any(|d| {
                let key = d.split('=').next().unwrap_or("").trim();
                ["private", "no-store"]
                    .iter()
                    .any(|k| key.eq_ignore_ascii_case(k))
            })
        {
            return Err("private_cache");
        }
    }
    for value in headers.get_all(header::VARY) {
        if value
            .to_str()
            .map_err(|_| "vary")?
            .split(',')
            .any(|v| !v.trim().eq_ignore_ascii_case("accept-encoding"))
        {
            return Err("vary");
        }
    }
    if let Some(size) = headers.get(header::CONTENT_LENGTH) {
        if size
            .to_str()
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .is_none_or(|n| n > MAX_PAGE_BYTES)
        {
            return Err("size");
        }
    }
    let mime = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        mime.as_str(),
        "text/html"
            | "text/plain"
            | "text/css"
            | "application/javascript"
            | "text/javascript"
    ) {
        return Err("content_type");
    }
    Ok(())
}

pub fn decoded_body(
    encoding: &str,
    input: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if input.len() > MAX_PAGE_BYTES {
        return Err("size");
    }
    let source = Cursor::new(input);
    let reader: Box<dyn Read + '_> =
        match encoding.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => return Ok(input.to_vec()),
            "gzip" => Box::new(flate2::read::MultiGzDecoder::new(source)),
            "deflate" => Box::new(flate2::read::ZlibDecoder::new(source)),
            "br" => Box::new(brotli::Decompressor::new(source, 4096)),
            _ => return Err("encoding"),
        };
    let mut result = Vec::new();
    reader
        .take(MAX_PAGE_BYTES as u64 + 1)
        .read_to_end(&mut result)
        .map_err(|_| "decode_failure")?;
    if result.len() > MAX_PAGE_BYTES {
        return Err("size");
    }
    Ok(result)
}

pub fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

#[derive(Clone)]
pub struct Rule {
    pub id: String,
    pub trusted_copy: bool,
    pub approved: Option<Approved>,
}

#[derive(Clone)]
pub struct Approved {
    pub digest: String,
    pub media_type: String,
    pub body: std::sync::Arc<[u8]>,
}

pub struct Observation {
    pub rule: String,
    pub category: &'static str,
    pub detail: String,
    pub media_type: String,
    pub candidate: Option<Vec<u8>>,
}

pub struct Policy {
    pub paths: std::collections::HashMap<String, Rule>,
    pub report: Box<dyn Fn(Observation) + Send + Sync>,
}

impl Policy {
    pub fn event(&self, rule: &Rule, category: &'static str, detail: &str) {
        (self.report)(Observation {
            rule: rule.id.clone(),
            category,
            detail: detail.to_owned(),
            media_type: String::new(),
            candidate: None,
        });
    }

    /// Compare a complete public representation before it is sent to the visitor.
    /// The caller applies the chosen media type and encoding to the response.
    pub fn compare(
        &self,
        rule: &Rule,
        media_type: &str,
        encoding: &str,
        raw: &[u8],
    ) -> Option<Vec<u8>> {
        let decoded = match decoded_body(encoding, raw) {
            Ok(body) => body,
            Err(reason) => {
                self.event(rule, "detection_failed", reason);
                return None;
            },
        };
        let digest = body_digest(&decoded);
        let category = if let Some(approved) = &rule.approved {
            if body_digest(&approved.body) != approved.digest {
                self.event(rule, "copy_corrupt", &approved.digest);
                return None;
            }
            if digest == approved.digest && media_type == approved.media_type {
                return None;
            }
            "changed"
        } else {
            "capture"
        };
        (self.report)(Observation {
            rule: rule.id.clone(),
            category,
            detail: digest,
            media_type: media_type.to_owned(),
            candidate: Some(decoded),
        });
        if !rule.trusted_copy {
            return None;
        }
        let approved = rule.approved.as_ref()?;
        encode_body(encoding, &approved.body)
            .map_err(|_| self.event(rule, "detection_failed", "encode_failure"))
            .ok()
    }
}

fn encode_body(encoding: &str, body: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    match encoding.trim().to_ascii_lowercase().as_str() {
        "" | "identity" => Ok(body.to_vec()),
        "br" => {
            let mut encoded = Vec::new();
            {
                let mut compressor =
                    brotli::CompressorWriter::new(&mut encoded, 4096, 3, 20);
                compressor.write_all(body)?;
            }
            Ok(encoded)
        },
        "gzip" => {
            let mut compressor = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            );
            compressor.write_all(body)?;
            compressor.finish()
        },
        "deflate" => {
            let mut compressor = flate2::write::ZlibEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            );
            compressor.write_all(body)?;
            compressor.finish()
        },
        _ => Err(std::io::Error::other("unsupported encoding")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn private_responses_and_requests_are_ineligible() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "text/html; charset=utf-8".parse().unwrap(),
        );
        assert!(public_response(StatusCode::OK, &headers).is_ok());
        headers.append(header::CACHE_CONTROL, "public".parse().unwrap());
        headers
            .append(header::CACHE_CONTROL, "Private=\"X-ID\"".parse().unwrap());
        assert_eq!(
            public_response(StatusCode::OK, &headers),
            Err("private_cache")
        );
        headers.insert(header::COOKIE, "x=y".parse().unwrap());
        assert_eq!(
            public_request(&Method::HEAD, &headers, false),
            Err("credentials")
        );
    }

    #[test]
    fn comparison_uses_bounded_decoded_bytes() {
        fn gzip(bytes: &[u8]) -> Vec<u8> {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), Default::default());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        }
        assert_eq!(decoded_body("gzip", &gzip(b"page")).unwrap(), b"page");
        assert_eq!(
            decoded_body("gzip", &gzip(&vec![0; MAX_PAGE_BYTES + 1])),
            Err("size")
        );
        assert_eq!(decoded_body("gzip", b"invalid"), Err("decode_failure"));
    }

    #[test]
    fn preserves_encoding_and_rejects_a_damaged_copy() {
        use std::sync::{Arc, Mutex};
        let observed = Arc::new(Mutex::new(Vec::new()));
        let log = observed.clone();
        let policy = Policy {
            paths: Default::default(),
            report: Box::new(move |event| {
                log.lock().unwrap().push(event.category)
            }),
        };
        let mut rule = Rule {
            id: "example".into(),
            trusted_copy: true,
            approved: Some(Approved {
                digest: body_digest(b"trusted"),
                media_type: "text/html".into(),
                body: Arc::from(b"trusted".as_slice()),
            }),
        };
        for encoding in ["identity", "gzip", "deflate", "br"] {
            let changed = encode_body(encoding, b"changed").unwrap();
            let result = policy
                .compare(&rule, "text/html", encoding, &changed)
                .unwrap();
            assert_eq!(decoded_body(encoding, &result).unwrap(), b"trusted");
        }
        rule.approved.as_mut().unwrap().body = Arc::from(b"damaged".as_slice());
        assert!(
            policy
                .compare(&rule, "text/html", "identity", b"changed")
                .is_none()
        );
        assert_eq!(
            *observed.lock().unwrap(),
            ["changed", "changed", "changed", "changed", "copy_corrupt"]
        );
    }
}
