// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use http::{
    HeaderMap,
    header::{COOKIE, SET_COOKIE},
};
use pingap_core::{
    Ctx, MANAGED_COOKIE_PREFIX, convert_header_value, sets_managed_cookie,
    without_managed_cookies,
};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;

pub(super) fn strip_managed_request_cookies(
    header: &mut RequestHeader,
) -> pingora::Result<()> {
    let fields = header.headers.get_all(COOKIE);
    if fields.iter().any(|value| {
        value
            .as_bytes()
            .windows(MANAGED_COOKIE_PREFIX.len())
            .any(|bytes| bytes == MANAGED_COOKIE_PREFIX.as_bytes())
    }) {
        let retained: Vec<_> =
            fields.iter().filter_map(without_managed_cookies).collect();
        header.remove_header(&COOKIE);
        for field in retained {
            header.append_header(COOKIE, field)?;
        }
    }
    Ok(())
}

pub(super) fn strip_managed_response_cookies(
    header: &mut ResponseHeader,
) -> pingora::Result<bool> {
    let fields = header.headers.get_all(SET_COOKIE);
    if !fields.iter().any(sets_managed_cookie) {
        return Ok(false);
    }
    let retained: Vec<_> = fields
        .iter()
        .filter(|field| !sets_managed_cookie(field))
        .cloned()
        .collect();
    header.remove_header(&SET_COOKIE);
    for field in retained {
        header.append_header(SET_COOKIE, field)?;
    }
    Ok(true)
}

pub(super) fn strip_managed_trailer_cookies(trailers: &mut HeaderMap) {
    let fields = trailers.get_all(SET_COOKIE);
    if fields.iter().any(sets_managed_cookie) {
        let retained: Vec<_> = fields
            .iter()
            .filter(|field| !sets_managed_cookie(field))
            .cloned()
            .collect();
        trailers.remove(SET_COOKIE);
        for field in retained {
            trailers.append(SET_COOKIE, field);
        }
    }
}

/// Returns true when the header value may contain a `$…` / `:…` substitution.
#[inline]
fn is_dynamic_header_value(value: &http::HeaderValue) -> bool {
    let buf = value.as_bytes();
    !buf.is_empty() && (buf[0] == b'$' || buf[0] == b':')
}

/// Sets or appends proxy-related headers before forwarding request
/// Handles both default reverse proxy headers and custom configured headers
#[inline]
pub fn set_append_proxy_headers(
    session: &Session,
    ctx: &Ctx,
    header: &mut RequestHeader,
) {
    if let Some(location) = &ctx.upstream.location_instance
        && let Some(headers) = location.headers()
    {
        if location.standard_proxy_headers() {
            header.remove_header("forwarded");
        }
        for (k, v, append) in headers {
            // Static values skip convert_header_value entirely (common for
            // proxy_set_headers / proxy_add_headers without `$` substitutions).
            let value = if is_dynamic_header_value(v) {
                match convert_header_value(v, session, ctx) {
                    Some(value) => value,
                    None if location.standard_proxy_headers()
                        && (v.as_bytes().starts_with(b"$proxy_client_")
                            || v.as_bytes() == b"$proxy_request_host"
                            || k == "x-forwarded-port") =>
                    {
                        header.remove_header(k);
                        continue;
                    },
                    None => v.clone(),
                }
            } else {
                v.clone()
            };
            if *append {
                let _ = header.append_header(k, value);
            } else {
                let _ = header.insert_header(k, value);
            }
        }
    }
    // `upstream_host` is the explicit knob for "which virtual host the
    // origin sees"; it wins over any Host entry in the proxy headers above
    // so the effective value is unambiguous. Applied outside the headers
    // block: a location that only sets upstream_host has no proxy headers,
    // and the override used to be skipped in exactly that case
    // (2026-10-19 review).
    if let Some(location) = &ctx.upstream.location_instance
        && let Some(host) = location.upstream_host()
    {
        let _ = header.insert_header(http::header::HOST, host.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::LocationConf;
    use pingap_core::Ctx;
    use pingap_location::Location;
    use pingora::{http::RequestHeader, proxy::Session};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use tokio_test::io::Builder;

    #[test]
    fn managed_cookie_filter_handles_all_fields_and_preserves_app_values() {
        use http::HeaderValue;

        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request
            .append_header(COOKIE, "__pingwaf_managed_oidc_one=secret")
            .unwrap();
        request.append_header(COOKIE, HeaderValue::from_bytes(b"theme=\xff;\t__pingwaf_managed_clearance_two = pass; cart=3").unwrap()).unwrap();
        request
            .append_header(
                COOKIE,
                "note=__pingwaf_managed_literal; __pingwaf_clearance=legacy",
            )
            .unwrap();
        request
            .append_header(
                COOKIE,
                "bad=1, __pingwaf_managed_visitor_three=value",
            )
            .unwrap();
        strip_managed_request_cookies(&mut request).unwrap();
        let values = request
            .headers
            .get_all(COOKIE)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            [
                b"theme=\xff; cart=3".as_slice(),
                b"note=__pingwaf_managed_literal; __pingwaf_clearance=legacy"
                    .as_slice()
            ]
        );

        let mut response = ResponseHeader::build(200, None).unwrap();
        let normal = "lang=en; Expires=Mon, 01 Jan 2040 00:00:00 GMT";
        for value in [
            normal,
            "__pingwaf_managed_oidc_one=secret",
            "bad=1, __pingwaf_managed_visitor_three=value",
            "theme=dark",
        ] {
            response.append_header(SET_COOKIE, value).unwrap();
        }
        assert!(strip_managed_response_cookies(&mut response).unwrap());
        assert!(!strip_managed_response_cookies(&mut response).unwrap());
        assert_eq!(
            response
                .headers
                .get_all(SET_COOKIE)
                .iter()
                .collect::<Vec<_>>(),
            [normal, "theme=dark"]
        );

        let mut trailers = HeaderMap::new();
        trailers.append(
            SET_COOKIE,
            HeaderValue::from_static("__pingwaf_managed_state_a=x"),
        );
        trailers.append("grpc-status", HeaderValue::from_static("0"));
        strip_managed_trailer_cookies(&mut trailers);
        assert!(!trailers.contains_key(SET_COOKIE));
        assert_eq!(trailers["grpc-status"], "0");
    }

    async fn new_session() -> Session {
        let headers = [
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Uuid: 138q71",
            "X-Forwarded-For: 1.1.1.1, 192.168.1.2",
        ]
        .join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?key=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    #[tokio::test]
    async fn test_set_append_proxy_headers() {
        let session = new_session().await;
        let mut ctx = Ctx::default();
        ctx.conn.remote_addr = Some("192.168.1.3".to_string());
        ctx.conn.server_port = Some(8080);
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        let location = Arc::new(
            Location::new(
                "test",
                &LocationConf {
                    enable_reverse_proxy_headers: Some(true),
                    proxy_add_headers: Some(vec![
                        "x-server:123".to_string(),
                        "x-server:456".to_string(),
                    ]),
                    proxy_set_headers: Some(vec!["x-trace-id:ab".to_string()]),
                    ..Default::default()
                },
            )
            .unwrap(),
        );
        ctx.upstream.location_instance = Some(location);
        header
            .append_header("x-forwarded-for", "192.0.2.9")
            .unwrap();
        header
            .append_header("x-forwarded-for", "192.0.2.10")
            .unwrap();
        header.append_header("forwarded", "for=192.0.2.9").unwrap();
        set_append_proxy_headers(&session, &ctx, &mut header);
        assert_eq!(1, header.headers.get_all("x-forwarded-for").iter().count());
        assert!(header.headers.get("forwarded").is_none());

        assert_eq!(
            "192.168.1.3",
            header.headers.get("x-real-ip").unwrap().to_str().unwrap()
        );
        assert_eq!(
            "192.168.1.3",
            header
                .headers
                .get("x-forwarded-for")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "http",
            header
                .headers
                .get("x-forwarded-proto")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "github.com",
            header
                .headers
                .get("x-forwarded-host")
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(
            "8080",
            header
                .headers
                .get("x-forwarded-port")
                .unwrap()
                .to_str()
                .unwrap()
        );

        assert_eq!(
            "123,456",
            header
                .headers
                .get_all("x-server")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            "ab",
            header.headers.get("x-trace-id").unwrap().to_str().unwrap()
        );
    }
}
