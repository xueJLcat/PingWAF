//! Rewrite explicit leaf text regions without inserting scripts or changing the DOM.
use lol_html::{
    RewriteStrSettings, element, html_content::ContentType, rewrite_str, text,
};
use std::{cell::Cell, fmt::Write};

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id.as_bytes()[0].is_ascii_alphabetic()
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
}

pub fn transform(bytes: &[u8], id: &str) -> Result<Vec<u8>, &'static str> {
    if !valid_id(id) {
        return Err("region_id");
    }
    if bytes.len() > super::protection::MAX_PAGE_BYTES {
        return Err("size");
    }
    let original = std::str::from_utf8(bytes).map_err(|_| "charset")?;
    let selector = format!("#{id}");
    let descendant = format!("{selector} *");
    let excluded = [
        "a",
        "button",
        "form",
        "label",
        "select",
        "textarea",
        "script",
        "style",
        "template",
        "noscript",
        "svg",
        "math",
        "head",
        "[contenteditable]",
        "[role]",
    ]
    .iter()
    .map(|tag| format!("{tag} {selector}, {tag}{selector}"))
    .collect::<Vec<_>>()
    .join(",");
    let count = Cell::new(0usize);
    let characters = Cell::new(0usize);
    let unsafe_region = Cell::new(false);
    let salt = rand::random::<u64>();
    let result = rewrite_str(
        original,
        RewriteStrSettings::new()
            .append_element_content_handler(element!("meta", |el| {
                if el.get_attribute("http-equiv").is_some_and(|v| {
                    v.eq_ignore_ascii_case("content-security-policy")
                        || v.eq_ignore_ascii_case("content-type")
                }) || el
                    .get_attribute("charset")
                    .is_some_and(|v| !v.eq_ignore_ascii_case("utf-8"))
                {
                    unsafe_region.set(true);
                }
                Ok(())
            }))
            .append_element_content_handler(element!(selector.as_str(), |el| {
                count.set(count.get() + 1);
                if !matches!(
                    el.tag_name().as_str(),
                    "p" | "span"
                        | "div"
                        | "h1"
                        | "h2"
                        | "h3"
                        | "h4"
                        | "h5"
                        | "h6"
                        | "li"
                        | "td"
                        | "th"
                        | "strong"
                        | "em"
                ) {
                    unsafe_region.set(true);
                }
                Ok(())
            }))
            .append_element_content_handler(element!(
                descendant.as_str(),
                |_| {
                    unsafe_region.set(true);
                    Ok(())
                }
            ))
            .append_element_content_handler(element!(excluded.as_str(), |_| {
                unsafe_region.set(true);
                Ok(())
            }))
            .append_element_content_handler(text!(
                selector.as_str(),
                |chunk| {
                    let raw = chunk.as_str();
                    if raw.contains('&')
                        || raw
                            .chars()
                            .any(|c| c.is_control() && !c.is_ascii_whitespace())
                    {
                        unsafe_region.set(true);
                        return Ok(());
                    }
                    if unsafe_region.get() || raw.is_empty() {
                        return Ok(());
                    }
                    let mut encoded = String::new();
                    for ch in raw.chars() {
                        if characters.get() >= 8192 {
                            unsafe_region.set(true);
                            return Ok(());
                        }
                        let index = characters.get();
                        characters.set(index + 1);
                        let width =
                            1 + ((salt.rotate_left(index as u32) & 7) as usize);
                        write!(
                            encoded,
                            "&#x{:0width$x};",
                            ch as u32,
                            width = width
                        )
                        .unwrap();
                    }
                    chunk.replace(&encoded, ContentType::Html);
                    Ok(())
                }
            )),
    )
    .map_err(|_| "html_parse")?;
    if unsafe_region.get() || count.get() != 1 || characters.get() == 0 {
        return Err("region_not_plain_text");
    }
    if result.len() > super::protection::MAX_PAGE_BYTES {
        return Err("size");
    }
    Ok(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn changes_only_explicit_text() {
        let page =
            r#"<p id="region">中文 text</p><a href="/path">中文 text</a>"#;
        let a = transform(page.as_bytes(), "region").unwrap();
        let b = transform(page.as_bytes(), "region").unwrap();
        assert_ne!(a, b);
        assert!(
            std::str::from_utf8(&a)
                .unwrap()
                .ends_with(r#"</p><a href="/path">中文 text</a>"#)
        );
        for bad in [
            r#"<a><span id="region">text</span></a>"#,
            r#"<p id="region"><b>text</b></p>"#,
            r#"<p id="region">a&amp;b</p>"#,
        ] {
            assert!(transform(bad.as_bytes(), "region").is_err());
        }
    }
}
