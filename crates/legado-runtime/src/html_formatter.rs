use std::sync::OnceLock;

use regex::{Captures, Regex};

pub(crate) fn format_intro(html: &str) -> String {
    if keeps_raw_markup(html) {
        html.trim_start().to_string()
    } else {
        format_with_tag_filter(html, false, false)
    }
}

pub(crate) fn format_content(html: &str) -> String {
    decode_html_entities(&format_with_tag_filter(html, true, true))
}

fn keeps_raw_markup(value: &str) -> bool {
    let trimmed = value.trim_start();
    trimmed.starts_with("<usehtml>")
        || trimmed.starts_with("<md>")
        || trimmed.starts_with("<useweb>")
}

fn format_with_tag_filter(html: &str, keep_img: bool, decode_entities: bool) -> String {
    let mut value = html.to_string();
    value = nbsp_re().replace_all(&value, " ").into_owned();
    value = space_entity_re().replace_all(&value, " ").into_owned();
    value = no_print_re().replace_all(&value, "").into_owned();
    value = wrap_tag_re().replace_all(&value, "\n").into_owned();
    value = comment_re().replace_all(&value, "").into_owned();
    value = strip_tags(&value, keep_img);
    value = newline_indent_re()
        .replace_all(&value, "\n　　")
        .into_owned();
    value = leading_indent_re().replace_all(&value, "　　").into_owned();
    value = trailing_whitespace_re()
        .replace_all(&value, "")
        .into_owned();
    if decode_entities {
        decode_html_entities(&value)
    } else {
        value
    }
}

fn strip_tags(html: &str, keep_img: bool) -> String {
    html_tag_re()
        .replace_all(html, |caps: &Captures<'_>| {
            if keep_img
                && caps
                    .get(1)
                    .is_some_and(|tag| tag.as_str().eq_ignore_ascii_case("img"))
            {
                caps.get(0)
                    .map(|whole| whole.as_str().to_string())
                    .unwrap_or_default()
            } else {
                String::new()
            }
        })
        .into_owned()
}

fn decode_html_entities(value: &str) -> String {
    html_entity_re()
        .replace_all(value, |caps: &Captures<'_>| {
            let entity = caps.get(1).map(|item| item.as_str()).unwrap_or_default();
            match entity {
                "amp" => "&".to_string(),
                "lt" => "<".to_string(),
                "gt" => ">".to_string(),
                "quot" => "\"".to_string(),
                "apos" => "'".to_string(),
                _ if entity.starts_with("#x") => u32::from_str_radix(&entity[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map(|ch| ch.to_string())
                    .unwrap_or_else(|| caps[0].to_string()),
                _ if entity.starts_with('#') => entity[1..]
                    .parse::<u32>()
                    .ok()
                    .and_then(char::from_u32)
                    .map(|ch| ch.to_string())
                    .unwrap_or_else(|| caps[0].to_string()),
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

fn nbsp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(&nbsp;)+").expect("valid nbsp regex"))
}

fn space_entity_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)&ensp;|&emsp;").expect("valid space entity regex"))
}

fn no_print_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)&thinsp;|&zwnj;|&zwj;|\u{2009}|\u{200C}|\u{200D}")
            .expect("valid no-print regex")
    })
}

fn wrap_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)</?(?:div|p|br|hr|h\d|article|dd|dl)[^>]*>").expect("valid wrap tag regex")
    })
}

fn comment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)<!--.*?-->").expect("valid comment regex"))
}

fn newline_indent_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s*\n+\s*").expect("valid newline indent regex"))
}

fn leading_indent_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[\n\s]+").expect("valid leading indent regex"))
}

fn trailing_whitespace_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\n\s]+$").expect("valid trailing whitespace regex"))
}

fn html_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)</?([a-zA-Z][a-zA-Z0-9]*)\b[^<>]*>").expect("valid html tag regex")
    })
}

fn html_entity_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"&(amp|lt|gt|quot|apos|#x[0-9a-fA-F]+|#[0-9]+);")
            .expect("valid html entity regex")
    })
}

#[cfg(test)]
mod tests {
    use super::{format_content, format_intro};

    #[test]
    fn intro_strips_html_tags_like_android_formatter() {
        assert_eq!(
            "　　hello\n　　world",
            format_intro("<p>hello</p><div>world</div>")
        );
    }

    #[test]
    fn intro_keeps_explicit_raw_markup_markers() {
        assert_eq!("<usehtml><b>x</b>", format_intro(" <usehtml><b>x</b>"));
    }

    #[test]
    fn content_strips_text_tags_but_keeps_images() {
        assert_eq!(
            "　　hello\n　　<img src=\"a.jpg\">",
            format_content("<p><span>hello</span></p><div><img src=\"a.jpg\"></div>")
        );
    }
}
