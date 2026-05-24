use chrono::DateTime;
use percent_encoding::percent_decode_str;
use scraper::{Html, Selector};
use serde::Serialize;
use url::Url;

use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavFileEntry {
    pub url: String,
    pub display_name: String,
    pub url_name: String,
    pub size: i64,
    pub content_type: String,
    pub resource_type: String,
    pub last_modify: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebDavErrorBody {
    pub exception: String,
    pub message: String,
}

pub fn parse_webdav_listing(
    body: &str,
    request_url: &str,
    original_path: &str,
) -> Result<Vec<WebDavFileEntry>> {
    match parse_webdav_xml_listing(body, request_url, original_path) {
        Ok(entries) if !entries.is_empty() => Ok(entries),
        _ => parse_webdav_html_listing(body, request_url),
    }
}

pub fn parse_webdav_error_body(body: &str) -> WebDavErrorBody {
    if let Ok(document) = roxmltree::Document::parse(body) {
        return WebDavErrorBody {
            exception: first_node_text(&document, "exception").unwrap_or_default(),
            message: first_node_text(&document, "message").unwrap_or_default(),
        };
    }
    let fragment = Html::parse_document(body);
    WebDavErrorBody {
        exception: select_first_text(&fragment, r#"s\:exception"#)
            .or_else(|| select_first_text(&fragment, "exception"))
            .unwrap_or_default(),
        message: select_first_text(&fragment, r#"s\:message"#)
            .or_else(|| select_first_text(&fragment, "message"))
            .unwrap_or_default(),
    }
}

fn parse_webdav_xml_listing(
    body: &str,
    request_url: &str,
    original_path: &str,
) -> Result<Vec<WebDavFileEntry>> {
    let document = roxmltree::Document::parse(body).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("failed to parse WebDAV XML response for {request_url}: {err}"),
        )
    })?;
    let base_url = base_url(request_url)?;
    let mut entries = Vec::new();
    for response in document
        .descendants()
        .filter(|node| node.is_element() && tag_eq(node, "response"))
    {
        let Some(href) = child_text(response, "href") else {
            continue;
        };
        let href_decode = percent_decode_str(href.trim())
            .decode_utf8_lossy()
            .into_owned();
        let file_name = href_decode
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let url_name = if href_decode.is_empty() {
            original_path.replace('/', "")
        } else {
            href_decode.clone()
        };
        let display_name = child_text(response, "displayname")
            .filter(|value| !value.is_empty())
            .map(|value| percent_decode_str(&value).decode_utf8_lossy().into_owned())
            .unwrap_or_else(|| file_name.clone());
        let content_type = child_text(response, "getcontenttype").unwrap_or_default();
        let resource_type = resource_type_html(response);
        let size = child_text(response, "getcontentlength")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default();
        let last_modify = child_text(response, "getlastmodified")
            .and_then(|value| DateTime::parse_from_rfc2822(&value).ok())
            .map(|time| time.timestamp_millis())
            .unwrap_or_default();
        let mut full_url = resolve_url(&base_url, &href_decode)?;
        if is_dir(&content_type, &resource_type) && !full_url.ends_with('/') {
            full_url.push('/');
        }
        entries.push(WebDavFileEntry {
            url: full_url,
            display_name,
            url_name,
            size,
            content_type,
            resource_type,
            last_modify,
        });
    }
    Ok(entries)
}

fn parse_webdav_html_listing(body: &str, request_url: &str) -> Result<Vec<WebDavFileEntry>> {
    let document = Html::parse_document(body);
    let selector = Selector::parse("a").map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("failed to parse WebDAV HTML selector for {request_url}: {err}"),
        )
    })?;
    let base = base_url(request_url)?;
    let mut entries = Vec::new();
    for element in document.select(&selector) {
        let href = element.value().attr("href").unwrap_or_default().trim();
        if href.is_empty() || href == "../" || href == "/" {
            continue;
        }
        let href_decode = percent_decode_str(href).decode_utf8_lossy().into_owned();
        let mut url = resolve_url(&base, &href_decode)?;
        let is_dir = href_decode.ends_with('/');
        if is_dir && !url.ends_with('/') {
            url.push('/');
        }
        let fallback_name = href_decode
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let display_name = element
            .text()
            .collect::<Vec<_>>()
            .join("")
            .trim()
            .trim_end_matches('/')
            .to_string();
        entries.push(WebDavFileEntry {
            url,
            display_name: if display_name.is_empty() {
                fallback_name.clone()
            } else {
                display_name
            },
            url_name: href_decode,
            size: 0,
            content_type: if is_dir {
                "httpd/unix-directory".to_string()
            } else {
                String::new()
            },
            resource_type: if is_dir {
                "<collection></collection>".to_string()
            } else {
                String::new()
            },
            last_modify: 0,
        });
    }
    Ok(entries)
}

fn first_node_text(document: &roxmltree::Document<'_>, local_name: &str) -> Option<String> {
    document
        .descendants()
        .find(|node| node.is_element() && tag_eq(node, local_name))
        .and_then(|node| node.text())
        .map(|value| value.trim().to_string())
}

fn child_text(node: roxmltree::Node<'_, '_>, local_name: &str) -> Option<String> {
    node.descendants()
        .find(|child| child.is_element() && tag_eq(child, local_name))
        .and_then(|child| child.text())
        .map(|value| value.trim().to_string())
}

fn resource_type_html(response: roxmltree::Node<'_, '_>) -> String {
    let Some(resource_type) = response
        .descendants()
        .find(|node| node.is_element() && tag_eq(node, "resourcetype"))
    else {
        return String::new();
    };
    let children = resource_type
        .children()
        .filter(|node| node.is_element())
        .map(|node| format!("<{}></{}>", node.tag_name().name(), node.tag_name().name()))
        .collect::<String>();
    children.trim().to_string()
}

fn tag_eq(node: &roxmltree::Node<'_, '_>, local_name: &str) -> bool {
    node.tag_name().name().eq_ignore_ascii_case(local_name)
}

fn select_first_text(document: &Html, selector: &str) -> Option<String> {
    let selector = Selector::parse(selector).ok()?;
    document.select(&selector).next().map(|element| {
        element
            .text()
            .collect::<Vec<_>>()
            .join("")
            .trim()
            .to_string()
    })
}

fn base_url(request_url: &str) -> Result<Url> {
    let parsed = Url::parse(request_url).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("invalid WebDAV request URL `{request_url}`: {err}"),
        )
    })?;
    parsed.join(".").map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("failed to derive WebDAV base URL from `{request_url}`: {err}"),
        )
    })
}

fn resolve_url(base: &Url, href: &str) -> Result<String> {
    base.join(href).map(|url| url.to_string()).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("failed to resolve WebDAV href `{href}` against `{base}`: {err}"),
        )
    })
}

fn is_dir(content_type: &str, resource_type: &str) -> bool {
    content_type == "httpd/unix-directory" || resource_type.to_lowercase().contains("collection")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_namespaced_propfind_listing_like_android_jsoup_path() {
        let entries = parse_webdav_listing(
            r#"<?xml version="1.0" encoding="utf-8"?>
            <d:multistatus xmlns:d="DAV:">
              <d:response>
                <d:href>/dav/</d:href>
                <d:propstat><d:prop><d:displayname>dav</d:displayname><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat>
              </d:response>
              <d:response>
                <d:href>/dav/book%20one.txt</d:href>
                <d:propstat><d:prop><d:displayname>book%20one.txt</d:displayname><d:getcontenttype>text/plain</d:getcontenttype><d:getcontentlength>9</d:getcontentlength><d:getlastmodified>Wed, 21 Oct 2015 07:28:00 GMT</d:getlastmodified><d:resourcetype/></d:prop></d:propstat>
              </d:response>
            </d:multistatus>"#,
            "https://example.test/dav/",
            "/dav/",
        )
        .expect("listing");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].url, "https://example.test/dav/");
        assert_eq!(entries[0].resource_type, "<collection></collection>");
        assert_eq!(entries[1].url, "https://example.test/dav/book%20one.txt");
        assert_eq!(entries[1].display_name, "book one.txt");
        assert_eq!(entries[1].size, 9);
        assert_eq!(entries[1].last_modify, 1_445_412_480_000);
    }

    #[test]
    fn parses_caddy_style_html_directory_listing() {
        let entries = parse_webdav_listing(
            r#"<html><body><a href="../">Parent</a><a href="folder/">folder/</a><a href="book.txt">book.txt</a></body></html>"#,
            "https://example.test/dav/",
            "/dav/",
        )
        .expect("listing");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].url, "https://example.test/dav/folder/");
        assert_eq!(entries[0].display_name, "folder");
        assert_eq!(entries[1].url, "https://example.test/dav/book.txt");
    }

    #[test]
    fn parses_webdav_error_body() {
        let err = parse_webdav_error_body(
            r#"<s:error xmlns:s="http://sabredav.org/ns"><s:exception>ObjectNotFound</s:exception><s:message>missing</s:message></s:error>"#,
        );
        assert_eq!(err.exception, "ObjectNotFound");
        assert_eq!(err.message, "missing");
    }
}
