use legado_runtime::{
    Analyzer, AnalyzerInput, AnalyzerSession, BookSource, RssAnalyzer, RssArticle, RssSource,
};
use serde::{Deserialize, Serialize};
use std::rc::Rc;

#[derive(Debug, thiserror::Error)]
enum BridgeError {
    #[error("invalid source JSON: {0}")]
    Source(String),
    #[error("invalid input JSON: {0}")]
    Input(String),
    #[error("invalid operation `{0}`")]
    Operation(String),
    #[error("{0}")]
    Analyzer(String),
    #[error("failed to serialize analyzer output: {0}")]
    Serialize(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BridgeInput {
    key: Option<String>,
    page: Option<i32>,
    book_url: Option<String>,
    toc_url: Option<String>,
    chapter_url: Option<String>,
    next_chapter_url: Option<String>,
    explore_url: Option<String>,
    script: Option<String>,
    result: Option<String>,
    base_url: Option<String>,
    rule_path: Option<String>,
    bindings_json: Option<String>,
    upload_file_name: Option<String>,
    upload_content_type: Option<String>,
    upload_body_base64: Option<String>,
    upload_compress: Option<bool>,
    speak_text: Option<String>,
    speak_speed: Option<i32>,
    use_web_view: Option<bool>,
    bootstrap_login_url: Option<bool>,
    run_pre_update_js: Option<bool>,
    sort_name: Option<String>,
}

impl From<BridgeInput> for AnalyzerInput {
    fn from(value: BridgeInput) -> Self {
        Self {
            key: value.key.unwrap_or_default(),
            page: value.page.unwrap_or(1),
            book_url: value.book_url.unwrap_or_default(),
            toc_url: value.toc_url.unwrap_or_default(),
            chapter_url: value.chapter_url.unwrap_or_default(),
            next_chapter_url: value.next_chapter_url.unwrap_or_default(),
            explore_url: value.explore_url.unwrap_or_default(),
            script: value.script.unwrap_or_default(),
            result: value.result.unwrap_or_default(),
            base_url: value.base_url.unwrap_or_default(),
            rule_path: value.rule_path.unwrap_or_default(),
            bindings_json: value.bindings_json.unwrap_or_default(),
            upload_file_name: value.upload_file_name.unwrap_or_default(),
            upload_content_type: value.upload_content_type.unwrap_or_default(),
            upload_body_base64: value.upload_body_base64.unwrap_or_default(),
            upload_compress: value.upload_compress.unwrap_or(false),
            speak_text: value.speak_text.unwrap_or_default(),
            speak_speed: value.speak_speed.unwrap_or_default(),
            use_web_view: value.use_web_view.unwrap_or(false),
            bootstrap_login_url: value.bootstrap_login_url.unwrap_or(false),
            run_pre_update_js: value.run_pre_update_js.unwrap_or(false),
        }
    }
}

fn analyze_json(source_json: String, operation: String, input_json: String) -> String {
    analyze_json_inner(source_json, operation, input_json, None)
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn configure_persistent_store(storage_dir: String) -> String {
    match legado_runtime::configure_persistent_store_dir(storage_dir) {
        Ok(()) => serde_json::json!({ "ok": true }).to_string(),
        Err(err) => serde_json::json!({ "ok": false, "error": err.to_string() }).to_string(),
    }
}

fn effective_domain(url: String) -> String {
    legado_runtime::effective_tld_plus_one(&url).unwrap_or_default()
}

fn fetch_raw_json(source_json: String, url: String) -> String {
    fetch_raw_json_inner(source_json, url)
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_text_array_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_text_array(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_charset_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_charset(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_format_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_format(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_title_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_title(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_first_alignment_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_first_alignment(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_native_entry_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_native_entry(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_readable_title_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_readable_title(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_book_info_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_book_info(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_footnote_ids_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_footnote_ids(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_footnote_target_json(html: String, target_id: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_footnote_target(
        &html, &target_id,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_readable_lines_json(html: String, delete_ruby: bool) -> String {
    serde_json::to_string(&legado_runtime::document::epub_readable_lines(
        &html,
        delete_ruby,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_body_html_json(html: String, start_fragment_id: String, end_fragment_id: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_body_html(
        &html,
        Some(&start_fragment_id),
        Some(&end_fragment_id),
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_debug_chapter_html_json(bodies_json: String, delete_ruby: bool) -> String {
    serde_json::to_string(&legado_runtime::document::epub_debug_chapter_html(
        &bodies_json,
        delete_ruby,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_image_options_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_image_options(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_image_page_marks_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_image_page_marks(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_materialized_images_json(
    html: String,
    base_href: String,
    resource_hrefs_json: String,
) -> String {
    serde_json::to_string(&legado_runtime::document::epub_materialized_images(
        &html,
        &base_href,
        &resource_hrefs_json,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_media_placeholders_json(html: String, base_href: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_media_placeholders(
        &html, &base_href,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_inline_styles_json(html: String, body_style: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_inline_styles(
        &html,
        &body_style,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_inherited_styles_json(html: String, body_style: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_inherited_styles(
        &html,
        &body_style,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_generated_content_json(body_outer_html: String, rules_json: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_generated_content(
        &body_outer_html,
        &rules_json,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_native_dom_json(body_outer_html: String, rules_json: String, base_href: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_native_dom(
        &body_outer_html,
        &rules_json,
        &base_href,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_applied_css_json(body_outer_html: String, rules_json: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_applied_css(
        &body_outer_html,
        &rules_json,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_resolved_links_json(html: String, base_href: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_resolved_links(
        &html, &base_href,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_body_background_image_json(body_style: String, body_background: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_body_background_image(
        &body_style,
        &body_background,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn epub_css_assets_json(document_html: String, body_html: String) -> String {
    serde_json::to_string(&legado_runtime::document::epub_css_assets(
        &document_html,
        &body_html,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_readable_table_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_readable_table(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_render_flags_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_render_flags(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_page_background_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_page_background(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_image_info_json(html: String) -> String {
    serde_json::to_string(&legado_runtime::document::html_image_info(&html))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn html_render_plan_json(html: String, classic_epub: bool) -> String {
    serde_json::to_string(&legado_runtime::document::html_render_plan(
        &html,
        classic_epub,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn mobi_content_html_json(html: String, rewrite_recindex_images: bool) -> String {
    serde_json::to_string(&legado_runtime::document::mobi_content_html(
        &html,
        rewrite_recindex_images,
    ))
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn parse_webdav_listing_json(body: String, request_url: String, original_path: String) -> String {
    match legado_runtime::webdav::parse_webdav_listing(&body, &request_url, &original_path) {
        Ok(entries) => serde_json::json!({ "files": entries }).to_string(),
        Err(err) => serde_json::json!({ "error": err.to_string() }).to_string(),
    }
}

fn parse_webdav_error_json(body: String) -> String {
    serde_json::to_string(&legado_runtime::webdav::parse_webdav_error_body(&body))
        .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

trait PlatformHost: Send {
    fn handle_platform_action(&self, api: String, source_name: String, args_json: String)
        -> String;
}

struct PlatformHostAdapter {
    host: Box<dyn PlatformHost>,
}

impl legado_runtime::PlatformHost for PlatformHostAdapter {
    fn handle_platform_action(&self, api: &str, source_name: &str, args_json: &str) -> String {
        self.host.handle_platform_action(
            api.to_string(),
            source_name.to_string(),
            args_json.to_string(),
        )
    }
}

fn analyze_json_with_platform(
    source_json: String,
    operation: String,
    input_json: String,
    platform_host: Box<dyn PlatformHost>,
) -> String {
    analyze_json_inner(
        source_json,
        operation,
        input_json,
        Some(Rc::new(PlatformHostAdapter {
            host: platform_host,
        })),
    )
    .unwrap_or_else(|err| serde_json::json!({ "error": err.to_string() }).to_string())
}

fn fetch_raw_json_inner(source_json: String, url: String) -> Result<String, BridgeError> {
    let source = BookSource::parse_first(&source_json)
        .map_err(|err| BridgeError::Source(err.to_string()))?;
    let mut analyzer = Analyzer::new(source, AnalyzerSession::default())
        .map_err(|err| BridgeError::Analyzer(err.to_string()))?;
    let output = analyzer
        .fetch_raw(AnalyzerInput {
            book_url: url,
            page: 1,
            rule_path: "fetchRaw".to_string(),
            ..AnalyzerInput::default()
        })
        .map_err(|err| BridgeError::Analyzer(err.to_string()))?;
    output
        .eval_result
        .ok_or_else(|| BridgeError::Analyzer("Rust fetchRaw did not return raw response".into()))
}

fn analyze_json_inner(
    source_json: String,
    operation: String,
    input_json: String,
    platform_host: Option<legado_runtime::PlatformHostRef>,
) -> Result<String, BridgeError> {
    if operation == "rssSorts" || operation == "rssArticles" || operation == "rssContent" {
        return analyze_rss_json_inner(source_json, operation, input_json, platform_host);
    }

    let source = BookSource::parse_first(&source_json)
        .map_err(|err| BridgeError::Source(err.to_string()))?;
    let input: AnalyzerInput = serde_json::from_str::<BridgeInput>(&input_json)
        .map_err(|err| BridgeError::Input(err.to_string()))?
        .into();
    let session = AnalyzerSession::default();

    let mut analyzer = Analyzer::new_with_platform(source, session, platform_host)
        .map_err(|err| BridgeError::Analyzer(err.to_string()))?;
    let output = match operation.as_str() {
        "search" => analyzer.search(input),
        "detail" => analyzer.detail(input),
        "toc" => analyzer.toc(input),
        "preUpdateToc" => analyzer.pre_update_toc(input),
        "content" => analyzer.content(input),
        "explore" => analyzer.explore(input),
        "eval" => analyzer.eval(input),
        "evalRule" => analyzer.eval_rule(input),
        "dictSearch" => analyzer.dict_search(input),
        "coverSearch" => analyzer.cover_search(input),
        "resolveUrl" => analyzer.resolve_url(input),
        "directLinkUpload" => analyzer.direct_link_upload(input),
        "fetchText" => analyzer.fetch_text(input),
        "fetchRaw" => analyzer.fetch_raw(input),
        other => return Err(BridgeError::Operation(other.to_string())),
    }
    .map_err(|err| BridgeError::Analyzer(err.to_string()))?;

    serde_json::to_string(&output).map_err(|err| BridgeError::Serialize(err.to_string()))
}

#[derive(Debug, Serialize)]
struct RssSortItem {
    name: String,
    url: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct RssBridgeOutput {
    #[serde(default)]
    rss_sorts: Vec<RssSortItem>,
    #[serde(default)]
    articles: Vec<RssArticle>,
    #[serde(default)]
    next_url: Option<String>,
    #[serde(default)]
    rss_content: Option<String>,
    diagnostics: Vec<String>,
    session: legado_runtime::analyzer::AnalyzerSessionSnapshot,
}

fn analyze_rss_json_inner(
    source_json: String,
    operation: String,
    input_json: String,
    platform_host: Option<legado_runtime::PlatformHostRef>,
) -> Result<String, BridgeError> {
    let source =
        RssSource::parse_first(&source_json).map_err(|err| BridgeError::Source(err.to_string()))?;
    let bridge_input = serde_json::from_str::<BridgeInput>(&input_json)
        .map_err(|err| BridgeError::Input(err.to_string()))?;
    let sort_name = bridge_input.sort_name.clone().unwrap_or_default();
    let input: AnalyzerInput = bridge_input.into();
    let session = AnalyzerSession::default();
    let mut analyzer = RssAnalyzer::new_with_platform(source, session, platform_host)
        .map_err(|err| BridgeError::Analyzer(err.to_string()))?;

    let output = match operation.as_str() {
        "rssSorts" => {
            let sorts = analyzer
                .sort_urls()
                .map_err(|err| BridgeError::Analyzer(err.to_string()))?;
            let session = analyzer.persisted_session_snapshot();
            RssBridgeOutput {
                rss_sorts: sorts
                    .into_iter()
                    .map(|(name, url)| RssSortItem { name, url })
                    .collect(),
                session,
                ..RssBridgeOutput::default()
            }
        }
        "rssArticles" => {
            let out = if input.explore_url.trim().is_empty() {
                analyzer
                    .search(&input.key, input.page.max(1))
                    .map_err(|err| BridgeError::Analyzer(err.to_string()))?
            } else {
                analyzer
                    .articles(
                        if sort_name.is_empty() {
                            "CLI"
                        } else {
                            &sort_name
                        },
                        &input.explore_url,
                        &input.key,
                        input.page.max(1),
                    )
                    .map_err(|err| BridgeError::Analyzer(err.to_string()))?
            };
            RssBridgeOutput {
                articles: out.articles,
                next_url: out.next_url,
                diagnostics: out.diagnostics,
                session: out.session,
                ..RssBridgeOutput::default()
            }
        }
        "rssContent" => {
            let article: RssArticle = serde_json::from_str(&input.result)
                .map_err(|err| BridgeError::Input(format!("invalid RSS article JSON: {err}")))?;
            let out = analyzer
                .content_with_rule(article, &input.script)
                .map_err(|err| BridgeError::Analyzer(err.to_string()))?;
            RssBridgeOutput {
                rss_content: out.content,
                diagnostics: out.diagnostics,
                session: out.session,
                ..RssBridgeOutput::default()
            }
        }
        other => return Err(BridgeError::Operation(other.to_string())),
    };

    serde_json::to_string(&output).map_err(|err| BridgeError::Serialize(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut temp = [0_u8; 4096];
        loop {
            let read = stream.read(&mut temp).unwrap();
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }

    #[test]
    fn fetch_raw_json_uses_analyzer_url_option_js() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /signed HTTP/1.1"), "{request}");
            assert!(request.contains("x-debug: 1"));
            let body = b"bridge-bytes";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let source_json = serde_json::json!([{
            "bookSourceName": "raw bridge",
            "bookSourceUrl": base
        }])
        .to_string();
        let response = fetch_raw_json_inner(
            source_json,
            format!(
                "{base}/start,{{\"js\":\"result.replace('start','signed')\",\"headers\":{{\"X-Debug\":\"1\"}}}}"
            ),
        )
        .unwrap();
        handle.join().unwrap();
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();

        assert_eq!(value["code"].as_i64(), Some(200));
        assert_eq!(value["bodyBase64"].as_str(), Some("YnJpZGdlLWJ5dGVz"));
        assert_eq!(
            value["contentType"].as_str(),
            Some("application/octet-stream")
        );
    }

    #[test]
    fn fetch_raw_json_reports_analyzer_webview_boundary() {
        let source_json =
            r#"[{"bookSourceName":"raw bridge","bookSourceUrl":"https://source.example/"}]"#
                .to_string();
        let err = fetch_raw_json_inner(
            source_json,
            r#"https://source.example/audio,{"webView":true}"#.to_string(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("WebView platform boundary"), "{err}");
        assert!(err.contains("fetchRaw"), "{err}");
    }
}

uniffi::include_scaffolding!("legado_native");
