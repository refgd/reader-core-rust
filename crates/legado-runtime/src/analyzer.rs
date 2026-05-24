use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Write};
use url::Url;

use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};
use crate::html_formatter::{format_content, format_intro};
use crate::js_runtime::JsRuntime;
use crate::platform::PlatformHostRef;
use crate::request::{
    legado_request_wants_webview, parse_header_map, parse_legado_request, split_legado_url_options,
    MultipartFilePart, RequestEngine,
};
use crate::rule_engine::{RuleContent, RuleEngine};
use crate::session::{persist_session, restore_persistent_session, AnalyzerSession};
use crate::source::BookSource;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AnalyzerInput {
    pub key: String,
    pub page: i32,
    pub book_url: String,
    pub toc_url: String,
    pub chapter_url: String,
    #[serde(default)]
    pub next_chapter_url: String,
    pub explore_url: String,
    pub script: String,
    pub result: String,
    pub base_url: String,
    pub rule_path: String,
    pub bindings_json: String,
    pub upload_file_name: String,
    pub upload_content_type: String,
    pub upload_body_base64: String,
    #[serde(default)]
    pub upload_compress: bool,
    #[serde(default)]
    pub speak_text: String,
    #[serde(default)]
    pub speak_speed: i32,
    #[serde(default)]
    pub use_web_view: bool,
    #[serde(default)]
    pub bootstrap_login_url: bool,
    #[serde(default)]
    pub run_pre_update_js: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BookItem {
    pub name: String,
    pub author: String,
    pub kind: String,
    pub cover_url: String,
    pub intro: String,
    pub last_chapter: String,
    pub word_count: String,
    pub book_url: String,
    pub toc_url: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ChapterItem {
    pub title: String,
    pub url: String,
    pub update_time: String,
    pub is_vip: String,
    pub is_pay: String,
    pub is_volume: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ContentOutput {
    pub title: String,
    pub content: String,
    pub next_content_url: String,
    pub sub_content: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ExploreItem {
    pub title: String,
    pub url: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub action: String,
    #[serde(default)]
    pub chars: Vec<Option<String>>,
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub style: serde_json::Value,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AnalyzerOutput {
    pub books: Vec<BookItem>,
    pub book: Option<BookItem>,
    pub chapters: Vec<ChapterItem>,
    pub content: Option<ContentOutput>,
    pub explore: Vec<ExploreItem>,
    pub eval_result: Option<String>,
    pub diagnostics: Vec<String>,
    pub session: AnalyzerSessionSnapshot,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FetchTextOutput {
    pub url: String,
    pub status_code: i32,
    pub message: String,
    pub body: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct FetchRawOutput {
    pub url: String,
    pub code: i32,
    pub message: String,
    pub headers: HashMap<String, String>,
    pub headers_list: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body_base64: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AnalyzerSessionSnapshot {
    pub source_variable: String,
    pub variables: HashMap<String, String>,
    pub source_store: HashMap<String, String>,
    pub cache: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub login_info_raw: String,
    pub login_info: HashMap<String, String>,
    pub book_variables: HashMap<String, String>,
    pub chapter_variables: HashMap<String, String>,
    pub java_store: HashMap<String, String>,
    pub logs: Vec<String>,
    pub toasts: Vec<String>,
}

impl From<AnalyzerSession> for AnalyzerSessionSnapshot {
    fn from(value: AnalyzerSession) -> Self {
        Self {
            source_variable: value.source_variable,
            variables: value.variables,
            source_store: value.source_store,
            cache: value.cache,
            cookies: value.cookies,
            login_info_raw: value.login_info_raw,
            login_info: value.login_info,
            book_variables: value.book_variables,
            chapter_variables: value.chapter_variables,
            java_store: value.java_store,
            logs: value.logs,
            toasts: value.toasts,
        }
    }
}

pub struct Analyzer {
    source: BookSource,
    source_key: String,
    session: AnalyzerSession,
    request: RequestEngine,
    platform_host: Option<PlatformHostRef>,
}

impl Analyzer {
    pub fn new(source: BookSource, session: AnalyzerSession) -> Result<Self> {
        Self::new_with_platform(source, session, None)
    }

    pub fn new_with_platform(
        source: BookSource,
        session: AnalyzerSession,
        platform_host: Option<PlatformHostRef>,
    ) -> Result<Self> {
        let request = RequestEngine::new_with_default_headers_and_rate_limit(
            parse_header_map(&source.header),
            &source.book_source_url,
            &source.concurrent_rate,
        )?;
        let source_key = source.book_source_url.clone();
        let session = restore_persistent_session(&source_key, session);
        Ok(Self {
            source,
            source_key,
            session,
            request,
            platform_host,
        })
    }

    fn js_runtime(&self) -> Result<JsRuntime> {
        JsRuntime::new_with_platform(
            &self.source,
            self.session.clone(),
            self.platform_host.clone(),
        )
    }

    pub fn search(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let raw_url = rules.eval_url_rule(
            &self.source.search_url,
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
            &self.source.book_source_url,
        )?;
        let response = self.fetch_text_with_url_options(
            &mut js,
            &raw_url,
            &self.source.book_source_url.clone(),
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
            "searchUrl",
        )?;
        let root = RuleContent::from_body(&response.body);
        let mut rules = RuleEngine::new(&mut js);
        let items = rules.select_list(
            &self.source.rule_search.book_list,
            &root,
            &response.body,
            &response.url,
            "ruleSearch.bookList",
        )?;
        let mut books = Vec::new();
        for item in items {
            let book_url = absolutize(
                &response.url,
                &rules.eval_field_rule(
                    &self.source.rule_search.book_url,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.bookUrl",
                    &input.key,
                    input.page,
                )?,
            )?;
            books.push(BookItem {
                name: rules.eval_field_rule(
                    &self.source.rule_search.name,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.name",
                    &input.key,
                    input.page,
                )?,
                author: rules.eval_field_rule(
                    &self.source.rule_search.author,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.author",
                    &input.key,
                    input.page,
                )?,
                kind: rules.eval_field_rule(
                    &self.source.rule_search.kind,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.kind",
                    &input.key,
                    input.page,
                )?,
                cover_url: rules.eval_field_rule(
                    &self.source.rule_search.cover_url,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.coverUrl",
                    &input.key,
                    input.page,
                )?,
                intro: format_intro(&rules.eval_field_rule(
                    &self.source.rule_search.intro,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.intro",
                    &input.key,
                    input.page,
                )?),
                last_chapter: rules
                    .eval_field_rule(
                        &self.source.rule_search.last_chapter,
                        &item,
                        &response.body,
                        &response.url,
                        "ruleSearch.lastChapter",
                        &input.key,
                        input.page,
                    )
                    .map_err(|err| err.with_rule_path("ruleSearch.lastChapter"))?,
                word_count: rules.eval_field_rule(
                    &self.source.rule_search.word_count,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleSearch.wordCount",
                    &input.key,
                    input.page,
                )?,
                book_url,
                toc_url: String::new(),
            });
        }
        self.session = js.session();
        Ok(AnalyzerOutput {
            books,
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn explore(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        if input.explore_url.trim().is_empty() {
            return self.explore_kinds(input);
        }
        self.explore_books(input)
    }

    pub fn eval(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        if input.bootstrap_login_url && !self.source.login_url.trim().is_empty() {
            js.eval_rule_script(
                &self.source.login_url,
                "eval.loginUrl.bootstrap",
                "",
                if input.base_url.is_empty() {
                    &self.source.book_source_url
                } else {
                    &input.base_url
                },
                &input.key,
                if input.page <= 0 { 1 } else { input.page },
            )?;
        }
        let result = js.eval_rule_script_with_bindings(
            &input.script,
            if input.rule_path.is_empty() {
                "eval"
            } else {
                &input.rule_path
            },
            &input.result,
            if input.base_url.is_empty() {
                &self.source.book_source_url
            } else {
                &input.base_url
            },
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
            &input.bindings_json,
        )?;
        self.session = js.session();
        let mut diagnostics = Vec::new();
        if let Some(api) = unsupported_platform_api_in(&result) {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticKind::UnsupportedPlatformApi,
                    format!("JavaScript eval reached platform UI API `{api}`"),
                )
                .with_source(self.source.book_source_name.clone())
                .with_base_url(input.base_url.clone())
                .with_rule_path(if input.rule_path.is_empty() {
                    "eval"
                } else {
                    &input.rule_path
                })
                .with_script(input.script.clone())
                .to_string(),
            );
        }
        Ok(AnalyzerOutput {
            eval_result: Some(result),
            diagnostics,
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn eval_rule(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        if input.bootstrap_login_url && !self.source.login_url.trim().is_empty() {
            js.eval_rule_script(
                &self.source.login_url,
                "evalRule.loginUrl.bootstrap",
                "",
                if input.base_url.is_empty() {
                    &self.source.book_source_url
                } else {
                    &input.base_url
                },
                &input.key,
                if input.page <= 0 { 1 } else { input.page },
            )?;
        }
        let root = RuleContent::from_body(&input.result);
        let mut rules = RuleEngine::new(&mut js);
        let result = rules.eval_field_rule(
            &input.script,
            &root,
            &input.result,
            if input.base_url.is_empty() {
                &self.source.book_source_url
            } else {
                &input.base_url
            },
            if input.rule_path.is_empty() {
                "evalRule"
            } else {
                &input.rule_path
            },
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
        )?;
        self.session = js.session();
        Ok(AnalyzerOutput {
            eval_result: Some(result),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn dict_search(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let page = if input.page <= 0 { 1 } else { input.page };
        let raw_url = rules.eval_url_rule(
            &input.book_url,
            &input.key,
            page,
            &self.source.book_source_url,
        )?;
        drop(rules);
        let base_url = self.source.book_source_url.clone();
        let response = self.fetch_text_with_url_options(
            &mut js,
            &raw_url,
            &base_url,
            &input.key,
            page,
            if input.rule_path.is_empty() {
                "dict.url"
            } else {
                &input.rule_path
            },
        )?;
        let result = if input.script.trim().is_empty() {
            response.body
        } else {
            let mut rules = RuleEngine::new(&mut js);
            let root = RuleContent::from_body(&response.body);
            rules.eval_field_rule(
                &input.script,
                &root,
                &response.body,
                &response.url,
                if input.rule_path.is_empty() {
                    "dict.showRule"
                } else {
                    &input.rule_path
                },
                &input.key,
                page,
            )?
        };
        self.session = js.session();
        Ok(AnalyzerOutput {
            eval_result: Some(result),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn cover_search(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let page = if input.page <= 0 { 1 } else { input.page };
        if !input.bindings_json.trim().is_empty() {
            let base_url = if input.base_url.is_empty() {
                &self.source.book_source_url
            } else {
                &input.base_url
            };
            js.eval_rule_script_with_bindings(
                "undefined",
                "coverSearch.bindings",
                "",
                base_url,
                &input.key,
                page,
                &input.bindings_json,
            )?;
        }
        let mut rules = RuleEngine::new(&mut js);
        let raw_url = rules.eval_url_rule(
            &input.book_url,
            &input.key,
            page,
            &self.source.book_source_url,
        )?;
        drop(rules);
        let base_url = self.source.book_source_url.clone();
        let response = self.fetch_text_with_url_options(
            &mut js,
            &raw_url,
            &base_url,
            &input.key,
            page,
            if input.rule_path.is_empty() {
                "BookCover.url"
            } else {
                &input.rule_path
            },
        )?;
        let mut rules = RuleEngine::new(&mut js);
        let root = RuleContent::from_body(&response.body);
        let cover_url = rules.eval_field_rule(
            &input.script,
            &root,
            &response.body,
            &response.url,
            if input.rule_path.is_empty() {
                "coverSearch.coverRule"
            } else {
                &input.rule_path
            },
            &input.key,
            page,
        )?;
        let cover_url = if cover_url.trim().is_empty() {
            String::new()
        } else {
            absolutize(&response.url, &cover_url)?
        };
        self.session = js.session();
        Ok(AnalyzerOutput {
            eval_result: Some(cover_url),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn resolve_url(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let page = if input.page <= 0 { 1 } else { input.page };
        let base_url = if input.base_url.trim().is_empty() {
            self.source.book_source_url.as_str()
        } else {
            input.base_url.as_str()
        };
        let raw_url = rules.eval_url_rule(&input.book_url, &input.key, page, base_url)?;
        let url = absolutize_url_preserving_options(base_url, &raw_url)?;
        let url = apply_url_option_js(
            &mut js,
            &url,
            base_url,
            &input.key,
            page,
            if input.rule_path.is_empty() {
                "resolveUrl.urlOption.js"
            } else {
                &input.rule_path
            },
        )?;
        let parsed = parse_legado_request(&url)?;
        let options = parsed
            .options_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        let server_id = match options
            .get("serverID")
            .or_else(|| options.get("serverId"))
            .or_else(|| options.get("server_id"))
        {
            Some(value) => parse_server_id_option(value)?,
            None => None,
        };
        self.session = js.session();
        let result = serde_json::json!({
            "url": parsed.url,
            "method": parsed.method,
            "headers": parsed.headers,
            "body": parsed.body,
            "options": options,
            "serverId": server_id,
        });
        Ok(AnalyzerOutput {
            eval_result: Some(result.to_string()),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn direct_link_upload(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let raw_url = rules.eval_url_rule(
            &input.book_url,
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
            &self.source.book_source_url,
        )?;
        drop(rules);
        let base_url = self.source.book_source_url.clone();
        let url = absolutize_url_preserving_options(&base_url, &raw_url)?;
        let url = apply_url_option_js(
            &mut js,
            &url,
            &base_url,
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
            if input.rule_path.is_empty() {
                "DirectLinkUpload.urlOption.js"
            } else {
                &input.rule_path
            },
        )?;
        let parsed = parse_legado_request(&url)?;
        let options = parsed
            .options_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        let multipart_type = options
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or("multipart/form-data");
        if !multipart_type.eq_ignore_ascii_case("multipart/form-data") {
            return Err(Diagnostic::new(
                DiagnosticKind::UnsupportedRule,
                format!("unsupported multipart type for direct link upload: {multipart_type}"),
            )
            .with_source(self.source.book_source_name.clone())
            .with_rule_path(if input.rule_path.is_empty() {
                "DirectLinkUpload.uploadUrl"
            } else {
                &input.rule_path
            })
            .with_request(parsed.url, None));
        }
        let body = parsed.body.as_deref().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::RuleParse,
                "direct link upload URL option must include body JSON",
            )
            .with_rule_path(if input.rule_path.is_empty() {
                "DirectLinkUpload.uploadUrl"
            } else {
                &input.rule_path
            })
        })?;
        let body_map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str::<serde_json::Value>(body)
                .map_err(|err| {
                    Diagnostic::new(
                        DiagnosticKind::RuleParse,
                        format!("invalid direct link upload body JSON: {err}"),
                    )
                    .with_rule_path(if input.rule_path.is_empty() {
                        "DirectLinkUpload.uploadUrl"
                    } else {
                        &input.rule_path
                    })
                    .with_script(body)
                })?
                .as_object()
                .cloned()
                .ok_or_else(|| {
                    Diagnostic::new(
                        DiagnosticKind::RuleParse,
                        "direct link upload body JSON must be an object",
                    )
                    .with_rule_path(if input.rule_path.is_empty() {
                        "DirectLinkUpload.uploadUrl"
                    } else {
                        &input.rule_path
                    })
                })?;
        let mut fields = Vec::new();
        let mut file_field = None;
        for (key, value) in body_map {
            if value.as_str() == Some("fileRequest") {
                file_field = Some(key);
            } else {
                fields.push((key, json_value_to_legacy_string(&value)));
            }
        }
        let file_field = file_field.ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::RuleParse,
                "direct link upload body JSON must contain a fileRequest field",
            )
            .with_rule_path(if input.rule_path.is_empty() {
                "DirectLinkUpload.uploadUrl"
            } else {
                &input.rule_path
            })
        })?;
        let mut file_name = input.upload_file_name;
        let mut content_type = input.upload_content_type;
        let mut file_body = base64::engine::general_purpose::STANDARD
            .decode(input.upload_body_base64.as_bytes())
            .map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::RuleParse,
                    format!("invalid direct link upload file base64: {err}"),
                )
                .with_rule_path(if input.rule_path.is_empty() {
                    "DirectLinkUpload.file"
                } else {
                    &input.rule_path
                })
            })?;
        if input.upload_compress && !content_type.eq_ignore_ascii_case("application/zip") {
            file_body = zip_single_file_bytes(&file_name, &file_body).map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::RuleParse,
                    format!("failed to zip direct link upload file: {err}"),
                )
                .with_rule_path(if input.rule_path.is_empty() {
                    "DirectLinkUpload.file"
                } else {
                    &input.rule_path
                })
            })?;
            file_name = format!("{file_name}.zip");
            content_type = "application/zip".to_string();
        }
        let response = self.request.upload_multipart_text_with_request(
            parsed,
            fields,
            MultipartFilePart {
                field_name: file_field,
                file_name,
                content_type,
                body: file_body,
            },
            &mut self.session,
        )?;
        let mut rules = RuleEngine::new(&mut js);
        let root = RuleContent::from_body(&response.body);
        let result = rules.eval_field_rule(
            &input.script,
            &root,
            &response.body,
            &response.url,
            if input.rule_path.is_empty() {
                "DirectLinkUpload.downloadUrlRule"
            } else {
                &input.rule_path
            },
            &input.key,
            if input.page <= 0 { 1 } else { input.page },
        )?;
        self.session = js.session();
        Ok(AnalyzerOutput {
            eval_result: Some(result),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn fetch_text(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let page = if input.page <= 0 { 1 } else { input.page };
        let base_url = if input.base_url.trim().is_empty() {
            self.source.book_source_url.clone()
        } else {
            input.base_url.clone()
        };
        let raw_url = rules.eval_url_rule(&input.book_url, &input.key, page, &base_url)?;
        drop(rules);
        let response = self.fetch_text_with_url_options(
            &mut js,
            &raw_url,
            &base_url,
            &input.key,
            page,
            if input.rule_path.is_empty() {
                "fetchText"
            } else {
                &input.rule_path
            },
        )?;
        let out = FetchTextOutput {
            url: response.url,
            status_code: response.status.unwrap_or(200) as i32,
            message: "OK".to_string(),
            body: response.body,
            content_type: response.content_type,
        };
        Ok(AnalyzerOutput {
            eval_result: Some(serde_json::to_string(&out).map_err(|err| {
                Diagnostic::new(DiagnosticKind::Extraction, err.to_string())
                    .with_rule_path("fetchText.serialize")
            })?),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn fetch_raw(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let page = if input.page <= 0 { 1 } else { input.page };
        let base_url = if input.base_url.trim().is_empty() {
            self.source.book_source_url.clone()
        } else {
            input.base_url.clone()
        };
        let bindings_json = tts_bindings_json(&input)?;
        let raw_url = rules.eval_url_rule_with_bindings(
            &input.book_url,
            &input.key,
            page,
            &base_url,
            &bindings_json,
        )?;
        drop(rules);
        let url = absolutize_url_preserving_options(&base_url, &raw_url)?;
        let url = apply_url_option_js(
            &mut js,
            &url,
            &base_url,
            &input.key,
            page,
            if input.rule_path.is_empty() {
                "fetchRaw.urlOption.js"
            } else {
                &input.rule_path
            },
        )?;
        let parsed = parse_legado_request(&url)?;
        if legado_request_wants_webview(&parsed)? {
            return Err(Diagnostic::new(
                DiagnosticKind::UnsupportedPlatformApi,
                "fetchRaw requires WebView platform boundary",
            )
            .with_source(self.source.book_source_name.clone())
            .with_rule_path(if input.rule_path.is_empty() {
                "fetchRaw"
            } else {
                &input.rule_path
            })
            .with_request(parsed.url, None));
        }
        self.session = js.session();
        let response = self.request.get_raw(&url, &mut self.session)?;
        if !self.source.login_check_js.trim().is_empty() {
            let text_response = crate::request::RequestOutput {
                url: response.url.clone(),
                status: response.status,
                headers: response.headers.clone(),
                content_type: response.content_type.clone(),
                body: String::from_utf8_lossy(&response.body).into_owned(),
            };
            let check_result = js.eval_rule_script_with_response(
                &self.source.login_check_js,
                "loginCheckJs",
                &text_response,
                &response.url,
                &input.key,
                page,
            )?;
            if let Some(response_json) = check_result.strip_prefix("__LEGADO_STR_RESPONSE_JSON__") {
                let value: serde_json::Value =
                    serde_json::from_str(response_json).map_err(|err| {
                        Diagnostic::new(
                            DiagnosticKind::JavaScript,
                            format!("loginCheckJs returned invalid response JSON: {err}"),
                        )
                        .with_source(self.source.book_source_name.clone())
                        .with_rule_path("loginCheckJs")
                    })?;
                if value.get("code").and_then(serde_json::Value::as_i64) == Some(500) {
                    return Err(Diagnostic::new(
                        DiagnosticKind::Request,
                        "loginCheckJs returned HTTP 500 for raw fetch",
                    )
                    .with_source(self.source.book_source_name.clone())
                    .with_rule_path("loginCheckJs")
                    .with_request(response.url.clone(), response.status));
                }
            }
        }
        self.session = js.session();
        let headers_list = response.headers;
        let headers = headers_list.iter().cloned().collect::<HashMap<_, _>>();
        let out = FetchRawOutput {
            url: response.url,
            code: response.status.unwrap_or(200) as i32,
            message: "OK".to_string(),
            headers,
            headers_list,
            content_type: response.content_type,
            body_base64: base64::engine::general_purpose::STANDARD.encode(response.body),
        };
        Ok(AnalyzerOutput {
            eval_result: Some(serde_json::to_string(&out).map_err(|err| {
                Diagnostic::new(DiagnosticKind::Extraction, err.to_string())
                    .with_rule_path("fetchRaw.serialize")
            })?),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    fn explore_kinds(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        if crate::rule_engine::is_js_rule(&self.source.explore_url) {
            install_explore_info_map(&mut js, &self.source.book_source_url)?;
        }
        let mut rules = RuleEngine::new(&mut js);
        let page = if input.page <= 0 { 1 } else { input.page };
        let raw = if crate::rule_engine::is_js_rule(&self.source.explore_url) {
            rules.eval_field_rule(
                &self.source.explore_url,
                &RuleContent::Json(serde_json::Value::Null),
                "",
                &self.source.book_source_url,
                "exploreUrl",
                "",
                page,
            )?
        } else {
            self.source
                .explore_url
                .replace("{{page}}", &page.to_string())
                .replace("{page}", &page.to_string())
        };
        let explore = parse_explore_items(&raw)?;
        let diagnostics = explore
            .iter()
            .filter_map(|item| {
                unsupported_platform_api_in(&item.url)
                    .or_else(|| unsupported_platform_api_in(&item.action))
                    .map(|api| {
                        Diagnostic::new(
                            DiagnosticKind::UnsupportedPlatformApi,
                            format!(
                                "explore item `{}` contains platform UI API `{api}` and must be handled by Android UI boundary",
                                item.title
                            ),
                        )
                        .with_source(self.source.book_source_name.clone())
                        .with_base_url(self.source.book_source_url.clone())
                        .with_rule_path("exploreUrl")
                        .with_script(item.url.clone())
                        .to_string()
                    })
            })
            .collect::<Vec<_>>();
        self.session = js.session();
        Ok(AnalyzerOutput {
            explore,
            diagnostics,
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    fn explore_books(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        if let Some(api) = unsupported_platform_api_in(&input.explore_url) {
            return Err(Diagnostic::new(
                DiagnosticKind::UnsupportedPlatformApi,
                format!("unsupported platform UI API `{api}` in explore URL"),
            )
            .with_source(self.source.book_source_name.clone())
            .with_base_url(input.explore_url.clone())
            .with_rule_path("exploreUrl")
            .with_script(input.explore_url));
        }
        let mut js = self.js_runtime()?;
        let mut rules = RuleEngine::new(&mut js);
        let page = if input.page <= 0 { 1 } else { input.page };
        let raw_url =
            rules.eval_url_rule(&input.explore_url, "", page, &self.source.book_source_url)?;
        let response = self.fetch_text_with_url_options(
            &mut js,
            &raw_url,
            &self.source.book_source_url.clone(),
            "",
            page,
            "exploreUrl",
        )?;
        let root = RuleContent::from_body(&response.body);
        let rule = if self.source.rule_explore.book_list.trim().is_empty() {
            self.source.rule_search.clone()
        } else {
            self.source.rule_explore.clone()
        };
        let mut rules = RuleEngine::new(&mut js);
        let items = rules.select_list(
            &rule.book_list,
            &root,
            &response.body,
            &response.url,
            "ruleExplore.bookList",
        )?;
        let mut books = Vec::new();
        for item in items {
            let book_url = absolutize(
                &response.url,
                &rules.eval_field_rule(
                    &rule.book_url,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.bookUrl",
                    "",
                    page,
                )?,
            )?;
            books.push(BookItem {
                name: rules.eval_field_rule(
                    &rule.name,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.name",
                    "",
                    page,
                )?,
                author: rules.eval_field_rule(
                    &rule.author,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.author",
                    "",
                    page,
                )?,
                kind: rules.eval_field_rule(
                    &rule.kind,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.kind",
                    "",
                    page,
                )?,
                cover_url: rules.eval_field_rule(
                    &rule.cover_url,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.coverUrl",
                    "",
                    page,
                )?,
                intro: format_intro(&rules.eval_field_rule(
                    &rule.intro,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.intro",
                    "",
                    page,
                )?),
                last_chapter: rules
                    .eval_field_rule(
                        &rule.last_chapter,
                        &item,
                        &response.body,
                        &response.url,
                        "ruleExplore.lastChapter",
                        "",
                        page,
                    )
                    .map_err(|err| err.with_rule_path("ruleExplore.lastChapter"))?,
                word_count: rules.eval_field_rule(
                    &rule.word_count,
                    &item,
                    &response.body,
                    &response.url,
                    "ruleExplore.wordCount",
                    "",
                    page,
                )?,
                book_url,
                toc_url: String::new(),
            });
        }
        self.session = js.session();
        Ok(AnalyzerOutput {
            books,
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn detail(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let body = self.fetch_rule_url_with_js(&mut js, &input.book_url, "ruleBookInfo.url")?;
        let root = RuleContent::from_body(&body.body);
        let mut rules = RuleEngine::new(&mut js);
        let init = if self.source.rule_book_info.init.trim().is_empty() {
            root
        } else if self.source.rule_book_info.init.contains("<js>")
            || self.source.rule_book_info.init.starts_with("@js:")
        {
            let out = rules.eval_field_rule(
                &self.source.rule_book_info.init,
                &root,
                &body.body,
                &body.url,
                "ruleBookInfo.init",
                "",
                1,
            )?;
            RuleContent::from_body(&out)
        } else {
            let Some(json) = root.as_json() else {
                return Err(Diagnostic::new(
                    DiagnosticKind::Extraction,
                    "ruleBookInfo.init uses JSON extraction but response content is HTML",
                ));
            };
            RuleContent::Json(crate::rule_engine::extract_value_path(
                json,
                &self.source.rule_book_info.init,
            )?)
        };
        let raw_toc_url = rules.eval_field_rule(
            &self.source.rule_book_info.toc_url,
            &init,
            &body.body,
            &body.url,
            "ruleBookInfo.tocUrl",
            "",
            1,
        )?;
        let toc_url = if raw_toc_url.trim().is_empty() {
            body.url.clone()
        } else {
            absolutize(&body.url, &raw_toc_url)?
        };
        let book = BookItem {
            name: rules.eval_field_rule(
                &self.source.rule_book_info.name,
                &init,
                &body.body,
                &body.url,
                "ruleBookInfo.name",
                "",
                1,
            )?,
            author: rules.eval_field_rule(
                &self.source.rule_book_info.author,
                &init,
                &body.body,
                &body.url,
                "ruleBookInfo.author",
                "",
                1,
            )?,
            kind: rules.eval_field_rule(
                &self.source.rule_book_info.kind,
                &init,
                &body.body,
                &body.url,
                "ruleBookInfo.kind",
                "",
                1,
            )?,
            cover_url: rules.eval_field_rule(
                &self.source.rule_book_info.cover_url,
                &init,
                &body.body,
                &body.url,
                "ruleBookInfo.coverUrl",
                "",
                1,
            )?,
            intro: format_intro(&rules.eval_field_rule(
                &self.source.rule_book_info.intro,
                &init,
                &body.body,
                &body.url,
                "ruleBookInfo.intro",
                "",
                1,
            )?),
            last_chapter: rules
                .eval_field_rule(
                    &self.source.rule_book_info.last_chapter,
                    &init,
                    &body.body,
                    &body.url,
                    "ruleBookInfo.lastChapter",
                    "",
                    1,
                )
                .map_err(|err| err.with_rule_path("ruleBookInfo.lastChapter"))?,
            word_count: rules.eval_field_rule(
                &self.source.rule_book_info.word_count,
                &init,
                &body.body,
                &body.url,
                "ruleBookInfo.wordCount",
                "",
                1,
            )?,
            toc_url,
            book_url: input.book_url,
        };
        self.session = js.session();
        Ok(AnalyzerOutput {
            book: Some(book),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn toc(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        let mut js = self.js_runtime()?;
        let base_url = if input.toc_url.trim().is_empty() {
            input.book_url.as_str()
        } else {
            input.toc_url.as_str()
        };
        if input.run_pre_update_js && !self.source.rule_toc.pre_update_js.trim().is_empty() {
            js.eval_rule_script(
                "globalThis.__legadoPreUpdateJs = true;",
                "ruleToc.preUpdateJs.guard",
                "",
                base_url,
                "",
                1,
            )?;
            js.eval_rule_script_with_bindings(
                &self.source.rule_toc.pre_update_js,
                "ruleToc.preUpdateJs",
                "",
                base_url,
                "",
                1,
                &input.bindings_json,
            )?;
            self.session = js.session();
            self.handle_pre_update_actions(&input)?;
        }
        let toc_url = self
            .session
            .book_variables
            .get("tocUrl")
            .filter(|url| !url.trim().is_empty())
            .cloned()
            .unwrap_or(input.toc_url);
        let list_rule = self.source.rule_toc.chapter_list.trim().to_string();
        let reverse = list_rule.starts_with('-');
        let list_rule = list_rule.trim_start_matches(['-', '+']).trim().to_string();
        let mut next_urls = Vec::new();
        let mut seen_page_urls = std::collections::HashSet::new();
        let mut body = self.fetch_rule_url_with_js(&mut js, &toc_url, "ruleToc.url")?;
        let mut chapters = Vec::new();
        let mut rules = RuleEngine::new(&mut js);
        loop {
            if !seen_page_urls.insert(body.url.clone()) {
                break;
            }
            let root = RuleContent::from_body(&body.body);
            let items = rules.select_list(
                &list_rule,
                &root,
                &body.body,
                &body.url,
                "ruleToc.chapterList",
            )?;
            for item in items {
                let title = rules.eval_field_rule(
                    &self.source.rule_toc.chapter_name,
                    &item,
                    &body.body,
                    &body.url,
                    "ruleToc.chapterName",
                    "",
                    1,
                )?;
                let raw_chapter_url = rules.eval_field_rule(
                    &self.source.rule_toc.chapter_url,
                    &item,
                    &body.body,
                    &body.url,
                    "ruleToc.chapterUrl",
                    "",
                    1,
                )?;
                let update_time = if self.source.rule_toc.update_time.trim().is_empty() {
                    String::new()
                } else {
                    rules
                        .eval_field_rule(
                            &self.source.rule_toc.update_time,
                            &item,
                            &body.body,
                            &body.url,
                            "ruleToc.updateTime",
                            "",
                            1,
                        )
                        .map_err(|err| err.with_rule_path("ruleToc.updateTime"))?
                };
                let is_vip = if self.source.rule_toc.is_vip.trim().is_empty() {
                    String::new()
                } else {
                    rules
                        .eval_field_rule(
                            &self.source.rule_toc.is_vip,
                            &item,
                            &body.body,
                            &body.url,
                            "ruleToc.isVip",
                            "",
                            1,
                        )
                        .map_err(|err| err.with_rule_path("ruleToc.isVip"))?
                };
                let is_pay = if self.source.rule_toc.is_pay.trim().is_empty() {
                    String::new()
                } else {
                    rules
                        .eval_field_rule(
                            &self.source.rule_toc.is_pay,
                            &item,
                            &body.body,
                            &body.url,
                            "ruleToc.isPay",
                            "",
                            1,
                        )
                        .map_err(|err| err.with_rule_path("ruleToc.isPay"))?
                };
                let is_volume = if self.source.rule_toc.is_volume.trim().is_empty() {
                    String::new()
                } else {
                    rules
                        .eval_field_rule(
                            &self.source.rule_toc.is_volume,
                            &item,
                            &body.body,
                            &body.url,
                            "ruleToc.isVolume",
                            "",
                            1,
                        )
                        .map_err(|err| err.with_rule_path("ruleToc.isVolume"))?
                };
                chapters.push(ChapterItem {
                    title,
                    url: absolutize(&body.url, &raw_chapter_url)?,
                    update_time,
                    is_vip,
                    is_pay,
                    is_volume,
                });
            }
            if self.source.rule_toc.next_toc_url.trim().is_empty() {
                break;
            }
            let raw_next = rules.eval_field_rule(
                &self.source.rule_toc.next_toc_url,
                &root,
                &body.body,
                &body.url,
                "ruleToc.nextTocUrl",
                "",
                1,
            )?;
            let next_url = absolutize(&body.url, &raw_next)?;
            if next_url.trim().is_empty() || seen_page_urls.contains(&next_url) {
                break;
            }
            next_urls.push(next_url.clone());
            drop(rules);
            body = self.fetch_rule_url_with_js(&mut js, &next_url, "ruleToc.nextTocUrl")?;
            rules = RuleEngine::new(&mut js);
        }
        if reverse {
            chapters.reverse();
        }
        let mut seen_chapters = std::collections::HashSet::new();
        chapters
            .retain(|chapter| seen_chapters.insert(format!("{}\n{}", chapter.title, chapter.url)));
        if !self.source.rule_toc.format_js.trim().is_empty() {
            for (index, chapter) in chapters.iter_mut().enumerate() {
                let script = format!(
                    "var gInt = {index}; var index = {}; var title = {}; {}",
                    index + 1,
                    serde_json::to_string(&chapter.title).unwrap_or_else(|_| "\"\"".to_string()),
                    self.source.rule_toc.format_js
                );
                let formatted = rules.eval_field_rule(
                    &format!("@js: {script}"),
                    &RuleContent::Json(serde_json::Value::String(chapter.title.clone())),
                    &chapter.title,
                    &toc_url,
                    "ruleToc.formatJs",
                    "",
                    1,
                )?;
                if !formatted.trim().is_empty() {
                    chapter.title = formatted;
                }
            }
        }
        drop(rules);
        self.session = js.session();
        if !next_urls.is_empty() {
            self.session
                .java_store
                .insert("__toc_next_pages".to_string(), next_urls.join("\n"));
        }
        Ok(AnalyzerOutput {
            chapters,
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    pub fn pre_update_toc(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        if self.source.rule_toc.pre_update_js.trim().is_empty() {
            return Ok(AnalyzerOutput {
                session: self.persisted_session_snapshot(),
                ..AnalyzerOutput::default()
            });
        }
        let mut js = self.js_runtime()?;
        let base_url = if input.toc_url.trim().is_empty() {
            input.book_url.as_str()
        } else {
            input.toc_url.as_str()
        };
        js.eval_rule_script_with_bindings(
            "globalThis.__legadoPreUpdateJs = true;",
            "ruleToc.preUpdateJs.guard",
            "",
            base_url,
            "",
            1,
            &input.bindings_json,
        )?;
        js.eval_rule_script_with_bindings(
            &self.source.rule_toc.pre_update_js,
            "ruleToc.preUpdateJs",
            "",
            base_url,
            "",
            1,
            &input.bindings_json,
        )?;
        self.session = js.session();
        self.handle_pre_update_actions(&input)?;
        Ok(AnalyzerOutput {
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    fn handle_pre_update_actions(&mut self, input: &AnalyzerInput) -> Result<()> {
        let actions = self
            .session
            .java_store
            .remove("__pre_update_actions")
            .unwrap_or_default();
        for action in actions
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            match action {
                "refreshTocUrl" => {
                    let book_url = self.current_book_url(input)?;
                    self.refresh_book_detail_into_session(book_url)?;
                }
                "reGetBook" => {
                    let name = self.current_book_field(input, "name");
                    let author = self.current_book_field(input, "author");
                    if name.trim().is_empty() {
                        return Err(Diagnostic::new(
                            DiagnosticKind::Extraction,
                            "java.reGetBook requires current book.name in ruleToc.preUpdateJs",
                        )
                        .with_source(self.source.book_source_name.clone())
                        .with_rule_path("ruleToc.preUpdateJs")
                        .with_script(&self.source.rule_toc.pre_update_js));
                    }
                    let found = self.precise_search_book(&name, &author)?;
                    let found_url = found.book_url.clone();
                    self.apply_book_item_to_session(&found);
                    self.refresh_book_detail_into_session(found_url)?;
                }
                other => {
                    return Err(Diagnostic::new(
                        DiagnosticKind::UnsupportedRule,
                        format!("unsupported ruleToc.preUpdateJs action `{other}`"),
                    )
                    .with_source(self.source.book_source_name.clone())
                    .with_rule_path("ruleToc.preUpdateJs")
                    .with_script(&self.source.rule_toc.pre_update_js));
                }
            }
        }
        Ok(())
    }

    fn current_book_url(&self, input: &AnalyzerInput) -> Result<String> {
        let book_url = self
            .session
            .book_variables
            .get("bookUrl")
            .filter(|value| !value.trim().is_empty())
            .cloned()
            .unwrap_or_else(|| input.book_url.clone());
        if book_url.trim().is_empty() {
            return Err(Diagnostic::new(
                DiagnosticKind::Extraction,
                "ruleToc.preUpdateJs action requires current bookUrl",
            )
            .with_source(self.source.book_source_name.clone())
            .with_rule_path("ruleToc.preUpdateJs")
            .with_script(&self.source.rule_toc.pre_update_js));
        }
        Ok(book_url)
    }

    fn current_book_field(&self, input: &AnalyzerInput, key: &str) -> String {
        self.session
            .book_variables
            .get(key)
            .cloned()
            .or_else(|| book_binding_field(&input.bindings_json, key))
            .unwrap_or_default()
    }

    fn precise_search_book(&mut self, name: &str, author: &str) -> Result<BookItem> {
        let output = self.search(AnalyzerInput {
            key: name.to_string(),
            page: 1,
            ..AnalyzerInput::default()
        })?;
        output
            .books
            .into_iter()
            .find(|book| book.name == name && (author.is_empty() || book.author == author))
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticKind::Extraction,
                    format!("java.reGetBook did not find `{name}` `{author}` from Rust search"),
                )
                .with_source(self.source.book_source_name.clone())
                .with_rule_path("ruleToc.preUpdateJs")
                .with_script(&self.source.rule_toc.pre_update_js)
            })
    }

    fn refresh_book_detail_into_session(&mut self, book_url: String) -> Result<()> {
        let output = self.detail(AnalyzerInput {
            book_url,
            ..AnalyzerInput::default()
        })?;
        if let Some(book) = output.book {
            self.apply_book_item_to_session(&book);
        }
        Ok(())
    }

    fn apply_book_item_to_session(&mut self, book: &BookItem) {
        let values = [
            ("name", &book.name),
            ("author", &book.author),
            ("kind", &book.kind),
            ("coverUrl", &book.cover_url),
            ("intro", &book.intro),
            ("latestChapterTitle", &book.last_chapter),
            ("wordCount", &book.word_count),
            ("bookUrl", &book.book_url),
            ("tocUrl", &book.toc_url),
        ];
        for (key, value) in values {
            self.session
                .book_variables
                .insert(key.to_string(), value.to_string());
        }
    }

    pub fn content(&mut self, input: AnalyzerInput) -> Result<AnalyzerOutput> {
        if !self.source.rule_content.web_js.trim().is_empty()
            || !self.source.rule_content.source_regex.trim().is_empty()
        {
            let script = if self.source.rule_content.web_js.trim().is_empty() {
                &self.source.rule_content.source_regex
            } else {
                &self.source.rule_content.web_js
            };
            return Err(Diagnostic::new(
                DiagnosticKind::UnsupportedPlatformApi,
                "ruleContent.webJs/sourceRegex requires WebView platform boundary",
            )
            .with_source(self.source.book_source_name.clone())
            .with_rule_path("ruleContent.webJs/sourceRegex")
            .with_script(script)
            .with_request(input.chapter_url.clone(), None));
        }
        let mut js = self.js_runtime()?;
        let mut body = if content_rules_need_initial_body(&self.source, &input.chapter_url) {
            self.fetch_rule_url_with_js(&mut js, &input.chapter_url, "ruleContent.url")?
        } else {
            crate::request::RequestOutput {
                url: absolutize(&self.source.book_source_url, &input.chapter_url)?,
                status: None,
                headers: Vec::new(),
                content_type: None,
                body: String::new(),
            }
        };
        let first_body = body.body.clone();
        let first_body_url = body.url.clone();
        let mut rules = RuleEngine::new(&mut js);

        let mut seen_page_urls = vec![body.url.clone()];
        let next_chapter_url = if input.next_chapter_url.trim().is_empty() {
            String::new()
        } else {
            absolutize(&body.url, &input.next_chapter_url)?
        };
        let mut page_contents = Vec::new();
        let mut title = String::new();
        let mut page = 1;

        let next_content_url = loop {
            let root = RuleContent::from_body(&body.body);
            let body_content = rules.eval_field_rule(
                &self.source.rule_content.content,
                &root,
                &body.body,
                &body.url,
                "ruleContent.content",
                "",
                page,
            )?;
            page_contents.push(format_content(&body_content));
            if title.is_empty() && !self.source.rule_content.title.trim().is_empty() {
                title = rules
                    .eval_field_rule(
                        &self.source.rule_content.title,
                        &root,
                        &body.body,
                        &body.url,
                        "ruleContent.title",
                        "",
                        page,
                    )
                    .map_err(|err| err.with_rule_path("ruleContent.title"))?;
            }
            let raw_next_content_url =
                if self.source.rule_content.next_content_url.trim().is_empty() {
                    String::new()
                } else {
                    rules
                        .eval_field_rule(
                            &self.source.rule_content.next_content_url,
                            &root,
                            &body.body,
                            &body.url,
                            "ruleContent.nextContentUrl",
                            "",
                            page,
                        )
                        .map_err(|err| err.with_rule_path("ruleContent.nextContentUrl"))?
                };
            let next_url = absolutize(&body.url, &raw_next_content_url)?;
            if next_url.trim().is_empty()
                || seen_page_urls.contains(&next_url)
                || (!next_chapter_url.is_empty() && next_url == next_chapter_url)
            {
                break raw_next_content_url;
            }
            seen_page_urls.push(next_url.clone());
            drop(rules);
            body = self.fetch_text_with_url_options(
                &mut js,
                &raw_next_content_url,
                &body.url,
                "",
                page + 1,
                "ruleContent.nextContentUrl",
            )?;
            rules = RuleEngine::new(&mut js);
            page += 1;
        };

        let mut content_text = page_contents.join("\n");
        let sub_content = if self.source.rule_content.sub_content.trim().is_empty() {
            String::new()
        } else {
            let root = RuleContent::from_body(&first_body);
            let raw = rules.eval_field_rule(
                &self.source.rule_content.sub_content,
                &root,
                &first_body,
                &first_body_url,
                "ruleContent.subContent",
                "",
                1,
            )?;
            if book_is_online_text(&input.bindings_json) {
                if !raw.is_empty() {
                    if content_text.is_empty() {
                        content_text = raw.clone();
                    } else {
                        content_text.push('\n');
                        content_text.push_str(&raw);
                    }
                }
                raw
            } else if raw.trim_start().starts_with("http://")
                || raw.trim_start().starts_with("https://")
            {
                drop(rules);
                let fetched = self.fetch_text_with_url_options(
                    &mut js,
                    raw.trim(),
                    &first_body_url,
                    "",
                    1,
                    "ruleContent.subContent",
                )?;
                rules = RuleEngine::new(&mut js);
                fetched.body
            } else {
                raw
            }
        };
        if !self.source.rule_content.replace_regex.trim().is_empty() {
            let replace_input = format!(
                "{}{}",
                crate::js_runtime::FORCED_STRING_RESULT_PREFIX,
                content_text
            );
            let content_value = RuleContent::Json(serde_json::Value::String(
                content_text
                    .lines()
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join("\n"),
            ));
            content_text = rules.eval_field_rule(
                &self.source.rule_content.replace_regex,
                &content_value,
                &replace_input,
                &body.url,
                "ruleContent.replaceRegex",
                "",
                1,
            )?;
        }
        let content = ContentOutput {
            title,
            content: content_text,
            next_content_url,
            sub_content,
        };
        self.session = js.session();
        Ok(AnalyzerOutput {
            content: Some(content),
            session: self.persisted_session_snapshot(),
            ..AnalyzerOutput::default()
        })
    }

    fn fetch_rule_url_with_js(
        &mut self,
        js: &mut JsRuntime,
        raw_url: &str,
        rule_path: &str,
    ) -> Result<crate::request::RequestOutput> {
        let base_url = self.source.book_source_url.clone();
        self.fetch_text_with_url_options(js, raw_url, &base_url, "", 1, rule_path)
    }

    fn fetch_text_with_url_options(
        &mut self,
        js: &mut JsRuntime,
        raw_url: &str,
        base_url: &str,
        key: &str,
        page: i32,
        rule_path: &str,
    ) -> Result<crate::request::RequestOutput> {
        let url = absolutize_url_preserving_options(base_url, raw_url)?;
        let url = apply_url_option_js(
            js,
            &url,
            base_url,
            key,
            page,
            &format!("{rule_path}.urlOption.js"),
        )?;
        let (url, body_js) = consume_url_option_script(&url, "bodyJs", "body_js")?;
        let parsed = parse_legado_request(&url)?;
        if legado_request_wants_webview(&parsed)? {
            return Err(Diagnostic::new(
                DiagnosticKind::UnsupportedPlatformApi,
                format!("{rule_path} requires WebView platform boundary"),
            )
            .with_source(self.source.book_source_name.clone())
            .with_rule_path(rule_path)
            .with_request(parsed.url, None));
        }
        self.session = js.session();
        let mut response = self.request.get_text(&url, &mut self.session)?;
        if let Some(body_js) = body_js {
            response.body = js.eval_rule_script(
                &body_js,
                &format!("{rule_path}.urlOption.bodyJs"),
                &response.body,
                base_url,
                key,
                page,
            )?;
        }
        self.session = js.session();
        Ok(response)
    }

    fn persisted_session_snapshot(&self) -> AnalyzerSessionSnapshot {
        persist_session(&self.source_key, &self.session);
        self.session.clone().into()
    }
}

fn content_rules_need_initial_body(source: &BookSource, chapter_url: &str) -> bool {
    if chapter_url.trim().starts_with("data:") {
        return true;
    }
    if !crate::rule_engine::is_js_rule(&source.rule_content.content) {
        return true;
    }
    let rules = [
        source.rule_content.content.as_str(),
        source.rule_content.sub_content.as_str(),
        source.rule_content.replace_regex.as_str(),
        source.rule_content.title.as_str(),
        source.rule_content.next_content_url.as_str(),
    ];
    rules
        .into_iter()
        .any(|rule| !rule.trim().is_empty() && rule_references_result(rule))
}

fn rule_references_result(rule: &str) -> bool {
    let mut ident = String::new();
    for ch in rule.chars().chain(std::iter::once(' ')) {
        if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
            ident.push(ch);
            continue;
        }
        if ident == "result" || ident == "@result" {
            return true;
        }
        ident.clear();
    }
    false
}

fn book_type_from_bindings(bindings_json: &str) -> i64 {
    serde_json::from_str::<serde_json::Value>(bindings_json)
        .ok()
        .and_then(|value| {
            value
                .get("book")
                .and_then(|book| book.get("type"))
                .and_then(|type_value| {
                    type_value
                        .as_i64()
                        .or_else(|| type_value.as_str().and_then(|text| text.parse().ok()))
                })
        })
        .unwrap_or(8)
}

fn book_is_online_text(bindings_json: &str) -> bool {
    let book_type = book_type_from_bindings(bindings_json);
    let text = 0b1000_i64;
    let local = 0b100000000_i64;
    (book_type & text) > 0 && (book_type & local) == 0
}

fn apply_url_option_js(
    js: &mut JsRuntime,
    url: &str,
    base_url: &str,
    key: &str,
    page: i32,
    rule_path: &str,
) -> Result<String> {
    let (base, Some(options_json)) = split_legado_url_options(url) else {
        return Ok(url.to_string());
    };
    let mut options: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str::<serde_json::Value>(&options_json)
            .map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!("invalid request options JSON: {err}; rawUrl={url}"),
                )
            })?
            .as_object()
            .cloned()
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!("request options JSON must be an object; rawUrl={}", url),
                )
            })?;
    let Some(script_value) = options.remove("js") else {
        return Ok(url.to_string());
    };
    let script = match script_value {
        serde_json::Value::Null => return rebuild_legado_url(base, options),
        serde_json::Value::String(script) if script.trim().is_empty() => {
            return rebuild_legado_url(base, options);
        }
        serde_json::Value::String(script) => script,
        other => {
            options.insert("js".to_string(), other);
            return rebuild_legado_url(base, options);
        }
    };
    let next_url = js.eval_rule_script(&script, rule_path, &base, base_url, key, page)?;
    let next_url = absolutize(base_url, &next_url)?;
    rebuild_legado_url(next_url, options)
}

fn consume_url_option_script(
    url: &str,
    primary_key: &str,
    alias_key: &str,
) -> Result<(String, Option<String>)> {
    let (base, Some(options_json)) = split_legado_url_options(url) else {
        return Ok((url.to_string(), None));
    };
    let mut options: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str::<serde_json::Value>(&options_json)
            .map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!("invalid request options JSON: {err}; rawUrl={url}"),
                )
            })?
            .as_object()
            .cloned()
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!("request options JSON must be an object; rawUrl={url}"),
                )
            })?;
    let script = options
        .remove(primary_key)
        .or_else(|| options.remove(alias_key));
    let Some(script) = script else {
        return Ok((url.to_string(), None));
    };
    let script = match script {
        serde_json::Value::Null => None,
        serde_json::Value::String(script) if script.trim().is_empty() => None,
        serde_json::Value::String(script) => Some(script),
        _ => Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!("request option `{primary_key}` must be a string; rawUrl={url}"),
        ))?,
    };
    Ok((rebuild_legado_url(base, options)?, script))
}

fn rebuild_legado_url(
    url: String,
    options: serde_json::Map<String, serde_json::Value>,
) -> Result<String> {
    if options.is_empty() {
        return Ok(url);
    }
    let options = serde_json::to_string(&serde_json::Value::Object(options)).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Request,
            format!("request options JSON could not be serialized after URL option JS: {err}"),
        )
    })?;
    Ok(format!("{url},{options}"))
}

fn parse_server_id_option(value: &serde_json::Value) -> Result<Option<i64>> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(value) = value.as_i64() {
        return Ok(Some(value));
    }
    if let Some(raw) = value.as_str() {
        if raw.trim().is_empty() {
            return Ok(None);
        }
        return raw
            .trim()
            .parse::<i64>()
            .map_err(|_| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!("request option `serverID` must be an integer: {raw}"),
                )
                .with_rule_path("resolveUrl.serverID")
            })
            .map(Some);
    }
    Err(Diagnostic::new(
        DiagnosticKind::Request,
        format!("request option `serverID` must be an integer: {value}"),
    )
    .with_rule_path("resolveUrl.serverID"))
}

fn parse_explore_items(raw: &str) -> Result<Vec<ExploreItem>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("null") || raw.eq_ignore_ascii_case("undefined") {
        return Ok(Vec::new());
    }
    if !raw.starts_with('[') && !raw.starts_with('{') {
        return Ok(raw
            .split('\n')
            .flat_map(|line| line.split("&&"))
            .filter_map(|item| {
                let item = item.trim();
                if item.is_empty() {
                    return None;
                }
                let mut parts = item.splitn(2, "::");
                Some(ExploreItem {
                    title: parts.next().unwrap_or_default().to_string(),
                    url: parts.next().unwrap_or_default().to_string(),
                    item_type: "url".to_string(),
                    action: String::new(),
                    chars: Vec::new(),
                    default: String::new(),
                    style: serde_json::Value::Null,
                })
            })
            .collect());
    }
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("exploreUrl did not return a JSON array: {err}"),
        )
        .with_rule_path("exploreUrl")
        .with_script(raw)
    })?;
    let Some(items) = value.as_array() else {
        return Err(Diagnostic::new(
            DiagnosticKind::Extraction,
            "exploreUrl returned JSON but not an array",
        )
        .with_rule_path("exploreUrl")
        .with_script(raw));
    };
    Ok(items
        .iter()
        .map(|item| ExploreItem {
            title: item
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            url: item
                .get("url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            item_type: item
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("url")
                .to_string(),
            action: item
                .get("action")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            chars: item
                .get("chars")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|value| value.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            default: item
                .get("default")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            style: item
                .get("style")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        })
        .collect())
}

fn install_explore_info_map(js: &mut JsRuntime, source_key: &str) -> Result<()> {
    let source_key = serde_json::to_string(source_key).unwrap_or_else(|_| "\"\"".to_string());
    let script = format!(
        r#"(function() {{
  var sourceKey = {source_key};
  var storeKey = "infoMap_" + sourceKey;
  function load() {{
    try {{
      var raw = cache.get(storeKey) || "{{}}";
      var value = JSON.parse(raw);
      return value && typeof value === "object" ? value : {{}};
    }} catch (e) {{
      return {{}};
    }}
  }}
  var actual = load();
  function save() {{
    cache.put(storeKey, JSON.stringify(actual || {{}}));
  }}
  globalThis.infoMap = {{
    get: function(key) {{
      if (arguments.length === 0) return actual;
      var value = actual[String(key)];
      return value === undefined ? null : String(value);
    }},
    set: function(value) {{
      actual = value && typeof value === "object" ? value : {{}};
      save();
    }},
    put: function(key, value) {{
      actual[String(key)] = String(value);
      save();
      return String(value);
    }},
    remove: function(key) {{
      var old = actual[String(key)];
      delete actual[String(key)];
      save();
      return old === undefined ? null : String(old);
    }},
    putAll: function(value) {{
      if (value && typeof value === "object") {{
        Object.keys(value).forEach(function(key) {{
          actual[String(key)] = String(value[key]);
        }});
        save();
      }}
    }},
    containsKey: function(key) {{
      return Object.prototype.hasOwnProperty.call(actual, String(key));
    }},
    containsValue: function(value) {{
      return Object.keys(actual).some(function(key) {{
        return String(actual[key]) === String(value);
      }});
    }},
    isEmpty: function() {{
      return Object.keys(actual).length === 0;
    }},
    clear: function() {{
      actual = {{}};
      save();
    }},
    save: function() {{ save(); }},
    saveNow: function() {{ save(); }}
  }};
}})()"#
    );
    js.eval_rule_script_with_bindings(&script, "exploreUrl.infoMap", "", "", "", 1, "")
        .map(|_| ())
}

fn book_binding_field(bindings_json: &str, key: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(bindings_json).ok()?;
    let book = value.get("book")?;
    let field = book.get(key)?;
    Some(match field {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        value => serde_json::to_string(value).unwrap_or_default(),
    })
}

fn unsupported_platform_api_in(text: &str) -> Option<&'static str> {
    [
        "java.startBrowserAwait",
        "java.startBrowser",
        "java.showBrowser",
        "java.openVideoPlayer",
        "startBrowserAwait",
        "startBrowser",
        "showBrowser",
        "openVideoPlayer",
    ]
    .into_iter()
    .find(|api| text.contains(api))
}

fn absolutize(base: &str, raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with("data:") {
        return Ok(raw.to_string());
    }
    let parsed = parse_legado_request(raw)?;
    let raw_url = parsed.url.as_str();
    if Url::parse(raw_url).is_ok() {
        return Ok(raw.to_string());
    }
    let base = Url::parse(base).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!("invalid base URL {base}: {err}"),
        )
    })?;
    let joined = base.join(raw_url).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!("invalid relative URL {raw_url}: {err}"),
        )
    })?;
    if let Some(options) = parsed.options_json {
        Ok(format!("{joined},{options}"))
    } else {
        Ok(joined.to_string())
    }
}

fn absolutize_url_preserving_options(base: &str, raw: &str) -> Result<String> {
    let raw = raw.trim();
    let (raw_url, options) = split_legado_url_options(raw);
    let url = if raw_url.is_empty() || raw_url.starts_with("data:") || Url::parse(&raw_url).is_ok()
    {
        raw_url
    } else {
        let base = Url::parse(base).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::RuleParse,
                format!("invalid base URL {base}: {err}"),
            )
        })?;
        base.join(&raw_url)
            .map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::RuleParse,
                    format!("invalid relative URL {raw_url}: {err}"),
                )
            })?
            .to_string()
    };
    if let Some(options) = options {
        Ok(format!("{url},{options}"))
    } else {
        Ok(url)
    }
}

fn zip_single_file_bytes(file_name: &str, body: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    writer
        .start_file(file_name, options)
        .map_err(|err| err.to_string())?;
    writer.write_all(body).map_err(|err| err.to_string())?;
    writer
        .finish()
        .map_err(|err| err.to_string())
        .map(|cursor| cursor.into_inner())
}

fn json_value_to_legacy_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn tts_bindings_json(input: &AnalyzerInput) -> Result<String> {
    let mut bindings = serde_json::Map::new();
    if !input.bindings_json.trim().is_empty() {
        let value: serde_json::Value =
            serde_json::from_str(&input.bindings_json).map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::RuleParse,
                    format!("invalid bindings JSON for raw fetch: {err}"),
                )
            })?;
        if let Some(map) = value.as_object() {
            bindings.extend(map.clone());
        }
    }
    bindings.insert(
        "speakText".to_string(),
        serde_json::Value::String(input.speak_text.clone()),
    );
    bindings.insert(
        "speakSpeed".to_string(),
        serde_json::Value::Number(serde_json::Number::from(input.speak_speed)),
    );
    serde_json::to_string(&serde_json::Value::Object(bindings)).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("failed to serialize raw fetch bindings: {err}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{clear_persistent_store_for_tests, configure_persistent_store_dir};
    use base64::Engine;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::thread;

    static PERSISTENT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_source(key: &str) -> BookSource {
        let mut source = BookSource::parse_first("[{}]").unwrap();
        source.book_source_url = key.to_string();
        source.book_source_name = key.to_string();
        source
    }

    fn eval_with_source(source: BookSource, script: &str, session: AnalyzerSession) -> String {
        let mut analyzer = Analyzer::new(source, session).unwrap();
        analyzer
            .eval(AnalyzerInput {
                script: script.to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap()
            .eval_result
            .unwrap_or_default()
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut temp = [0_u8; 4096];
        let mut header_end = None;
        while header_end.is_none() {
            let read = stream.read(&mut temp).unwrap();
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..read]);
            header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n");
        }
        if let Some(header_end) = header_end {
            let headers = String::from_utf8_lossy(&buffer[..header_end + 4]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let body_start = header_end + 4;
            while buffer.len().saturating_sub(body_start) < content_length {
                let read = stream.read(&mut temp).unwrap();
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..read]);
            }
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }

    #[test]
    fn dict_search_fetches_url_rule_and_extracts_show_rule() {
        let source = test_source("https://dict.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .dict_search(AnalyzerInput {
                key: "term".to_string(),
                page: 1,
                book_url: "data:text/html,%3Chtml%3E%3Cbody%3E%3Cdiv%20class%3D%22def%22%3Ehello%3C%2Fdiv%3E%3C%2Fbody%3E%3C%2Fhtml%3E".to_string(),
                script: ".def@text".to_string(),
                rule_path: "DictRule.test".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(output.eval_result.as_deref(), Some("hello"));
    }

    #[test]
    fn dict_search_returns_body_when_show_rule_is_blank() {
        let source = test_source("https://dict.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let body = "<html><body>raw</body></html>";

        let output = analyzer
            .dict_search(AnalyzerInput {
                key: "term".to_string(),
                page: 1,
                book_url: format!(
                    "data:text/html,{}",
                    percent_encoding::utf8_percent_encode(body, percent_encoding::NON_ALPHANUMERIC)
                ),
                script: String::new(),
                rule_path: "DictRule.test".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(output.eval_result.as_deref(), Some(body));
    }

    #[test]
    fn explore_kinds_accepts_legacy_text_rule() {
        let mut source = test_source("https://explore.example/");
        source.explore_url = "分类一::/one&&分类二::/two\n分类三::/three".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer.explore(AnalyzerInput::default()).unwrap();

        assert_eq!(output.explore.len(), 3);
        assert_eq!(output.explore[0].title, "分类一");
        assert_eq!(output.explore[0].url, "/one");
        assert_eq!(output.explore[1].title, "分类二");
        assert_eq!(output.explore[1].url, "/two");
        assert_eq!(output.explore[2].title, "分类三");
        assert_eq!(output.explore[2].url, "/three");
    }

    #[test]
    fn explore_kinds_js_gets_persistent_info_map() {
        let _guard = PERSISTENT_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        clear_persistent_store_for_tests();
        configure_persistent_store_dir(dir.path()).unwrap();

        let mut source = test_source("https://explore-info.example/");
        source.explore_url = r#"@js:
var old = infoMap.get("seen") || "none";
infoMap.put("seen", "yes");
JSON.stringify([{title: old, url: infoMap.get("seen")}])
"#
        .to_string();

        let mut analyzer = Analyzer::new(source.clone(), AnalyzerSession::default()).unwrap();
        let first = analyzer.explore(AnalyzerInput::default()).unwrap();
        assert_eq!(first.explore[0].title, "none");
        assert_eq!(first.explore[0].url, "yes");

        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let second = analyzer.explore(AnalyzerInput::default()).unwrap();
        assert_eq!(second.explore[0].title, "yes");
        assert_eq!(second.explore[0].url, "yes");
    }

    #[test]
    fn book_last_chapter_rule_errors_fail_fast() {
        let body = r#"<html><body><a class="book" href="https://book.example/1"><span class="name">Book</span></a></body></html>"#;
        let url = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(body, percent_encoding::NON_ALPHANUMERIC)
        );

        let mut source = test_source("https://search.example/");
        source.search_url = url.clone();
        source.rule_search.book_list = ".book".to_string();
        source.rule_search.name = ".name@text".to_string();
        source.rule_search.book_url = "@href".to_string();
        source.rule_search.last_chapter = "span[".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let err = analyzer
            .search(AnalyzerInput::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("ruleSearch.lastChapter"), "{err}");

        let mut source = test_source("https://explore.example/");
        source.rule_explore.book_list = ".book".to_string();
        source.rule_explore.name = ".name@text".to_string();
        source.rule_explore.book_url = "@href".to_string();
        source.rule_explore.last_chapter = "span[".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let err = analyzer
            .explore(AnalyzerInput {
                explore_url: url.clone(),
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("ruleExplore.lastChapter"), "{err}");

        let mut source = test_source("https://detail.example/");
        source.rule_book_info.name = ".name@text".to_string();
        source.rule_book_info.last_chapter = "span[".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let err = analyzer
            .detail(AnalyzerInput {
                book_url: url,
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("ruleBookInfo.lastChapter"), "{err}");
    }

    #[test]
    fn search_evaluates_url_option_js_and_body_js_before_rules() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /signed HTTP/1.1"), "{request}");
            assert!(request.contains("x-debug: 1"));
            let body = r#"<html><body><a class="book" href="/b1"><span class="name">Raw</span></a></body></html>"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let mut source = test_source(&base);
        source.search_url = format!(
            "{base}/start,{{\"js\":\"result.replace('start','signed')\",\"bodyJs\":\"result.replace('Raw','Book')\",\"headers\":{{\"X-Debug\":\"1\"}}}}"
        );
        source.rule_search.book_list = ".book".to_string();
        source.rule_search.name = ".name@text".to_string();
        source.rule_search.book_url = "@href".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .search(AnalyzerInput {
                key: "ignored".to_string(),
                page: 1,
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        assert_eq!(output.books.len(), 1);
        assert_eq!(output.books[0].name, "Book");
        assert_eq!(output.books[0].book_url, format!("{base}/b1"));
    }

    #[test]
    fn detail_and_content_evaluate_url_option_body_js() {
        let detail_body = r#"<html><body><h1>Raw Detail</h1><a class="toc" href="https://book.example/toc">toc</a></body></html>"#;
        let content_body = r#"<html><body><div class="content">Raw Content</div></body></html>"#;
        let mut source = test_source("https://book.example/");
        source.rule_book_info.name = "h1@text".to_string();
        source.rule_book_info.toc_url = ".toc@href".to_string();
        source.rule_content.content = ".content@text".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let detail = analyzer
            .detail(AnalyzerInput {
                book_url: format!(
                    "data:text/html,{},{{\"bodyJs\":\"result.replace('Raw Detail','Final Detail')\"}}",
                    percent_encoding::utf8_percent_encode(
                        detail_body,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                ..AnalyzerInput::default()
            })
            .unwrap();
        assert_eq!(detail.book.unwrap().name, "Final Detail");

        let content = analyzer
            .content(AnalyzerInput {
                chapter_url: format!(
                    "data:text/html,{},{{\"bodyJs\":\"result.replace('Raw Content','Final Content')\"}}",
                    percent_encoding::utf8_percent_encode(
                        content_body,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                ..AnalyzerInput::default()
            })
            .unwrap()
            .content
            .unwrap();
        assert_eq!(content.content, "Final Content");
    }

    #[test]
    fn toc_runs_pre_update_js_before_fetching_toc_url() {
        let initial = "data:text/html,%3Chtml%3E%3Cbody%3Ewrong%3C%2Fbody%3E%3C%2Fhtml%3E";
        let updated_body =
            r#"<html><body><a class="chapter" href="https://toc.example/c1">One</a></body></html>"#;
        let updated = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(updated_body, percent_encoding::NON_ALPHANUMERIC)
        );
        let mut source = test_source("https://toc.example/book/");
        source.rule_toc.pre_update_js = format!(
            "book.tocUrl = {};",
            serde_json::to_string(&updated).unwrap()
        );
        source.rule_toc.chapter_list = ".chapter".to_string();
        source.rule_toc.chapter_name = "@text".to_string();
        source.rule_toc.chapter_url = "@href".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .toc(AnalyzerInput {
                book_url: "https://toc.example/book/".to_string(),
                toc_url: initial.to_string(),
                run_pre_update_js: true,
                bindings_json: format!(
                    r#"{{"book":{{"tocUrl":{}}}}}"#,
                    serde_json::to_string(initial).unwrap()
                ),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(output.chapters.len(), 1);
        assert_eq!(output.chapters[0].title, "One");
        assert_eq!(output.chapters[0].url, "https://toc.example/c1");
        assert_eq!(output.session.book_variables.get("tocUrl"), Some(&updated));
    }

    #[test]
    fn toc_does_not_run_pre_update_js_unless_requested() {
        let initial_body = r#"<html><body><a class="chapter" href="https://toc.example/c0">Zero</a></body></html>"#;
        let initial = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(initial_body, percent_encoding::NON_ALPHANUMERIC)
        );
        let updated_body =
            r#"<html><body><a class="chapter" href="https://toc.example/c1">One</a></body></html>"#;
        let updated = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(updated_body, percent_encoding::NON_ALPHANUMERIC)
        );
        let mut source = test_source("https://toc.example/book/");
        source.rule_toc.pre_update_js = format!(
            "book.tocUrl = {};",
            serde_json::to_string(&updated).unwrap()
        );
        source.rule_toc.chapter_list = ".chapter".to_string();
        source.rule_toc.chapter_name = "@text".to_string();
        source.rule_toc.chapter_url = "@href".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .toc(AnalyzerInput {
                book_url: "https://toc.example/book/".to_string(),
                toc_url: initial.clone(),
                bindings_json: format!(
                    r#"{{"book":{{"tocUrl":{}}}}}"#,
                    serde_json::to_string(&initial).unwrap()
                ),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(output.chapters.len(), 1);
        assert_eq!(output.chapters[0].title, "Zero");
        assert_ne!(output.session.book_variables.get("tocUrl"), Some(&updated));
    }

    #[test]
    fn pre_update_toc_syncs_book_mutations_without_fetching_toc() {
        let mut source = test_source("https://toc.example/book/");
        source.rule_toc.pre_update_js =
            "book.bookUrl = 'https://toc.example/new-book'; book.tocUrl = 'https://toc.example/new-toc';"
                .to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .pre_update_toc(AnalyzerInput {
                book_url: "https://toc.example/book/".to_string(),
                toc_url: "https://toc.example/toc".to_string(),
                bindings_json: r#"{"book":{"bookUrl":"https://toc.example/book/","tocUrl":"https://toc.example/toc"}}"#.to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(
            output
                .session
                .book_variables
                .get("bookUrl")
                .map(String::as_str),
            Some("https://toc.example/new-book")
        );
        assert_eq!(
            output
                .session
                .book_variables
                .get("tocUrl")
                .map(String::as_str),
            Some("https://toc.example/new-toc")
        );
    }

    #[test]
    fn pre_update_refresh_toc_url_reloads_detail_in_rust() {
        let detail_body = r#"<html><body><a class="toc" href="https://refresh.example/new-toc">toc</a><h1>Fresh</h1></body></html>"#;
        let detail_url = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(detail_body, percent_encoding::NON_ALPHANUMERIC)
        );
        let mut source = test_source("https://refresh.example/");
        source.rule_book_info.name = "h1@text".to_string();
        source.rule_book_info.toc_url = ".toc@href".to_string();
        source.rule_toc.pre_update_js = "java.refreshTocUrl();".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .pre_update_toc(AnalyzerInput {
                book_url: detail_url.clone(),
                toc_url: "https://refresh.example/old-toc".to_string(),
                bindings_json: format!(
                    r#"{{"book":{{"bookUrl":{},"tocUrl":"https://refresh.example/old-toc","name":"Fresh"}}}}"#,
                    serde_json::to_string(&detail_url).unwrap()
                ),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(
            output
                .session
                .book_variables
                .get("tocUrl")
                .map(String::as_str),
            Some("https://refresh.example/new-toc")
        );
        assert_eq!(
            output
                .session
                .book_variables
                .get("name")
                .map(String::as_str),
            Some("Fresh")
        );
    }

    #[test]
    fn pre_update_re_get_book_searches_and_reloads_detail_in_rust() {
        let detail_body = r#"<html><body><a class="toc" href="https://reget.example/fresh-toc">toc</a><h1>Fresh Book</h1><span class="author">Author</span></body></html>"#;
        let detail_url = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(detail_body, percent_encoding::NON_ALPHANUMERIC)
        );
        let search_body = format!(
            r#"<html><body><a class="book" href="{}"><span class="name">Fresh Book</span><span class="author">Author</span></a></body></html>"#,
            detail_url
        );
        let search_url = format!(
            "data:text/html,{}",
            percent_encoding::utf8_percent_encode(&search_body, percent_encoding::NON_ALPHANUMERIC)
        );
        let mut source = test_source("https://reget.example/");
        source.search_url = search_url;
        source.rule_search.book_list = ".book".to_string();
        source.rule_search.name = ".name@text".to_string();
        source.rule_search.author = ".author@text".to_string();
        source.rule_search.book_url = "@href".to_string();
        source.rule_book_info.name = "h1@text".to_string();
        source.rule_book_info.author = ".author@text".to_string();
        source.rule_book_info.toc_url = ".toc@href".to_string();
        source.rule_toc.pre_update_js = "java.reGetBook();".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .pre_update_toc(AnalyzerInput {
                book_url: "https://reget.example/stale-book".to_string(),
                toc_url: "https://reget.example/stale-toc".to_string(),
                bindings_json: r#"{"book":{"bookUrl":"https://reget.example/stale-book","tocUrl":"https://reget.example/stale-toc","name":"Fresh Book","author":"Author"}}"#.to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(
            output
                .session
                .book_variables
                .get("bookUrl")
                .map(String::as_str),
            Some(detail_url.as_str())
        );
        assert_eq!(
            output
                .session
                .book_variables
                .get("tocUrl")
                .map(String::as_str),
            Some("https://reget.example/fresh-toc")
        );
        assert_eq!(
            output
                .session
                .book_variables
                .get("author")
                .map(String::as_str),
            Some("Author")
        );
    }

    #[test]
    fn pre_update_actions_fail_fast_outside_pre_update_js() {
        let source = test_source("https://pre-update.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let err = analyzer
            .eval(AnalyzerInput {
                script: "java.refreshTocUrl()".to_string(),
                rule_path: "not.preUpdate".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("java.refreshTocUrl can only be called in ruleToc.preUpdateJs"),
            "{err}"
        );
        assert!(err.contains("not.preUpdate"), "{err}");
    }

    #[test]
    fn toc_follows_next_toc_url_and_formats_titles() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                let body = if request.starts_with("GET /page2 ") {
                    r#"<html><body><a class="chapter" href="/c2">Two</a></body></html>"#
                } else {
                    r#"<html><body><a class="chapter" href="/c1">One</a><a class="next" href="/page2">next</a></body></html>"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });
        let mut source = test_source(&base);
        source.rule_toc.chapter_list = ".chapter".to_string();
        source.rule_toc.chapter_name = "@text".to_string();
        source.rule_toc.chapter_url = "@href".to_string();
        source.rule_toc.next_toc_url = ".next@href".to_string();
        source.rule_toc.format_js = "return index + ':' + title + ':' + gInt;".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .toc(AnalyzerInput {
                toc_url: base.clone(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        assert_eq!(output.chapters.len(), 2);
        assert_eq!(output.chapters[0].title, "1:One:0");
        assert_eq!(output.chapters[0].url, format!("{base}/c1"));
        assert_eq!(output.chapters[1].title, "2:Two:1");
        assert_eq!(output.chapters[1].url, format!("{base}/c2"));
    }

    #[test]
    fn toc_update_time_rule_errors_fail_fast() {
        let mut source = test_source("https://toc.example/");
        source.rule_toc.chapter_list = ".chapter".to_string();
        source.rule_toc.chapter_name = "@text".to_string();
        source.rule_toc.chapter_url = "@href".to_string();
        source.rule_toc.update_time = "span[".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let err = analyzer
            .toc(AnalyzerInput {
                toc_url:
                    "data:text/html,<html><body><a class='chapter' href='/c1'>One</a></body></html>"
                        .to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("ruleToc.updateTime"), "{err}");
    }

    #[test]
    fn toc_flag_rule_errors_fail_fast() {
        for field in ["ruleToc.isVip", "ruleToc.isPay", "ruleToc.isVolume"] {
            let mut source = test_source("https://toc.example/");
            source.rule_toc.chapter_list = ".chapter".to_string();
            source.rule_toc.chapter_name = "@text".to_string();
            source.rule_toc.chapter_url = "@href".to_string();
            match field {
                "ruleToc.isVip" => source.rule_toc.is_vip = "span[".to_string(),
                "ruleToc.isPay" => source.rule_toc.is_pay = "span[".to_string(),
                "ruleToc.isVolume" => source.rule_toc.is_volume = "span[".to_string(),
                _ => unreachable!(),
            }
            let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

            let err = analyzer
                .toc(AnalyzerInput {
                    toc_url:
                        "data:text/html,<html><body><a class='chapter' href='/c1'>One</a></body></html>"
                            .to_string(),
                    ..AnalyzerInput::default()
                })
                .unwrap_err()
                .to_string();
            assert!(err.contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn content_follows_next_content_url_until_next_chapter_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_http_request(&mut stream);
                let body = if request.starts_with("GET /c1p2 ") {
                    r#"<html><body><h1>Ignored</h1><div class="content">Two</div><a class="next" href="/c2">next chapter</a></body></html>"#
                } else {
                    r#"<html><body><h1>Title One</h1><div class="content">One</div><a class="next" href="/c1p2">next page</a></body></html>"#
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let mut source = test_source(&base);
        source.rule_content.content = ".content@text".to_string();
        source.rule_content.title = "h1@text".to_string();
        source.rule_content.next_content_url = ".next@href".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .content(AnalyzerInput {
                chapter_url: format!("{base}/c1"),
                next_chapter_url: format!("{base}/c2"),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        let content = output.content.unwrap();
        assert_eq!(content.title, "Title One");
        assert_eq!(content.content, "One\nTwo");
        assert_eq!(content.next_content_url, "/c2");
    }

    #[test]
    fn content_next_content_url_rule_errors_fail_fast() {
        let mut source = test_source("https://content.example/");
        source.rule_content.content = ".content@text".to_string();
        source.rule_content.next_content_url = "div[".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let err = analyzer
            .content(AnalyzerInput {
                chapter_url:
                    "data:text/html,<html><body><div class='content'>One</div></body></html>"
                        .to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("ruleContent.nextContentUrl"), "{err}");
    }

    #[test]
    fn content_title_rule_errors_fail_fast() {
        let mut source = test_source("https://content.example/");
        source.rule_content.content = ".content@text".to_string();
        source.rule_content.title = "h1[".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let err = analyzer
            .content(AnalyzerInput {
                chapter_url:
                    "data:text/html,<html><body><div class='content'>One</div></body></html>"
                        .to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("ruleContent.title"), "{err}");
    }

    #[test]
    fn content_replace_regex_js_receives_extracted_content_not_raw_page() {
        let mut source = test_source("https://content.example/");
        source.rule_content.content = ".content@html".to_string();
        source.rule_content.replace_regex = "<js>result.replace('One', 'Two')</js>".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let body =
            r#"<html><body><div class="content"><p>One</p></div><div>Outside</div></body></html>"#;

        let output = analyzer
            .content(AnalyzerInput {
                chapter_url: format!(
                    "data:text/html,{}",
                    percent_encoding::utf8_percent_encode(body, percent_encoding::NON_ALPHANUMERIC)
                ),
                ..AnalyzerInput::default()
            })
            .unwrap();

        let content = output.content.unwrap().content;
        assert!(content.contains("Two"));
        assert!(!content.contains("Outside"));
        assert!(!content.contains("<div"));
    }

    #[test]
    fn content_appends_sub_content_for_online_text_before_replace_regex() {
        let mut source = test_source("https://content.example/");
        source.rule_content.content = ".content@text".to_string();
        source.rule_content.sub_content = ".extra@text".to_string();
        source.rule_content.replace_regex = "<js>result.replace('Extra', 'Sub')</js>".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let body = r#"<html><body><div class="content">Main</div><div class="extra">Extra</div></body></html>"#;

        let output = analyzer
            .content(AnalyzerInput {
                chapter_url: format!(
                    "data:text/html,{}",
                    percent_encoding::utf8_percent_encode(body, percent_encoding::NON_ALPHANUMERIC)
                ),
                bindings_json: r#"{"book":{"type":8}}"#.to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        let content = output.content.unwrap();
        assert_eq!(content.content, "Main\nSub");
        assert_eq!(content.sub_content, "Extra");
    }

    #[test]
    fn content_returns_fetched_sub_content_for_audio_without_appending() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let lyric_url = format!("http://{}/lyric", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /lyric "));
            let body = "LYRIC";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let mut source = test_source("https://content.example/");
        source.rule_content.content = ".content@text".to_string();
        source.rule_content.sub_content = ".lyric@href".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let body = format!(
            r#"<html><body><div class="content">Audio URL</div><a class="lyric" href="{lyric_url}">lyric</a></body></html>"#
        );

        let output = analyzer
            .content(AnalyzerInput {
                chapter_url: format!(
                    "data:text/html,{}",
                    percent_encoding::utf8_percent_encode(
                        &body,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                bindings_json: r#"{"book":{"type":32}}"#.to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        let content = output.content.unwrap();
        assert_eq!(content.content, "Audio URL");
        assert_eq!(content.sub_content, "LYRIC");
    }

    #[test]
    fn content_fails_fast_when_webview_source_extraction_is_required() {
        let mut source = test_source("https://content.example/");
        source.rule_content.content = ".content@text".to_string();
        source.rule_content.web_js = "document.body.innerHTML".to_string();
        source.rule_content.source_regex = "window.__DATA__".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let err = analyzer
            .content(AnalyzerInput {
                chapter_url: "https://content.example/chapter".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err();

        assert_eq!(err.kind, DiagnosticKind::UnsupportedPlatformApi);
        let message = err.to_string();
        assert!(message.contains("ruleContent.webJs/sourceRegex"));
        assert!(message.contains("document.body.innerHTML"));
        assert!(message.contains("https://content.example/chapter"));
    }

    #[test]
    fn cover_search_fetches_url_rule_and_resolves_cover_rule_url() {
        let source = test_source("https://cover.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let body =
            r#"<html><body><img class="cover" src="https://img.example/c.jpg"></body></html>"#;

        let output = analyzer
            .cover_search(AnalyzerInput {
                key: "book".to_string(),
                page: 1,
                book_url: format!(
                    "data:text/html,{}",
                    percent_encoding::utf8_percent_encode(body, percent_encoding::NON_ALPHANUMERIC)
                ),
                script: ".cover@src".to_string(),
                rule_path: "BookCover.coverRule".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(
            output.eval_result.as_deref(),
            Some("https://img.example/c.jpg")
        );
    }

    #[test]
    fn cover_search_exposes_book_binding_to_js_cover_rule() {
        let source = test_source("https://cover.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let body =
            r#"<html><body><img class="cover" src="https://img.example/c.jpg"></body></html>"#;

        let output = analyzer
            .cover_search(AnalyzerInput {
                key: "book".to_string(),
                page: 1,
                book_url: format!(
                    "data:text/html,{}",
                    percent_encoding::utf8_percent_encode(body, percent_encoding::NON_ALPHANUMERIC)
                ),
                script: r#"@js: return book.name === "Bound Book" ? result.match(/src="([^"]+)/)[1] : """#.to_string(),
                rule_path: "BookCover.coverRule".to_string(),
                bindings_json: r#"{"book":{"name":"Bound Book"}}"#.to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(
            output.eval_result.as_deref(),
            Some("https://img.example/c.jpg")
        );
    }

    #[test]
    fn resolve_url_returns_final_url_options_and_server_id() {
        let source = test_source("https://source.example/root/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .resolve_url(AnalyzerInput {
                book_url: "folder/file,{\"headers\":{\"X-Test\":\"1\"},\"serverID\":\"42\"}"
                    .to_string(),
                base_url: "https://webdav.example/base/".to_string(),
                page: 1,
                ..AnalyzerInput::default()
            })
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(
            value["url"].as_str(),
            Some("https://webdav.example/base/folder/file")
        );
        assert_eq!(value["serverId"].as_i64(), Some(42));
        assert_eq!(value["headers"][0][0].as_str(), Some("X-Test"));
        assert_eq!(value["headers"][0][1].as_str(), Some("1"));
    }

    #[test]
    fn resolve_url_fails_fast_on_invalid_server_id() {
        let source = test_source("https://source.example/root/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let err = analyzer
            .resolve_url(AnalyzerInput {
                book_url: "folder/file,{\"serverID\":\"not-a-number\"}".to_string(),
                base_url: "https://webdav.example/base/".to_string(),
                page: 1,
                ..AnalyzerInput::default()
            })
            .unwrap_err()
            .to_string();

        assert!(err.contains("serverID"), "{err}");
        assert!(err.contains("resolveUrl.serverID"), "{err}");
    }

    #[test]
    fn resolve_url_allows_blank_server_id_like_original_app() {
        let source = test_source("https://source.example/root/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .resolve_url(AnalyzerInput {
                book_url: "folder/file,{\"serverID\":\"   \"}".to_string(),
                base_url: "https://webdav.example/base/".to_string(),
                page: 1,
                ..AnalyzerInput::default()
            })
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert!(value["serverId"].is_null(), "{value}");
    }

    #[test]
    fn resolve_url_evaluates_url_option_js_before_parsing_options() {
        let source = test_source("https://source.example/root/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .resolve_url(AnalyzerInput {
                book_url: "folder/start,{\"js\":\"result.replace('start','signed')\",\"headers\":{\"X-Test\":\"1\"}}".to_string(),
                base_url: "https://media.example/base/".to_string(),
                page: 1,
                ..AnalyzerInput::default()
            })
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(
            value["url"].as_str(),
            Some("https://media.example/base/folder/signed")
        );
        assert_eq!(value["headers"][0][0].as_str(), Some("X-Test"));
    }

    #[test]
    fn resolve_url_for_media_keeps_relative_url_and_headers() {
        let source = test_source("https://media-source.example/root/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .resolve_url(AnalyzerInput {
                book_url:
                    "audio/ep01.m3u8,{\"headers\":{\"Referer\":\"https://reader.example/book\"}}"
                        .to_string(),
                base_url: "https://cdn.example/series/".to_string(),
                page: 1,
                ..AnalyzerInput::default()
            })
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(
            value["url"].as_str(),
            Some("https://cdn.example/series/audio/ep01.m3u8")
        );
        assert_eq!(value["headers"][0][0].as_str(), Some("Referer"));
        assert_eq!(
            value["headers"][0][1].as_str(),
            Some("https://reader.example/book")
        );
    }

    #[test]
    fn direct_link_upload_posts_multipart_and_extracts_download_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST / HTTP/1.1"));
            assert!(request.contains("multipart/form-data"));
            assert!(request.contains("name=\"file\"; filename=\"rule.json\""));
            assert!(request.contains("application/json"));
            assert!(request.contains("{\"name\":\"source\"}"));
            let body = r#"{"data":"https://download.example/rule.json"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .direct_link_upload(AnalyzerInput {
                book_url: format!(
                    "{url},{{\"method\":\"POST\",\"body\":{{\"file\":\"fileRequest\"}},\"type\":\"multipart/form-data\"}}"
                ),
                script: "$.data".to_string(),
                upload_file_name: "rule.json".to_string(),
                upload_content_type: "application/json".to_string(),
                upload_body_base64: base64::engine::general_purpose::STANDARD
                    .encode(br#"{"name":"source"}"#),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        assert_eq!(
            output.eval_result.as_deref(),
            Some("https://download.example/rule.json")
        );
    }

    #[test]
    fn direct_link_upload_compresses_file_in_rust_before_multipart_post() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST / HTTP/1.1"), "{request}");
            assert!(
                request.contains("name=\"file\"; filename=\"rule.json.zip\""),
                "{request}"
            );
            assert!(request.contains("application/zip"), "{request}");
            assert!(request.contains("PK"), "{request}");
            let body = r#"{"data":"https://download.example/rule.json.zip"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .direct_link_upload(AnalyzerInput {
                book_url: format!(
                    "{url},{{\"method\":\"POST\",\"body\":{{\"file\":\"fileRequest\"}},\"type\":\"multipart/form-data\"}}"
                ),
                script: "$.data".to_string(),
                upload_file_name: "rule.json".to_string(),
                upload_content_type: "application/json".to_string(),
                upload_body_base64: base64::engine::general_purpose::STANDARD
                    .encode(br#"{"name":"source"}"#),
                upload_compress: true,
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        assert_eq!(
            output.eval_result.as_deref(),
            Some("https://download.example/rule.json.zip")
        );
    }

    #[test]
    fn direct_link_upload_evaluates_url_option_js_before_post() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /signed HTTP/1.1"), "{request}");
            let body = r#"{"data":"ok"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .direct_link_upload(AnalyzerInput {
                book_url: format!(
                    "{url}/start,{{\"js\":\"result.replace('start','signed')\",\"method\":\"POST\",\"body\":{{\"file\":\"fileRequest\"}},\"type\":\"multipart/form-data\"}}"
                ),
                script: "$.data".to_string(),
                upload_file_name: "rule.json".to_string(),
                upload_content_type: "application/json".to_string(),
                upload_body_base64: base64::engine::general_purpose::STANDARD.encode(b"{}"),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        assert_eq!(output.eval_result.as_deref(), Some("ok"));
    }

    #[test]
    fn direct_link_upload_preserves_request_options_for_multipart_post() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /upload HTTP/1.1"), "{request}");
            assert!(
                request.contains(&format!("Host: legado-upload.test:{port}"))
                    || request.contains(&format!("host: legado-upload.test:{port}")),
                "{request}"
            );
            assert!(request.contains("multipart/form-data"), "{request}");
            let body = r#"{"data":"dns-ok"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&format!("http://legado-upload.test:{port}"));
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .direct_link_upload(AnalyzerInput {
                book_url: format!(
                    "http://legado-upload.test:{port}/upload,{{\"method\":\"POST\",\"body\":{{\"file\":\"fileRequest\"}},\"type\":\"multipart/form-data\",\"dnsIp\":\"127.0.0.1\",\"redirect\":false,\"retry\":1}}"
                ),
                script: "$.data".to_string(),
                upload_file_name: "rule.json".to_string(),
                upload_content_type: "application/json".to_string(),
                upload_body_base64: base64::engine::general_purpose::STANDARD.encode(b"{}"),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();

        assert_eq!(output.eval_result.as_deref(), Some("dns-ok"));
    }

    #[test]
    fn fetch_text_gets_html_with_url_option_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET / HTTP/1.1"));
            assert!(request.contains("x-debug: 1"));
            let body = "<html><title>ok</title></html>";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .fetch_text(AnalyzerInput {
                book_url: format!("{url},{{\"headers\":{{\"X-Debug\":\"1\"}}}}"),
                rule_path: "test.fetchText".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        let expected_url = format!("{url}/");
        assert_eq!(value["url"].as_str(), Some(expected_url.as_str()));
        assert_eq!(value["statusCode"].as_i64(), Some(200));
        assert_eq!(
            value["body"].as_str(),
            Some("<html><title>ok</title></html>")
        );
        assert_eq!(value["contentType"].as_str(), Some("text/html"));
    }

    #[test]
    fn fetch_text_evaluates_url_option_js_before_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /signed HTTP/1.1"), "{request}");
            assert!(request.contains("x-debug: 1"));
            let body = "signed";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .fetch_text(AnalyzerInput {
                book_url: format!(
                    "{url}/start,{{\"js\":\"result.replace('start','signed')\",\"headers\":{{\"X-Debug\":\"1\"}}}}"
                ),
                rule_path: "test.fetchText.urlOptionJs".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(value["body"].as_str(), Some("signed"));
        assert_eq!(value["statusCode"].as_i64(), Some(200));
    }

    #[test]
    fn fetch_text_evaluates_url_option_body_js_after_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /body HTTP/1.1"), "{request}");
            assert!(request.contains("x-debug: 1"));
            let body = "raw body";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .fetch_text(AnalyzerInput {
                book_url: format!(
                    "{url}/body,{{\"bodyJs\":\"result.toUpperCase()\",\"headers\":{{\"X-Debug\":\"1\"}}}}"
                ),
                rule_path: "test.fetchText.urlOptionBodyJs".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(value["body"].as_str(), Some("RAW BODY"));
        assert_eq!(value["statusCode"].as_i64(), Some(200));
    }

    #[test]
    fn fetch_text_fails_fast_when_webview_option_is_requested() {
        let source = test_source("https://webview.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let err = analyzer
            .fetch_text(AnalyzerInput {
                book_url: "https://webview.example/page,{\"webView\":true}".to_string(),
                rule_path: "test.fetchText.webView".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err();

        assert_eq!(err.kind, DiagnosticKind::UnsupportedPlatformApi);
        assert!(err.to_string().contains("WebView platform boundary"));
        assert!(err.to_string().contains("test.fetchText.webView"));
    }

    #[test]
    fn fetch_raw_evaluates_http_tts_speak_bindings_and_posts_audio_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /tts HTTP/1.1"));
            assert!(request.contains("x-tts: 1"));
            assert!(request.contains("tex=%E9%AD%94%E7%A5%9E&spd=6"));
            let body = b"ID3audio";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let mut source = test_source(&url);
        source.header = r#"{"X-TTS":"1"}"#.to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .fetch_raw(AnalyzerInput {
                book_url: format!(
                    r#"{url}/tts,{{"method":"POST","body":"tex={{{{java.encodeURI(speakText)}}}}&spd={{{{speakSpeed - 9}}}}"}}"#
                ),
                speak_text: "魔神".to_string(),
                speak_speed: 15,
                rule_path: "HttpTTS.fetch".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(value["code"].as_i64(), Some(200));
        assert_eq!(value["contentType"].as_str(), Some("audio/mpeg"));
        assert_eq!(value["bodyBase64"].as_str(), Some("SUQzYXVkaW8="));
        let set_cookies = value["headersList"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|pair| {
                pair.get(0)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|name| name.eq_ignore_ascii_case("set-cookie"))
            })
            .count();
        assert_eq!(set_cookies, 2);
    }

    #[test]
    fn fetch_raw_evaluates_url_option_js_before_byte_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /signed HTTP/1.1"), "{request}");
            assert!(request.contains("x-debug: 1"));
            let body = b"raw-bytes";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let source = test_source(&url);
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let output = analyzer
            .fetch_raw(AnalyzerInput {
                book_url: format!(
                    "{url}/start,{{\"js\":\"result.replace('start','signed')\",\"headers\":{{\"X-Debug\":\"1\"}}}}"
                ),
                rule_path: "test.fetchRaw.urlOptionJs".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();
        handle.join().unwrap();
        let value: serde_json::Value =
            serde_json::from_str(output.eval_result.as_deref().unwrap()).unwrap();

        assert_eq!(value["code"].as_i64(), Some(200));
        assert_eq!(value["bodyBase64"].as_str(), Some("cmF3LWJ5dGVz"));
        assert_eq!(
            value["contentType"].as_str(),
            Some("application/octet-stream")
        );
    }

    #[test]
    fn fetch_raw_fails_fast_when_webview_option_is_requested() {
        let source = test_source("https://webview.example/");
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();
        let err = analyzer
            .fetch_raw(AnalyzerInput {
                book_url: "https://webview.example/audio,{\"webView\":true}".to_string(),
                rule_path: "test.fetchRaw.webView".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap_err();

        assert_eq!(err.kind, DiagnosticKind::UnsupportedPlatformApi);
        assert!(err.to_string().contains("WebView platform boundary"));
        assert!(err.to_string().contains("test.fetchRaw.webView"));
    }

    #[test]
    fn eval_can_bootstrap_login_url_before_source_variable_reads() {
        let _guard = PERSISTENT_TEST_LOCK.lock().expect("test lock poisoned");
        clear_persistent_store_for_tests();
        let mut source = test_source("rss://bootstrap-variable");
        source.login_url =
            "var current = source.getVariable(); if (!current) { source.setVariable(JSON.stringify({ url: 'https://example.org' })); }"
                .to_string();
        source.js_lib =
            "function Get(key) { return JSON.parse(source.getVariable())[key]; }".to_string();
        let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .eval(AnalyzerInput {
                script: "Get('url')".to_string(),
                bootstrap_login_url: true,
                rule_path: "test.bootstrap".to_string(),
                ..AnalyzerInput::default()
            })
            .unwrap();

        assert_eq!(output.eval_result.as_deref(), Some("https://example.org"));
        assert_eq!(
            output.session.source_variable,
            r#"{"url":"https://example.org"}"#
        );
    }

    #[test]
    fn rust_persistent_store_keeps_source_state_between_uniffi_style_calls() {
        let _guard = PERSISTENT_TEST_LOCK.lock().expect("test lock poisoned");
        clear_persistent_store_for_tests();
        let dir = tempfile::tempdir().unwrap();
        configure_persistent_store_dir(dir.path()).unwrap();
        let source = test_source("https://source-a.example");

        let out = eval_with_source(
            source.clone(),
            "@js: source.setVariable('token', 'a1'); source.put('local', 's1'); cache.put('shared', 'g1'); cookie.setCookie('v1.example', 'sid=1'); source.putLoginInfo('user', 'alice'); return 'ok'",
            AnalyzerSession::default(),
        );
        assert_eq!(out, "ok");

        let out = eval_with_source(
            source,
            "@js: return source.getVariable('token') + '|' + source.get('local') + '|' + cache.get('shared') + '|' + cookie.getCookie('v1.example') + '|' + JSON.parse(source.getLoginInfo()).user",
            AnalyzerSession::default(),
        );
        assert_eq!(out, "a1|s1|g1|sid=1|alice");
    }

    #[test]
    fn rust_persistent_store_keeps_source_put_scoped_and_cache_global() {
        let _guard = PERSISTENT_TEST_LOCK.lock().expect("test lock poisoned");
        clear_persistent_store_for_tests();
        let dir = tempfile::tempdir().unwrap();
        configure_persistent_store_dir(dir.path()).unwrap();
        eval_with_source(
            test_source("https://source-a.example"),
            "@js: source.put('k', 'source-a'); cache.put('k', 'global'); return 'ok'",
            AnalyzerSession::default(),
        );

        let out = eval_with_source(
            test_source("https://source-b.example"),
            "@js: return source.get('k') + '|' + cache.get('k')",
            AnalyzerSession::default(),
        );
        assert_eq!(out, "|global");
    }

    #[test]
    fn rust_persistent_store_survives_process_store_reload_from_disk() {
        let _guard = PERSISTENT_TEST_LOCK.lock().expect("test lock poisoned");
        clear_persistent_store_for_tests();
        let dir = tempfile::tempdir().unwrap();
        configure_persistent_store_dir(dir.path()).unwrap();

        eval_with_source(
            test_source("https://source-disk.example"),
            "@js: source.put('k', 'disk-source'); cache.put('k', 'disk-cache'); cookie.setCookie('disk.example', 'sid=disk'); return 'ok'",
            AnalyzerSession::default(),
        );

        clear_persistent_store_for_tests();
        configure_persistent_store_dir(dir.path()).unwrap();

        let out = eval_with_source(
            test_source("https://source-disk.example"),
            "@js: return source.get('k') + '|' + cache.get('k') + '|' + cookie.getCookie('disk.example')",
            AnalyzerSession::default(),
        );
        assert_eq!(out, "disk-source|disk-cache|sid=disk");
    }
}
