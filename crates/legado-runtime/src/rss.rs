use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::analyzer::AnalyzerSessionSnapshot;
use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};
use crate::js_runtime::JsRuntime;
use crate::platform::PlatformHostRef;
use crate::request::{
    parse_header_map, parse_legado_request, split_legado_url_options, RequestEngine, RequestOutput,
};
use crate::rule_engine::{is_js_rule, RuleContent, RuleEngine};
use crate::session::{persist_session, restore_persistent_session, AnalyzerSession};
use crate::source::BookSource;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RssSource {
    pub source_url: String,
    pub source_name: String,
    pub source_icon: String,
    pub source_group: Option<String>,
    pub variable_comment: String,
    pub enabled: bool,
    pub js_lib: String,
    pub enabled_cookie_jar: Option<bool>,
    pub concurrent_rate: Option<String>,
    pub header: String,
    pub login_url: String,
    pub login_ui: String,
    pub login_check_js: String,
    pub sort_url: String,
    pub single_url: bool,
    pub rule_articles: String,
    pub rule_next_page: String,
    pub rule_title: String,
    pub rule_pub_date: String,
    pub rule_description: String,
    pub rule_image: String,
    pub rule_link: String,
    pub rule_content: String,
    #[serde(rename = "type")]
    pub item_type: i32,
    pub search_url: String,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RssArticle {
    pub origin: String,
    pub sort: String,
    pub title: String,
    pub order: i64,
    pub link: String,
    pub pub_date: Option<String>,
    pub description: Option<String>,
    pub content: Option<String>,
    pub image: Option<String>,
    pub group: String,
    pub read: bool,
    pub variable: Option<String>,
    #[serde(rename = "type")]
    pub item_type: i32,
    pub dur_pos: i32,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RssOutput {
    pub articles: Vec<RssArticle>,
    pub article: Option<RssArticle>,
    pub content: Option<String>,
    pub next_url: Option<String>,
    pub diagnostics: Vec<String>,
    pub session: AnalyzerSessionSnapshot,
}

pub struct RssAnalyzer {
    source: RssSource,
    compat_source: BookSource,
    source_key: String,
    session: AnalyzerSession,
    request: RequestEngine,
    platform_host: Option<PlatformHostRef>,
}

impl RssSource {
    pub fn parse_many(input: &str) -> Result<Vec<Self>> {
        let value: Value = serde_json::from_str(input).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::SourceParse,
                format!("failed to parse RSS source JSON: {err}"),
            )
        })?;
        match value {
            Value::Array(_) => serde_json::from_value(value).map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::SourceParse,
                    format!("failed to parse RSS source JSON: {err}"),
                )
            }),
            Value::Object(_) => serde_json::from_value(value)
                .map(|source| vec![source])
                .map_err(|err| {
                    Diagnostic::new(
                        DiagnosticKind::SourceParse,
                        format!("failed to parse RSS source JSON: {err}"),
                    )
                }),
            other => Err(Diagnostic::new(
                DiagnosticKind::SourceParse,
                format!("RSS source JSON must be an object or array, got {other}"),
            )),
        }
    }

    pub fn parse_first(input: &str) -> Result<Self> {
        let mut sources = Self::parse_many(input)?;
        sources.pop().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::SourceParse,
                "RSS source JSON did not contain any source",
            )
        })
    }

    fn as_compat_book_source(&self) -> BookSource {
        let mut source = BookSource::parse_first("[{}]").unwrap_or_else(|_| BookSource {
            book_source_name: String::new(),
            book_source_url: String::new(),
            header: String::new(),
            concurrent_rate: String::new(),
            search_url: String::new(),
            explore_url: String::new(),
            js_lib: String::new(),
            login_url: String::new(),
            login_check_js: String::new(),
            rule_search: Default::default(),
            rule_explore: Default::default(),
            rule_book_info: Default::default(),
            rule_toc: Default::default(),
            rule_content: Default::default(),
            extra: Value::Null,
        });
        source.book_source_name = self.source_name.clone();
        source.book_source_url = self.source_url.clone();
        source.header = self.header.clone();
        source.js_lib = self.js_lib.clone();
        source.login_url = self.login_url.clone();
        source.extra = serde_json::to_value(self).unwrap_or(Value::Null);
        if let Value::Object(object) = &mut source.extra {
            object.insert(
                "variableComment".to_string(),
                Value::String(self.variable_comment.clone()),
            );
        }
        source
    }
}

impl RssAnalyzer {
    pub fn new(source: RssSource, session: AnalyzerSession) -> Result<Self> {
        Self::new_with_platform(source, session, None)
    }

    pub fn new_with_platform(
        source: RssSource,
        session: AnalyzerSession,
        platform_host: Option<PlatformHostRef>,
    ) -> Result<Self> {
        let compat_source = source.as_compat_book_source();
        let source_key = source.source_url.clone();
        let session = restore_persistent_session(&source_key, session);
        Ok(Self {
            source,
            compat_source,
            source_key,
            session,
            request: RequestEngine::new()?,
            platform_host,
        })
    }

    fn js_runtime(&self) -> Result<JsRuntime> {
        let mut js = JsRuntime::new_with_platform(
            &self.compat_source,
            self.session.clone(),
            self.platform_host.clone(),
        )?;
        if !self.source.login_url.trim().is_empty() {
            js.eval_rule_script(
                &self.source.login_url,
                "rss.loginUrl.bootstrap",
                "",
                &self.source.source_url,
                "",
                1,
            )?;
        }
        Ok(js)
    }

    pub fn sort_urls(&mut self) -> Result<Vec<(String, String)>> {
        let raw_rule = self.source.sort_url.trim();
        let mut raw = raw_rule.to_string();
        if raw_rule.starts_with("<js>") || raw_rule.starts_with("@js:") {
            let script = strip_wrapped_js(raw_rule);
            let mut js = self.js_runtime()?;
            raw = js
                .eval_rule_script(script, "rss.sortUrl", "", &self.source.source_url, "", 1)
                .map_err(|err| {
                    if err
                        .to_string()
                        .contains("__LEGADO_UNSUPPORTED_PLATFORM_API__")
                    {
                        self.diag(
                            DiagnosticKind::UnsupportedPlatformApi,
                            "RSS sortUrl requires Android platform UI boundary",
                        )
                        .with_rule_path("rss.sortUrl")
                        .with_script(script)
                    } else {
                        err
                    }
                })?;
            self.session = js.session();
            if raw.trim().is_empty() {
                if let Some(message) = session_user_messages(&self.session) {
                    return Err(self
                        .diag(
                            DiagnosticKind::JavaScript,
                            format!("RSS sortUrl returned blank after script message: {message}"),
                        )
                        .with_rule_path("rss.sortUrl")
                        .with_script(script));
                }
            }
        }
        if unsupported_platform_api_in(&raw).is_some() {
            return Err(self
                .diag(
                    DiagnosticKind::UnsupportedPlatformApi,
                    "RSS sortUrl requires Android platform UI boundary",
                )
                .with_rule_path("rss.sortUrl")
                .with_script(raw_rule.to_string()));
        }
        let mut out = Vec::new();
        for item in rss_sort_splitter_re().split(&raw) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let name = item.split_once("::").map(|(name, _)| name).unwrap_or(item);
            let url = item.split_once("::").map(|(_, url)| url).unwrap_or("");
            if !url.is_empty() {
                out.push((name.to_string(), url.to_string()));
            }
        }
        if out.is_empty() && !raw.trim().is_empty() {
            return Err(self
                .diag(
                    DiagnosticKind::RuleParse,
                    format!(
                        "RSS sortUrl returned data but no name::url entries: {}",
                        excerpt(raw.trim(), 240)
                    ),
                )
                .with_rule_path("rss.sortUrl")
                .with_script(raw_rule.to_string()));
        }
        if out.is_empty() {
            out.push(("".to_string(), self.source.source_url.clone()));
        }
        persist_session(&self.source_key, &self.session);
        Ok(out)
    }

    pub fn search(&mut self, key: &str, page: i32) -> Result<RssOutput> {
        let page = page.max(1);
        let rule = if !self.source.search_url.trim().is_empty() {
            self.source.search_url.clone()
        } else if self.source.single_url {
            self.source.source_url.clone()
        } else {
            self.source.sort_url.clone()
        };
        if rule.trim().is_empty() {
            return Err(self
                .diag(
                    DiagnosticKind::SourceParse,
                    "RSS source has no searchUrl/sortUrl/sourceUrl to fetch",
                )
                .with_rule_path("rss.searchUrl"));
        }
        self.articles("搜索", &rule, key, page)
    }

    pub fn articles(
        &mut self,
        sort_name: &str,
        sort_url: &str,
        key: &str,
        page: i32,
    ) -> Result<RssOutput> {
        let mut js = self.js_runtime()?;
        self.seed_sort_url_scope_for_generated_url(&mut js, sort_url)?;
        let response =
            self.fetch_rule_url(&mut js, sort_url, key, page.max(1), "rss.articles.url")?;
        self.apply_login_check(
            &mut js,
            &response,
            key,
            page.max(1),
            "rss.loginCheckJs.articles",
        )?;
        let (articles, next_url) =
            self.parse_articles(&mut js, sort_name, sort_url, &response, key, page.max(1))?;
        self.session = js.session();
        Ok(RssOutput {
            articles,
            next_url,
            session: self.persisted_session_snapshot(),
            ..RssOutput::default()
        })
    }

    pub fn content(&mut self, article: RssArticle) -> Result<RssOutput> {
        self.content_with_rule(article, "")
    }

    pub fn content_with_rule(
        &mut self,
        article: RssArticle,
        rule_content: &str,
    ) -> Result<RssOutput> {
        let rule_content = rule_content.trim();
        let rule_content = if rule_content.is_empty() {
            self.source.rule_content.clone()
        } else {
            rule_content.to_string()
        };
        if rule_content.trim().is_empty() {
            return Ok(RssOutput {
                article: Some(article.clone()),
                content: article.content.clone().or(article.description.clone()),
                session: self.persisted_session_snapshot(),
                ..RssOutput::default()
            });
        }
        let mut js = self.js_runtime()?;
        let rss_bindings = serde_json::json!({ "rssArticle": &article }).to_string();
        js.eval_rule_script_with_bindings(
            "undefined",
            "rss.ruleContent.bindings",
            "",
            &self.source.source_url,
            "",
            1,
            &rss_bindings,
        )?;
        let response = self.fetch_rule_url(&mut js, &article.link, "", 1, "rss.content.url")?;
        self.apply_login_check(&mut js, &response, "", 1, "rss.loginCheckJs.content")?;
        let root = RuleContent::from_body(&response.body);
        let content_result = {
            let mut rules = RuleEngine::new(&mut js);
            rules.eval_field_rule(
                &rule_content,
                &root,
                &response.body,
                &response.url,
                "rss.ruleContent",
                "",
                1,
            )
        };
        let content = match content_result {
            Ok(content) => content,
            Err(err) => {
                self.session = js.session();
                if let Some(message) = session_user_messages(&self.session) {
                    return Err(self
                        .diag(
                            DiagnosticKind::JavaScript,
                            format!(
                                "RSS ruleContent failed after script message: {message}; original={err}"
                            ),
                        )
                        .with_rule_path("rss.ruleContent")
                        .with_script(&rule_content));
                }
                return Err(err);
            }
        };
        self.session = js.session();
        Ok(RssOutput {
            article: Some(article),
            content: Some(content),
            session: self.persisted_session_snapshot(),
            ..RssOutput::default()
        })
    }

    fn fetch_rule_url(
        &mut self,
        js: &mut JsRuntime,
        raw_rule: &str,
        key: &str,
        page: i32,
        rule_path: &str,
    ) -> Result<RequestOutput> {
        let mut rules = RuleEngine::new(js);
        let raw_url = rules.eval_url_rule(raw_rule, key, page, &self.source.source_url)?;
        let url = absolutize(&self.source.source_url, &raw_url).map_err(|err| {
            err.with_source(self.source.source_name.clone())
                .with_rule_path(rule_path)
                .with_script(raw_rule.to_string())
        })?;
        let url = apply_rss_url_option_js(
            js,
            &url,
            &self.source.source_url,
            key,
            page,
            &format!("{rule_path}.urlOption.js"),
        )?;
        let (url, body_js) = consume_url_option_script(&url, "bodyJs", "body_js")?;
        let parsed = parse_legado_request(&url)?;
        if unsupported_platform_api_in(&url).is_some() {
            return Err(self
                .diag(
                    DiagnosticKind::UnsupportedPlatformApi,
                    "RSS URL evaluation reached platform UI API",
                )
                .with_rule_path(rule_path)
                .with_script(raw_rule.to_string()));
        }
        if crate::request::legado_request_wants_webview(&parsed)? {
            return Err(self
                .diag(
                    DiagnosticKind::UnsupportedPlatformApi,
                    "RSS URL request requires WebView platform boundary",
                )
                .with_rule_path(rule_path)
                .with_request(parsed.url, None));
        }
        let headers = self.eval_header_map(js, &url)?;
        self.session = js.session();
        let mut response =
            self.request
                .get_text_with_timeout(&url, headers, None, &mut self.session)?;
        if let Some(body_js) = body_js {
            response.body = js.eval_rule_script(
                &body_js,
                &format!("{rule_path}.urlOption.bodyJs"),
                &response.body,
                &self.source.source_url,
                key,
                page,
            )?;
            self.session = js.session();
        }
        Ok(response)
    }

    fn eval_header_map(
        &self,
        js: &mut JsRuntime,
        request_url: &str,
    ) -> Result<Vec<(String, String)>> {
        let header = self.source.header.trim();
        if header.is_empty() {
            return Ok(Vec::new());
        }
        if is_js_rule(header) {
            let mut rules = RuleEngine::new(js);
            let value = rules.eval_field_rule(
                header,
                &RuleContent::Json(Value::Null),
                "",
                request_url,
                "rss.header",
                "",
                1,
            )?;
            Ok(parse_header_map(&value))
        } else {
            Ok(parse_header_map(header))
        }
    }

    fn apply_login_check(
        &self,
        js: &mut JsRuntime,
        response: &RequestOutput,
        key: &str,
        page: i32,
        rule_path: &str,
    ) -> Result<()> {
        if self.source.login_check_js.trim().is_empty() {
            return Ok(());
        }
        let out = js.eval_rule_script_with_response(
            &self.source.login_check_js,
            rule_path,
            response,
            &response.url,
            key,
            page,
        )?;
        if unsupported_platform_api_in(&out).is_some() {
            return Err(self
                .diag(
                    DiagnosticKind::UnsupportedPlatformApi,
                    "RSS loginCheckJs requires Android platform UI boundary",
                )
                .with_rule_path(rule_path)
                .with_script(self.source.login_check_js.clone()));
        }
        Ok(())
    }

    fn parse_articles(
        &self,
        js: &mut JsRuntime,
        sort_name: &str,
        sort_url: &str,
        response: &RequestOutput,
        key: &str,
        page: i32,
    ) -> Result<(Vec<RssArticle>, Option<String>)> {
        if self.source.rule_articles.trim().is_empty() {
            return Ok((
                parse_default_rss(sort_name, &response.body, &self.source.source_url),
                None,
            ));
        }
        let root = RuleContent::from_body(&response.body);
        let mut rules = RuleEngine::new(js);
        let mut rule_articles = self.source.rule_articles.trim().to_string();
        let reverse = rule_articles.starts_with('-');
        if reverse {
            rule_articles = rule_articles[1..].to_string();
        }
        let items = rules.select_list(
            &rule_articles,
            &root,
            &response.body,
            &response.url,
            "rss.ruleArticles",
        )?;
        let next_url = if self.source.rule_next_page.trim().is_empty() {
            None
        } else if self
            .source
            .rule_next_page
            .trim()
            .eq_ignore_ascii_case("PAGE")
        {
            Some(sort_url.to_string())
        } else {
            let raw = rules.eval_field_rule(
                &self.source.rule_next_page,
                &root,
                &response.body,
                &response.url,
                "rss.ruleNextPage",
                key,
                page,
            )?;
            if raw.trim().is_empty() {
                None
            } else {
                Some(absolutize(&response.url, &raw)?)
            }
        };
        let mut articles = Vec::new();
        for (index, item) in items.into_iter().enumerate() {
            let title = rules.eval_field_rule(
                &self.source.rule_title,
                &item,
                &response.body,
                &response.url,
                "rss.ruleTitle",
                key,
                page,
            )?;
            if title.trim().is_empty() {
                continue;
            }
            let pub_date = none_if_blank(rules.eval_field_rule(
                &self.source.rule_pub_date,
                &item,
                &response.body,
                &response.url,
                "rss.rulePubDate",
                key,
                page,
            )?);
            let description = if self.source.rule_description.trim().is_empty() {
                None
            } else {
                none_if_blank(rules.eval_field_rule(
                    &self.source.rule_description,
                    &item,
                    &response.body,
                    &response.url,
                    "rss.ruleDescription",
                    key,
                    page,
                )?)
            };
            let image = none_if_blank(
                rules
                    .eval_field_rule(
                        &self.source.rule_image,
                        &item,
                        &response.body,
                        &response.url,
                        "rss.ruleImage",
                        key,
                        page,
                    )
                    .unwrap_or_default(),
            )
            .map(|raw| absolutize(&self.source.source_url, &raw).unwrap_or(raw));
            let raw_link = rules.eval_field_rule(
                &self.source.rule_link,
                &item,
                &response.body,
                &response.url,
                "rss.ruleLink",
                key,
                page,
            )?;
            let link = absolutize(&response.url, &raw_link)?;
            articles.push(RssArticle {
                origin: self.source.source_url.clone(),
                sort: sort_name.to_string(),
                title,
                order: index as i64,
                link,
                pub_date,
                description,
                image,
                group: "默认分组".to_string(),
                item_type: self.source.item_type,
                ..RssArticle::default()
            });
        }
        if reverse {
            articles.reverse();
        }
        Ok((articles, next_url))
    }

    fn seed_sort_url_scope_for_generated_url(
        &mut self,
        js: &mut JsRuntime,
        sort_url: &str,
    ) -> Result<()> {
        let raw_rule = self.source.sort_url.trim();
        if raw_rule.is_empty() || !is_js_rule(raw_rule) || !sort_url.contains("{{") {
            return Ok(());
        }
        let script = strip_wrapped_js(raw_rule);
        js.eval_rule_script(
            script,
            "rss.sortUrl.scopeBootstrap",
            "",
            &self.source.source_url,
            "",
            1,
        )
        .map(|_| {
            self.session = js.session();
        })
        .map_err(|err| {
            if err
                .to_string()
                .contains("__LEGADO_UNSUPPORTED_PLATFORM_API__")
            {
                self.diag(
                    DiagnosticKind::UnsupportedPlatformApi,
                    "RSS sortUrl scope bootstrap requires Android platform UI boundary",
                )
                .with_rule_path("rss.sortUrl.scopeBootstrap")
                .with_script(script)
            } else {
                err
            }
        })
    }

    pub fn persisted_session_snapshot(&self) -> AnalyzerSessionSnapshot {
        persist_session(&self.source_key, &self.session);
        self.session.clone().into()
    }

    fn diag(&self, kind: DiagnosticKind, message: impl Into<String>) -> Diagnostic {
        Diagnostic::new(kind, message)
            .with_source(self.source.source_name.clone())
            .with_base_url(self.source.source_url.clone())
    }
}

fn parse_default_rss(sort_name: &str, body: &str, source_url: &str) -> Vec<RssArticle> {
    let doc = scraper::Html::parse_document(body);
    let selector = scraper::Selector::parse("item").ok();
    let mut out = Vec::new();
    if let Some(selector) = selector {
        for (index, item) in doc.select(&selector).enumerate() {
            let html = item.html();
            let title = crate::rule_engine::extract_html_rule_from_str(&html, "title@text")
                .unwrap_or_default();
            if title.trim().is_empty() {
                continue;
            }
            let link = crate::rule_engine::extract_html_rule_from_str(&html, "link@text")
                .unwrap_or_default();
            let description = none_if_blank(
                crate::rule_engine::extract_html_rule_from_str(&html, "description@text")
                    .unwrap_or_default(),
            );
            let content = none_if_blank(
                crate::rule_engine::extract_html_rule_from_str(&html, "content|encoded@text")
                    .unwrap_or_default(),
            );
            let image = extract_first_img(description.as_deref().unwrap_or(""));
            out.push(RssArticle {
                origin: source_url.to_string(),
                sort: sort_name.to_string(),
                title,
                order: index as i64,
                link,
                pub_date: none_if_blank(
                    crate::rule_engine::extract_html_rule_from_str(&html, "pubDate@text")
                        .unwrap_or_default(),
                ),
                description,
                content,
                image,
                group: "默认分组".to_string(),
                ..RssArticle::default()
            });
        }
    }
    out
}

fn strip_wrapped_js(rule: &str) -> &str {
    let trimmed = rule.trim();
    if let Some(script) = trimmed.strip_prefix("@js:") {
        return script;
    }
    if trimmed.starts_with("<js>") {
        return trimmed
            .strip_prefix("<js>")
            .and_then(|script| script.rsplit_once("</js>").map(|(script, _)| script))
            .unwrap_or(trimmed);
    }
    trimmed
}

fn extract_first_img(input: &str) -> Option<String> {
    first_img_re()
        .captures(input)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().trim().to_string()))
}

fn rss_sort_splitter_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(&&|\n)+").expect("valid RSS sort splitter"))
}

fn first_img_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"<img [^>]*src\s*=\s*["']([^"']+)"#).expect("valid first image regex")
    })
}

fn none_if_blank(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn session_user_messages(session: &AnalyzerSession) -> Option<String> {
    let mut messages = Vec::new();
    messages.extend(
        session
            .logs
            .iter()
            .filter(|value| !value.trim().is_empty())
            .cloned(),
    );
    messages.extend(
        session
            .toasts
            .iter()
            .filter(|value| !value.trim().is_empty())
            .cloned(),
    );
    if messages.is_empty() {
        None
    } else {
        Some(messages.join("\n").chars().take(500).collect())
    }
}

fn excerpt(value: &str, limit: usize) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= limit {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

fn unsupported_platform_api_in(text: &str) -> Option<&'static str> {
    [
        "java.startBrowserAwait",
        "java.startBrowser",
        "java.showBrowser",
        "java.openVideoPlayer",
        "__LEGADO_UNSUPPORTED_PLATFORM_API__",
    ]
    .into_iter()
    .find(|api| text.contains(api))
}

fn apply_rss_url_option_js(
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
                    format!("request options JSON must be an object; rawUrl={url}"),
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

fn absolutize(base: &str, raw: &str) -> Result<String> {
    let raw = raw.trim();
    let (raw_url, options) = split_legado_url_options(raw);
    if raw_url.is_empty() || raw_url.starts_with("data:") || Url::parse(&raw_url).is_ok() {
        return rebuild_legado_url_with_optional_options(raw_url, options);
    }
    let base = Url::parse(base).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!("invalid base URL {base}: {err}; raw URL after rule evaluation was `{raw}`"),
        )
    })?;
    let joined = base.join(&raw_url).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!("invalid relative URL {raw_url}: {err}"),
        )
    })?;
    rebuild_legado_url_with_optional_options(joined.to_string(), options)
}

fn rebuild_legado_url_with_optional_options(
    url: String,
    options: Option<String>,
) -> Result<String> {
    if let Some(options) = options {
        Ok(format!("{url},{options}"))
    } else {
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformHost;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::rc::Rc;
    use std::thread;

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
        let Some(header_end) = header_end else {
            return String::from_utf8_lossy(&buffer).into_owned();
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end + 4]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
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
        String::from_utf8_lossy(&buffer).into_owned()
    }

    #[test]
    fn rss_sort_urls_evaluates_js_rule() {
        let source = RssSource {
            source_name: "RSS JS Sort".to_string(),
            source_url: "https://example.test/".to_string(),
            sort_url: "<js>'动画::https://example.test/a&&漫画::https://example.test/b'</js>"
                .to_string(),
            ..RssSource::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();

        let sorts = analyzer.sort_urls().unwrap();

        assert_eq!(
            sorts,
            vec![
                ("动画".to_string(), "https://example.test/a".to_string()),
                ("漫画".to_string(), "https://example.test/b".to_string())
            ]
        );
    }

    #[test]
    fn rss_sort_urls_fail_fast_without_platform_host() {
        let source = RssSource {
            source_name: "RSS Platform Sort".to_string(),
            source_url: "https://example.test/".to_string(),
            sort_url: "<js>java.webView('<html></html>', 'https://example.test', '')</js>"
                .to_string(),
            ..RssSource::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();

        let err = analyzer.sort_urls().unwrap_err().to_string();

        assert!(err.contains("UnsupportedPlatformApi"), "{err}");
        assert!(err.contains("rss.sortUrl"), "{err}");
        assert!(err.contains("webView"), "{err}");
    }

    #[test]
    fn rss_sort_urls_uses_platform_host_response() {
        struct SortPlatformHost;

        impl PlatformHost for SortPlatformHost {
            fn handle_platform_action(
                &self,
                api: &str,
                _source_name: &str,
                _args_json: &str,
            ) -> String {
                assert_eq!(api, "webView");
                serde_json::json!({
                    "url": "https://example.test/",
                    "body": "动画::https://example.test/a\n漫画::https://example.test/b",
                    "code": 200,
                    "message": "OK"
                })
                .to_string()
            }
        }

        let source = RssSource {
            source_name: "RSS Platform Sort".to_string(),
            source_url: "https://example.test/".to_string(),
            sort_url: "<js>java.webView('<html></html>', 'https://example.test', '')</js>"
                .to_string(),
            ..RssSource::default()
        };
        let mut analyzer = RssAnalyzer::new_with_platform(
            source,
            AnalyzerSession::default(),
            Some(Rc::new(SortPlatformHost)),
        )
        .unwrap();

        let sorts = analyzer.sort_urls().unwrap();

        assert_eq!(
            sorts,
            vec![
                ("动画".to_string(), "https://example.test/a".to_string()),
                ("漫画".to_string(), "https://example.test/b".to_string())
            ]
        );
    }

    #[test]
    fn rss_articles_bootstraps_sort_url_helpers_for_generated_category_url() {
        let source = RssSource {
            source_name: "RSS Generated Sort URL".to_string(),
            source_url: "https://example.test/".to_string(),
            sort_url: r#"<js>
                function get(tag, num) {
                    var region = ["*", "cn"];
                    return eval(tag + "[" + num + "]");
                }
                "全部::data:application/json,%7B%22items%22%3A%5B%7B%22name%22%3A%22A%22%7D%5D%7D,{\"headers\":{\"X-Region\":\"{{get('region',1)}}\"}}"
            </js>"#
            .to_string(),
            rule_articles: "$.items".to_string(),
            rule_title: "$.name".to_string(),
            rule_link: r#"<js>"https://example.test/" + result.name</js>"#.to_string(),
            ..RssSource::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();
        let sort_url = analyzer.sort_urls().unwrap().remove(0).1;

        let output = analyzer.articles("全部", &sort_url, "", 1).unwrap();

        assert_eq!(output.articles.len(), 1);
        assert_eq!(output.articles[0].title, "A");
    }

    #[test]
    fn rss_articles_apply_analyze_url_options_before_request_and_rules() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /signed HTTP/1.1"), "{request}");
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("X-Source: 1")),
                "{request}"
            );
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("X-Option: 1")),
                "{request}"
            );
            assert!(request.ends_with("q=1"), "{request}");
            let body = r#"{"items":[{"name":"Raw"}]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let option_json = serde_json::json!({
            "js": "result.replace('start', 'signed')",
            "bodyJs": "JSON.stringify(result).replace('Raw', 'Final')",
            "method": "POST",
            "body": "q=1",
            "headers": {
                "X-Option": "1"
            }
        })
        .to_string();
        let source = RssSource {
            source_name: "RSS URL Options".to_string(),
            source_url: format!("{base}/"),
            header: r#"{"X-Source":"1"}"#.to_string(),
            rule_articles: "$.items".to_string(),
            rule_title: "$.name".to_string(),
            rule_link: r#"<js>"https://example.test/" + result.name</js>"#.to_string(),
            ..RssSource::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .articles("全部", &format!("{base}/start,{option_json}"), "", 1)
            .unwrap();

        assert_eq!(output.articles.len(), 1);
        assert_eq!(output.articles[0].title, "Final");
        handle.join().unwrap();
    }

    #[test]
    fn rss_content_preserves_rule_html_for_webview_reader() {
        let source = RssSource {
            source_name: "RSS HTML Content".to_string(),
            source_url: "https://example.test/".to_string(),
            rule_content: r#"<js>"<!DOCTYPE html><html><body><div class=\"video-container\"><video></video></div></body></html>"</js>"#
                .to_string(),
            ..RssSource::default()
        };
        let article = RssArticle {
            origin: source.source_url.clone(),
            link: "data:text/html,ok".to_string(),
            title: "Video".to_string(),
            ..RssArticle::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer.content(article).unwrap();
        let content = output.content.unwrap();

        assert!(content.contains("<video"), "{content}");
        assert!(content.contains("video-container"), "{content}");
        assert!(content.contains("<!DOCTYPE html>"), "{content}");
    }

    #[test]
    fn rss_content_accepts_call_site_rule_override_like_android_debug_path() {
        let source = RssSource {
            source_name: "RSS Override Content".to_string(),
            source_url: "https://example.test/".to_string(),
            rule_content: r#"<js>"source-rule"</js>"#.to_string(),
            ..RssSource::default()
        };
        let article = RssArticle {
            origin: source.source_url.clone(),
            link: "data:text/html,%3Chtml%3E%3Cbody%3E%3Ch1%3EOverride%3C%2Fh1%3E%3C%2Fbody%3E%3C%2Fhtml%3E"
                .to_string(),
            title: "Override".to_string(),
            ..RssArticle::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer
            .content_with_rule(article, "<js>'override:' + java.getString('h1@text')</js>")
            .unwrap();

        assert_eq!(output.content.as_deref(), Some("override:Override"));
    }

    #[test]
    fn rss_content_exposes_rss_article_binding_like_original_analyze_rule() {
        let source = RssSource {
            source_name: "RSS Article Binding".to_string(),
            source_url: "https://example.test/feed".to_string(),
            rule_content: concat!(
                r#"<js>rssArticle.title + "|" + "#,
                r#"rssArticle.origin + "|" + "#,
                r#"rssArticle.variable + "|" + "#,
                r#"java.getString("h1@text")</js>"#
            )
            .to_string(),
            ..RssSource::default()
        };
        let article = RssArticle {
            origin: source.source_url.clone(),
            link: "data:text/html,%3Chtml%3E%3Cbody%3E%3Ch1%3EBound%3C%2Fh1%3E%3C%2Fbody%3E%3C%2Fhtml%3E"
                .to_string(),
            title: "Article".to_string(),
            variable: Some("state".to_string()),
            ..RssArticle::default()
        };
        let mut analyzer = RssAnalyzer::new(source, AnalyzerSession::default()).unwrap();

        let output = analyzer.content(article).unwrap();

        assert_eq!(
            output.content.as_deref(),
            Some("Article|https://example.test/feed|state|Bound")
        );
    }
}
