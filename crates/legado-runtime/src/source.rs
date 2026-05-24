use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BookSource {
    #[serde(default, alias = "sourceName", alias = "name")]
    pub book_source_name: String,
    #[serde(default, alias = "sourceUrl", alias = "url")]
    pub book_source_url: String,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub concurrent_rate: String,
    #[serde(default)]
    pub search_url: String,
    #[serde(default)]
    pub explore_url: String,
    #[serde(default)]
    pub js_lib: String,
    #[serde(default)]
    pub login_url: String,
    #[serde(default)]
    pub login_check_js: String,
    #[serde(default)]
    pub rule_search: SearchRule,
    #[serde(default)]
    pub rule_explore: SearchRule,
    #[serde(default)]
    pub rule_book_info: BookInfoRule,
    #[serde(default)]
    pub rule_toc: TocRule,
    #[serde(default, deserialize_with = "deserialize_content_rule")]
    pub rule_content: ContentRule,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRule {
    #[serde(default)]
    pub book_list: String,
    #[serde(default)]
    pub book_url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default, alias = "cover")]
    pub cover_url: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub intro: String,
    #[serde(default)]
    pub last_chapter: String,
    #[serde(default)]
    pub word_count: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BookInfoRule {
    #[serde(default)]
    pub init: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub author: String,
    #[serde(default, alias = "cover")]
    pub cover_url: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub intro: String,
    #[serde(default)]
    pub toc_url: String,
    #[serde(default)]
    pub last_chapter: String,
    #[serde(default)]
    pub word_count: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TocRule {
    #[serde(default)]
    pub pre_update_js: String,
    #[serde(default)]
    pub chapter_list: String,
    #[serde(default)]
    pub chapter_name: String,
    #[serde(default)]
    pub chapter_url: String,
    #[serde(default)]
    pub update_time: String,
    #[serde(default)]
    pub is_vip: String,
    #[serde(default)]
    pub is_pay: String,
    #[serde(default)]
    pub is_volume: String,
    #[serde(default)]
    pub next_toc_url: String,
    #[serde(default)]
    pub format_js: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentRule {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub sub_content: String,
    #[serde(default)]
    pub replace_regex: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub next_content_url: String,
    #[serde(default)]
    pub web_js: String,
    #[serde(default)]
    pub source_regex: String,
}

fn deserialize_content_rule<'de, D>(deserializer: D) -> std::result::Result<ContentRule, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if value.is_string() || value.is_null() {
        return Ok(ContentRule::default());
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

impl BookSource {
    pub fn parse_many(input: &str) -> Result<Vec<Self>> {
        let value: serde_json::Value = serde_json::from_str(input).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::SourceParse,
                format!("failed to parse source JSON: {err}"),
            )
        })?;
        match value {
            serde_json::Value::Array(_) => serde_json::from_value(value).map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::SourceParse,
                    format!("failed to parse source JSON: {err}"),
                )
            }),
            serde_json::Value::Object(_) => serde_json::from_value(value)
                .map(|source| vec![source])
                .map_err(|err| {
                    Diagnostic::new(
                        DiagnosticKind::SourceParse,
                        format!("failed to parse source JSON: {err}"),
                    )
                }),
            other => Err(Diagnostic::new(
                DiagnosticKind::SourceParse,
                format!(
                    "source JSON must be an object or array, got {}",
                    json_type_name(&other)
                ),
            )),
        }
    }

    pub fn parse_first(input: &str) -> Result<Self> {
        let mut sources = Self::parse_many(input)?;
        sources.pop().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::SourceParse,
                "source JSON did not contain any source",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BookSource;

    #[test]
    fn parses_rss_style_source_aliases_for_eval_context() {
        let source = BookSource::parse_first(
            r#"[{
                "sourceName": "RSS",
                "sourceUrl": "https://rss.example",
                "ruleContent": "<js>result</js>",
                "variableComment": "encrypted"
            }]"#,
        )
        .unwrap();

        assert_eq!(source.book_source_name, "RSS");
        assert_eq!(source.book_source_url, "https://rss.example");
        assert_eq!(source.rule_content.content, "");
        assert_eq!(source.extra["variableComment"].as_str(), Some("encrypted"));
    }

    #[test]
    fn parses_http_tts_style_source_aliases() {
        let source = BookSource::parse_first(
            r#"{
                "name": "TTS",
                "url": "https://tts.example/api",
                "loginCheckJs": "result"
            }"#,
        )
        .unwrap();

        assert_eq!(source.book_source_name, "TTS");
        assert_eq!(source.book_source_url, "https://tts.example/api");
        assert_eq!(source.login_check_js, "result");
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
