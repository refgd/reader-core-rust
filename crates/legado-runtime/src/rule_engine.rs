use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use serde_json::Value;

use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};
use crate::js_runtime::JsRuntime;

#[derive(Debug, Clone)]
pub enum RuleContent {
    Json(Value),
    HtmlDocument(String),
    HtmlNode(String),
}

impl RuleContent {
    pub fn from_body(body: &str) -> Self {
        serde_json::from_str(body)
            .map(Self::Json)
            .unwrap_or_else(|_| Self::HtmlDocument(body.to_string()))
    }

    fn raw_for_js(&self, fallback: &str) -> String {
        match self {
            Self::Json(value) => {
                serde_json::to_string(value).unwrap_or_else(|_| fallback.to_string())
            }
            Self::HtmlDocument(html) | Self::HtmlNode(html) => html.clone(),
        }
    }

    pub(crate) fn as_json(&self) -> Option<&Value> {
        match self {
            Self::Json(value) => Some(value),
            Self::HtmlDocument(_) | Self::HtmlNode(_) => None,
        }
    }

    fn html(&self) -> Option<&str> {
        match self {
            Self::HtmlDocument(html) | Self::HtmlNode(html) => Some(html.as_str()),
            Self::Json(_) => None,
        }
    }
}

pub struct RuleEngine<'a> {
    js: &'a mut JsRuntime,
    selector_cache: HashMap<String, Selector>,
    field_rule_cache: HashMap<String, ParsedFieldRule>,
    replacement_regex_cache: HashMap<String, Regex>,
}

impl<'a> RuleEngine<'a> {
    pub fn new(js: &'a mut JsRuntime) -> Self {
        Self {
            js,
            selector_cache: HashMap::new(),
            field_rule_cache: HashMap::new(),
            replacement_regex_cache: HashMap::new(),
        }
    }

    pub fn eval_url_rule(
        &mut self,
        rule: &str,
        key: &str,
        page: i32,
        base_url: &str,
    ) -> Result<String> {
        self.eval_url_rule_with_bindings(rule, key, page, base_url, "")
    }

    pub fn eval_url_rule_with_bindings(
        &mut self,
        rule: &str,
        key: &str,
        page: i32,
        base_url: &str,
        bindings_json: &str,
    ) -> Result<String> {
        let rule = rule.trim();
        let mut out = if rule.contains("@js:") || rule.contains("<js>") {
            self.eval_url_js_segments(rule, key, page, base_url, bindings_json)?
        } else if is_js_rule(rule) {
            return self.js.eval_rule_script_with_bindings(
                rule,
                "searchUrl",
                "",
                base_url,
                key,
                page,
                bindings_json,
            );
        } else {
            rule.to_string()
        };
        if out.contains("{{") {
            out = self.apply_template_with_bindings(
                &out,
                &RuleContent::Json(Value::Null),
                "",
                base_url,
                "url",
                key,
                page,
                bindings_json,
            )?;
        }
        out = replace_url_page_list_rules(&out, page);
        Ok(out
            .replace("{{key}}", key)
            .replace("{{page}}", &page.to_string())
            .replace("{key}", key)
            .replace("{page}", &page.to_string()))
    }

    fn eval_url_js_segments(
        &mut self,
        rule: &str,
        key: &str,
        page: i32,
        base_url: &str,
        bindings_json: &str,
    ) -> Result<String> {
        let mut start = 0;
        let mut result = rule.to_string();
        for caps in url_js_segment_re().captures_iter(rule) {
            let mat = caps.get(0).expect("capture");
            if mat.start() > start {
                let segment = rule[start..mat.start()].trim();
                if !segment.is_empty() {
                    result = segment.replace("@result", &result);
                }
            }
            let script = caps
                .get(2)
                .or_else(|| caps.get(1))
                .map(|m| m.as_str())
                .unwrap_or_default();
            result = self.js.eval_rule_script_with_bindings(
                script,
                "url",
                &result,
                base_url,
                key,
                page,
                bindings_json,
            )?;
            start = mat.end();
        }
        if rule.len() > start {
            let segment = rule[start..].trim();
            if !segment.is_empty() {
                result = segment.replace("@result", &result);
            }
        }
        Ok(result)
    }

    pub fn eval_field_rule(
        &mut self,
        rule: &str,
        value: &RuleContent,
        raw_result: &str,
        base_url: &str,
        rule_path: &str,
        key: &str,
        page: i32,
    ) -> Result<String> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(String::new());
        }
        if has_mixed_js_chain(rule) {
            return self
                .eval_mixed_js_chain(rule, value, raw_result, base_url, rule_path, key, page);
        }
        if is_js_rule(rule) {
            let rule =
                self.apply_template(rule, value, raw_result, base_url, rule_path, key, page)?;
            let current_result =
                if raw_result.starts_with(crate::js_runtime::FORCED_STRING_RESULT_PREFIX) {
                    raw_result.to_string()
                } else {
                    value.raw_for_js(raw_result)
                };
            return self.js.eval_rule_script(
                &rule,
                rule_path,
                &current_result,
                base_url,
                key,
                page,
            );
        }
        let had_template = rule.contains("{{");
        let templated =
            self.apply_template(rule, value, raw_result, base_url, rule_path, key, page)?;
        let parsed = self.parsed_field_rule(&templated);
        let field_rule = parsed.field_rule.trim();
        let mut out = if field_rule.trim().is_empty() {
            value_to_string_content(value)
        } else if had_template && !is_embedded_rule(field_rule.trim()) {
            field_rule.to_string()
        } else {
            match classify_rule_mode(field_rule) {
                RuleMode::Json(rule) => {
                    extract_rule_content_path(value, rule_path, field_rule, rule)?
                }
                RuleMode::Html(rule) => self
                    .extract_html_field(value, rule, raw_result, base_url, rule_path, key, page)?,
                RuleMode::Default(rule) => {
                    if value.html().is_some() {
                        self.extract_html_field(
                            value, rule, raw_result, base_url, rule_path, key, page,
                        )?
                    } else {
                        let Some(json) = value.as_json() else {
                            return Ok(String::new());
                        };
                        extract_path_to_string(json, rule)?
                    }
                }
            }
        };
        for replacement in parsed.replacements {
            let regex = self.replacement_regex(&replacement.from)?;
            out = if replacement.replace_first {
                regex
                    .find(&out)
                    .map(|mat| {
                        regex
                            .replace(&out[mat.start()..mat.end()], replacement.to.as_str())
                            .into_owned()
                    })
                    .unwrap_or_default()
            } else {
                regex
                    .replace_all(&out, replacement.to.as_str())
                    .into_owned()
            };
        }
        for (key, value_rule) in parsed.put_rules {
            let value = if value_rule.trim().is_empty() {
                String::new()
            } else {
                self.eval_field_rule(
                    &value_rule,
                    value,
                    raw_result,
                    base_url,
                    rule_path,
                    &key,
                    page,
                )?
            };
            self.js.put_java_store(key, value);
        }
        Ok(out)
    }

    pub fn select_list(
        &mut self,
        rule: &str,
        value: &RuleContent,
        raw: &str,
        base_url: &str,
        rule_path: &str,
    ) -> Result<Vec<RuleContent>> {
        let rule = rule.trim();
        if rule.is_empty() {
            return Ok(vec![value.clone()]);
        }
        if has_mixed_js_chain(rule) {
            return self.eval_mixed_js_list_chain(rule, value, raw, base_url, rule_path);
        }
        if is_js_rule(rule) {
            let raw_result = format!("{}{}", crate::js_runtime::FORCED_STRING_RESULT_PREFIX, raw);
            let out = self
                .js
                .eval_rule_script(rule, rule_path, &raw_result, base_url, "", 1)?;
            let parsed = parse_js_json_value_output(&out);
            return value_as_list(&parsed)
                .map(|items| items.into_iter().map(RuleContent::Json).collect());
        }
        match classify_rule_mode(rule) {
            RuleMode::Json(rule) => {
                let json = json_value_for_rule(value, rule_path, rule)?;
                let extracted =
                    extract_value_path(&json, rule).or_else(empty_json_array_on_no_match)?;
                value_as_list(&extracted)
                    .map(|items| items.into_iter().map(RuleContent::Json).collect())
            }
            RuleMode::Html(rule) => self.select_html_list(value, rule),
            RuleMode::Default(rule) => {
                if value.html().is_some() {
                    return self.select_html_list(value, rule);
                }
                let Some(json) = value.as_json() else {
                    return Ok(Vec::new());
                };
                let extracted =
                    extract_value_path(json, rule).or_else(empty_json_array_on_no_match)?;
                value_as_list(&extracted)
                    .map(|items| items.into_iter().map(RuleContent::Json).collect())
            }
        }
    }

    fn eval_mixed_js_list_chain(
        &mut self,
        rule: &str,
        value: &RuleContent,
        raw_result: &str,
        base_url: &str,
        rule_path: &str,
    ) -> Result<Vec<RuleContent>> {
        let mut current = ChainValue::Single(value.clone());
        let mut rest = rule;
        while let Some(start) = rest.find("<js>") {
            let prefix = rest[..start].trim();
            if !prefix.is_empty() {
                current = select_chain_value(current, prefix)?;
            }
            let after_start = start + "<js>".len();
            let Some(end) = rest[after_start..].find("</js>") else {
                return Err(Diagnostic::new(
                    DiagnosticKind::RuleParse,
                    format!("unterminated <js> rule in {rule_path}"),
                ));
            };
            let js_end = after_start + end;
            let result = current.to_js_result(raw_result);
            let out = self.js.eval_rule_script(
                &rest[after_start..js_end],
                rule_path,
                &result,
                base_url,
                "",
                1,
            )?;
            current = ChainValue::Single(RuleContent::from_body(&out));
            rest = &rest[js_end + "</js>".len()..];
        }
        let trailing = rest.trim();
        if !trailing.is_empty() {
            current = select_chain_value(current, trailing)?;
        }
        Ok(current.into_vec())
    }

    fn eval_mixed_js_chain(
        &mut self,
        rule: &str,
        value: &RuleContent,
        raw_result: &str,
        base_url: &str,
        rule_path: &str,
        key: &str,
        page: i32,
    ) -> Result<String> {
        let mut out = String::new();
        let mut current_value = value.clone();
        let mut current_result_for_js = raw_result.to_string();
        let mut rest = rule;
        while let Some(start) = rest.find("<js>") {
            let prefix = rest[..start].trim();
            if !prefix.is_empty() {
                let extraction_value = mixed_segment_value(prefix, value, &current_value);
                out = self.eval_field_rule(
                    prefix,
                    extraction_value,
                    &current_result_for_js,
                    base_url,
                    rule_path,
                    key,
                    page,
                )?;
                current_value = RuleContent::Json(Value::String(out.clone()));
            }
            let after_start = start + "<js>".len();
            let Some(end) = rest[after_start..].find("</js>") else {
                return Err(Diagnostic::new(
                    DiagnosticKind::RuleParse,
                    format!("unterminated <js> rule in {rule_path}"),
                ));
            };
            let js_end = after_start + end;
            let script = &rest[after_start..js_end];
            let js_input = if out.is_empty() {
                if current_result_for_js.is_empty() {
                    value_to_string_content(&current_value)
                } else {
                    current_result_for_js.clone()
                }
            } else {
                format!("{}{}", crate::js_runtime::FORCED_STRING_RESULT_PREFIX, out)
            };
            out = self
                .js
                .eval_rule_script(script, rule_path, &js_input, base_url, key, page)?;
            current_value = RuleContent::from_body(&out);
            current_result_for_js =
                format!("{}{}", crate::js_runtime::FORCED_STRING_RESULT_PREFIX, out);
            rest = &rest[js_end + "</js>".len()..];
        }
        let trailing = rest.trim();
        if !trailing.is_empty() {
            let extraction_value = mixed_segment_value(trailing, value, &current_value);
            out = self.eval_field_rule(
                trailing,
                extraction_value,
                &current_result_for_js,
                base_url,
                rule_path,
                key,
                page,
            )?;
        }
        Ok(out)
    }

    fn apply_template(
        &mut self,
        rule: &str,
        value: &RuleContent,
        raw_result: &str,
        base_url: &str,
        rule_path: &str,
        key: &str,
        page: i32,
    ) -> Result<String> {
        self.apply_template_with_bindings(
            rule, value, raw_result, base_url, rule_path, key, page, "",
        )
    }

    fn apply_template_with_bindings(
        &mut self,
        rule: &str,
        value: &RuleContent,
        raw_result: &str,
        base_url: &str,
        rule_path: &str,
        key: &str,
        page: i32,
        bindings_json: &str,
    ) -> Result<String> {
        let mut out = String::new();
        let mut last = 0;
        for caps in template_re().captures_iter(rule) {
            let mat = caps.get(0).expect("capture");
            out.push_str(&rule[last..mat.start()]);
            let expr = caps.get(1).map(|m| m.as_str()).unwrap_or_default().trim();
            let replacement = if is_embedded_rule(expr) {
                self.eval_field_rule(expr, value, raw_result, base_url, rule_path, key, page)?
            } else {
                let current_result =
                    if raw_result.starts_with(crate::js_runtime::FORCED_STRING_RESULT_PREFIX) {
                        raw_result.to_string()
                    } else {
                        value.raw_for_js(raw_result)
                    };
                self.js.eval_rule_script_with_bindings(
                    expr,
                    rule_path,
                    &current_result,
                    base_url,
                    key,
                    page,
                    bindings_json,
                )?
            };
            out.push_str(&replacement);
            last = mat.end();
        }
        out.push_str(&rule[last..]);
        Ok(out)
    }

    fn extract_html_field(
        &mut self,
        value: &RuleContent,
        rule: &str,
        raw_result: &str,
        base_url: &str,
        rule_path: &str,
        key: &str,
        page: i32,
    ) -> Result<String> {
        let mut current = if rule.contains("&&") {
            let values = split_balanced(rule, "&&")
                .into_iter()
                .filter_map(|part| self.extract_html_rule(value, part.trim()).ok())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            values.join("\n")
        } else if rule.contains("||") {
            let mut out = String::new();
            for part in split_balanced(rule, "||") {
                let extracted = self.extract_html_rule(value, part.trim())?;
                if !extracted.is_empty() {
                    out = extracted;
                    break;
                }
            }
            out
        } else {
            self.extract_html_rule(value, rule)?
        };

        if let Some((prefix, script)) = split_html_js(rule) {
            current = self.extract_html_rule(value, prefix.trim())?;
            current = self.js.eval_rule_script(
                script.trim_start_matches("js:"),
                rule_path,
                &current,
                base_url,
                key,
                page,
            )?;
        }

        if current.is_empty() && !raw_result.is_empty() && rule.trim().is_empty() {
            current = raw_result.to_string();
        }
        Ok(current)
    }

    fn parsed_field_rule(&mut self, rule: &str) -> ParsedFieldRule {
        if let Some(parsed) = self.field_rule_cache.get(rule) {
            return parsed.clone();
        }
        let (without_put, put_rules) = split_put_rules(rule);
        let (field_rule, replacements) = split_replacements(&without_put);
        let parsed = ParsedFieldRule {
            field_rule: field_rule.trim().to_string(),
            replacements,
            put_rules,
        };
        self.field_rule_cache
            .insert(rule.to_string(), parsed.clone());
        parsed
    }

    fn replacement_regex(&mut self, pattern: &str) -> Result<Regex> {
        if let Some(regex) = self.replacement_regex_cache.get(pattern) {
            return Ok(regex.clone());
        }
        let regex = Regex::new(pattern).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::RuleParse,
                format!("invalid replacement regex {pattern}: {err}"),
            )
        })?;
        self.replacement_regex_cache
            .insert(pattern.to_string(), regex.clone());
        Ok(regex)
    }

    fn extract_html_rule(&mut self, value: &RuleContent, rule: &str) -> Result<String> {
        let html = value.html().unwrap_or_default();
        let document = Html::parse_fragment(html);
        let mut current = document.root_element().html();
        let parts = split_rule_at(rule);
        for (index, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if part.starts_with("js:") {
                break;
            }
            let is_last = index == parts.len() - 1
                || parts
                    .get(index + 1)
                    .is_some_and(|next| next.starts_with("js:"));
            if is_html_last_rule(part) && is_last {
                let fragment = Html::parse_fragment(&current);
                let values = html_fragment_elements(&fragment)
                    .into_iter()
                    .filter_map(|element| html_last_value(element, part))
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>();
                return Ok(values.join("\n"));
            }

            let fragment = Html::parse_fragment(&current);
            let nodes = self.select_elements(&fragment, normalize_html_selector(part).as_str())?;
            if nodes.is_empty() {
                return Ok(String::new());
            }
            if is_last {
                let values = nodes
                    .into_iter()
                    .filter_map(|element| html_last_value(element, "text"))
                    .filter(|value| !value.is_empty())
                    .collect::<Vec<_>>();
                return Ok(values.join("\n"));
            }
            current = nodes
                .into_iter()
                .map(|element| element.html())
                .collect::<Vec<_>>()
                .join("\n");
        }
        Ok(current)
    }

    fn select_html_list(&mut self, value: &RuleContent, rule: &str) -> Result<Vec<RuleContent>> {
        let html = value.html().unwrap_or_default();
        let values = self
            .select_html_chain(html, rule)?
            .into_iter()
            .map(RuleContent::HtmlNode)
            .collect::<Vec<_>>();
        Ok(values)
    }

    fn select_html_chain(&mut self, html: &str, rule: &str) -> Result<Vec<String>> {
        let mut current = html.to_string();
        let mut nodes = Vec::new();
        for part in split_rule_at(rule)
            .into_iter()
            .filter(|part| !part.trim().is_empty())
        {
            if matches!(part, "text" | "html" | "all" | "ownText" | "textNodes")
                || part.starts_with("js:")
            {
                break;
            }
            let document = Html::parse_fragment(&current);
            nodes = self
                .select_elements(&document, normalize_html_selector(part).as_str())?
                .into_iter()
                .map(|element| element.html())
                .collect::<Vec<_>>();
            current = nodes.join("\n");
        }
        if nodes.is_empty() && !rule.trim().is_empty() && !rule.contains('@') {
            let document = Html::parse_fragment(html);
            nodes = self
                .select_elements(&document, normalize_html_selector(rule).as_str())?
                .into_iter()
                .map(|element| element.html())
                .collect::<Vec<_>>();
        }
        Ok(nodes)
    }

    fn select_elements<'doc>(
        &mut self,
        document: &'doc Html,
        rule: &str,
    ) -> Result<Vec<ElementRef<'doc>>> {
        let (selector_rule, indexes) = split_selector_indexes(rule);
        let (selector_rule, contains_text) = split_contains_selector(selector_rule);
        let selector = self.selector_from_legacy(&selector_rule)?;
        let mut elements = document.select(&selector).collect::<Vec<_>>();
        if let Some(contains_text) = contains_text {
            elements.retain(|element| element.text().collect::<String>().contains(&contains_text));
        }
        if !indexes.is_empty() {
            let len = elements.len() as isize;
            elements = indexes
                .into_iter()
                .filter_map(|index| {
                    let index = if index < 0 { len + index } else { index };
                    if index >= 0 {
                        elements.get(index as usize).copied()
                    } else {
                        None
                    }
                })
                .collect();
        }
        Ok(elements)
    }

    fn selector_from_legacy(&mut self, rule: &str) -> Result<Selector> {
        let selector = legacy_selector_string(rule);
        if let Some(selector) = self.selector_cache.get(&selector) {
            return Ok(selector.clone());
        }
        let parsed = Selector::parse(&selector).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::RuleParse,
                format!("invalid CSS selector {selector}: {err:?}"),
            )
        })?;
        self.selector_cache.insert(selector, parsed.clone());
        Ok(parsed)
    }
}

fn parse_js_json_value_output(out: &str) -> Value {
    const JSON_VALUE_PREFIX: &str = "__LEGADO_JSON_VALUE__";
    let raw = out.strip_prefix(JSON_VALUE_PREFIX).unwrap_or(out);
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(out.to_string()))
}

pub fn is_js_rule(rule: &str) -> bool {
    let trimmed = rule.trim();
    trimmed.starts_with("@js:") || trimmed.starts_with("<js>")
}

fn has_mixed_js_chain(rule: &str) -> bool {
    let trimmed = rule.trim();
    if !trimmed.contains("<js>") {
        return false;
    }
    let Some(first) = trimmed.find("<js>") else {
        return false;
    };
    let Some(first_end) = trimmed[first + "<js>".len()..]
        .find("</js>")
        .map(|index| first + "<js>".len() + index + "</js>".len())
    else {
        return false;
    };
    first > 0 || first_end < trimmed.len()
}

#[derive(Debug, Clone)]
enum ChainValue {
    Single(RuleContent),
    List(Vec<RuleContent>),
}

impl ChainValue {
    fn to_js_result(&self, fallback: &str) -> String {
        match self {
            Self::Single(value) => value.raw_for_js(fallback),
            Self::List(values) => {
                let items = values
                    .iter()
                    .map(|value| value_to_string_content(value))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{items}]")
            }
        }
    }

    fn into_vec(self) -> Vec<RuleContent> {
        match self {
            Self::Single(value) => vec![value],
            Self::List(values) => values,
        }
    }
}

fn select_chain_value(current: ChainValue, rule: &str) -> Result<ChainValue> {
    let mut out = Vec::new();
    for value in current.into_vec() {
        if value.html().is_some() {
            out.extend(select_html_list(&value, rule)?);
        } else {
            let Some(json) = value.as_json() else {
                continue;
            };
            let extracted = extract_value_path(json, rule)?;
            out.extend(
                value_as_list(&extracted)?
                    .into_iter()
                    .map(RuleContent::Json),
            );
        }
    }
    Ok(ChainValue::List(out))
}

fn is_embedded_rule(rule: &str) -> bool {
    let trimmed = rule.trim();
    trimmed.starts_with('@')
        || trimmed.starts_with("$.")
        || trimmed.starts_with("$[")
        || trimmed.starts_with("//")
        || trimmed == "$"
}

fn mixed_segment_value<'a>(
    segment: &str,
    original: &'a RuleContent,
    current: &'a RuleContent,
) -> &'a RuleContent {
    if original.html().is_none() {
        return current;
    }
    if segment_prefers_original_html(segment) {
        original
    } else {
        current
    }
}

fn segment_prefers_original_html(segment: &str) -> bool {
    match classify_rule_mode(segment) {
        RuleMode::Html(_) => return true,
        RuleMode::Json(_) => return false,
        RuleMode::Default(_) => {}
    }
    let has_html_rule = template_re().captures_iter(segment).any(|caps| {
        caps.get(1)
            .map(|m| matches!(classify_rule_mode(m.as_str()), RuleMode::Html(_)))
            .unwrap_or(false)
    });
    has_html_rule
}

fn template_re() -> &'static Regex {
    static TEMPLATE_RE: OnceLock<Regex> = OnceLock::new();
    TEMPLATE_RE.get_or_init(|| Regex::new(r"\{\{(.*?)\}\}").expect("valid template regex"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMode<'a> {
    Json(&'a str),
    Html(&'a str),
    Default(&'a str),
}

fn classify_rule_mode(rule: &str) -> RuleMode<'_> {
    let trimmed = rule.trim();
    if let Some(rule) = trimmed.strip_prefix("@@") {
        return RuleMode::Html(rule.trim());
    }
    if let Some(rule) = strip_ascii_prefix(trimmed, "@CSS:") {
        return RuleMode::Html(rule.trim());
    }
    if let Some(rule) = strip_ascii_prefix(trimmed, "@XPath:") {
        return RuleMode::Html(rule.trim());
    }
    if let Some(rule) = strip_ascii_prefix(trimmed, "@Json:") {
        return RuleMode::Json(rule.trim());
    }
    if trimmed.starts_with("$.") || trimmed.starts_with("$[") || trimmed == "$" {
        return RuleMode::Json(trimmed);
    }
    RuleMode::Default(trimmed)
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &value[prefix.len()..])
}

fn json_value_for_rule(value: &RuleContent, rule_path: &str, rule: &str) -> Result<Value> {
    if let Some(json) = value.as_json() {
        return Ok(json.clone());
    }
    let raw = value_to_string_content(value);
    serde_json::from_str(&raw).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!(
                "{rule_path} requires JSONPath rule {rule}, but current result is not valid JSON: {err}"
            ),
        )
    })
}

fn extract_rule_content_path(
    value: &RuleContent,
    rule_path: &str,
    field_rule: &str,
    rule: &str,
) -> Result<String> {
    if let Some(json) = value.as_json() {
        return extract_path_to_string(json, rule).or_else(empty_string_on_json_no_match);
    }
    let raw = value_to_string_content(value);
    let json = serde_json::from_str(&raw).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!(
                "{rule_path} requires JSONPath rule {field_rule}, but current result is not valid JSON: {err}"
            ),
        )
    })?;
    extract_path_to_string(&json, rule).or_else(empty_string_on_json_no_match)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplacementRule {
    from: String,
    to: String,
    replace_first: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedFieldRule {
    field_rule: String,
    replacements: Vec<ReplacementRule>,
    put_rules: Vec<(String, String)>,
}

fn split_replacements(rule: &str) -> (&str, Vec<ReplacementRule>) {
    let mut parts = rule.split("##");
    let field = parts.next().unwrap_or_default();
    let rest = parts.collect::<Vec<_>>();
    let mut replacements = Vec::new();
    let mut index = 0;
    while index < rest.len() {
        let from = rest[index];
        let to = rest.get(index + 1).copied().unwrap_or_default();
        let replace_first = rest
            .get(index + 2)
            .is_some_and(|part| part.is_empty() || *part == "#");
        replacements.push(ReplacementRule {
            from: from.to_string(),
            to: to.to_string(),
            replace_first,
        });
        index += if replace_first { 3 } else { 2 };
    }
    (field, replacements)
}

fn replace_url_page_list_rules(input: &str, page: i32) -> String {
    let page_index = page.max(1) as usize;
    page_list_re()
        .replace_all(input, |caps: &regex::Captures<'_>| {
            let values = caps[1].split(',').map(str::trim).collect::<Vec<_>>();
            if values.is_empty() {
                String::new()
            } else {
                values
                    .get(page_index.saturating_sub(1))
                    .or_else(|| values.last())
                    .copied()
                    .unwrap_or_default()
                    .to_string()
            }
        })
        .into_owned()
}

fn select_html_list(value: &RuleContent, rule: &str) -> Result<Vec<RuleContent>> {
    let html = value.html().unwrap_or_default();
    let values = select_html_chain(html, rule)?
        .into_iter()
        .map(RuleContent::HtmlNode)
        .collect::<Vec<_>>();
    Ok(values)
}

fn select_html_chain(html: &str, rule: &str) -> Result<Vec<String>> {
    let mut current = html.to_string();
    let mut nodes = Vec::new();
    for part in split_rule_at(rule)
        .into_iter()
        .filter(|part| !part.trim().is_empty())
    {
        if matches!(part, "text" | "html" | "all" | "ownText" | "textNodes")
            || part.starts_with("js:")
        {
            break;
        }
        let document = Html::parse_fragment(&current);
        nodes = select_elements(&document, normalize_html_selector(part).as_str())?
            .into_iter()
            .map(|element| element.html())
            .collect::<Vec<_>>();
        current = nodes.join("\n");
    }
    if nodes.is_empty() && !rule.trim().is_empty() && !rule.contains('@') {
        let document = Html::parse_fragment(html);
        nodes = select_elements(&document, normalize_html_selector(rule).as_str())?
            .into_iter()
            .map(|element| element.html())
            .collect::<Vec<_>>();
    }
    Ok(nodes)
}

fn extract_html_rule(value: &RuleContent, rule: &str) -> Result<String> {
    let html = value.html().unwrap_or_default();
    let document = Html::parse_fragment(&html);
    let mut current = document.root_element().html();
    let parts = split_rule_at(rule);
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if part.starts_with("js:") {
            break;
        }
        let is_last = index == parts.len() - 1
            || parts
                .get(index + 1)
                .is_some_and(|next| next.starts_with("js:"));
        if is_html_last_rule(part) && is_last {
            let fragment = Html::parse_fragment(&current);
            let values = html_fragment_elements(&fragment)
                .into_iter()
                .filter_map(|element| html_last_value(element, part))
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            return Ok(values.join("\n"));
        }

        let fragment = Html::parse_fragment(&current);
        let nodes = select_elements(&fragment, normalize_html_selector(part).as_str())?;
        if nodes.is_empty() {
            return Ok(String::new());
        }
        if is_last {
            let values = nodes
                .into_iter()
                .filter_map(|element| html_last_value(element, "text"))
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            return Ok(values.join("\n"));
        }
        current = nodes
            .into_iter()
            .map(|element| element.html())
            .collect::<Vec<_>>()
            .join("\n");
    }
    Ok(current)
}

pub(crate) fn extract_html_rule_from_str(html: &str, rule: &str) -> Result<String> {
    extract_html_rule(&RuleContent::HtmlDocument(html.to_string()), rule)
}

pub(crate) fn select_html_nodes_from_str(html: &str, rule: &str) -> Result<Vec<String>> {
    select_html_chain(html, rule)
}

fn html_fragment_elements<'a>(fragment: &'a Html) -> Vec<ElementRef<'a>> {
    let children = fragment
        .root_element()
        .children()
        .filter_map(ElementRef::wrap)
        .collect::<Vec<_>>();
    if children.is_empty() {
        vec![fragment.root_element()]
    } else {
        children
    }
}

fn split_html_js(rule: &str) -> Option<(&str, &str)> {
    let index = rule.find("@js:")?;
    Some((&rule[..index], &rule[index + 1..]))
}

fn is_html_last_rule(rule: &str) -> bool {
    matches!(rule, "text" | "html" | "all" | "ownText" | "textNodes")
        || rule.starts_with("js:")
        || !looks_like_selector(rule)
}

fn html_last_value(element: ElementRef<'_>, rule: &str) -> Option<String> {
    match rule {
        "text" | "ownText" | "textNodes" => Some(
            element
                .text()
                .collect::<Vec<_>>()
                .join("")
                .trim()
                .to_string(),
        ),
        "html" | "all" => Some(element.inner_html()),
        attr => element.value().attr(attr).map(ToString::to_string),
    }
}

fn select_elements<'a>(document: &'a Html, rule: &str) -> Result<Vec<ElementRef<'a>>> {
    let (selector_rule, indexes) = split_selector_indexes(rule);
    let (selector_rule, contains_text) = split_contains_selector(selector_rule);
    let selector = selector_from_legacy(&selector_rule)?;
    let mut elements = document.select(&selector).collect::<Vec<_>>();
    if let Some(contains_text) = contains_text {
        elements.retain(|element| element.text().collect::<String>().contains(&contains_text));
    }
    if !indexes.is_empty() {
        let len = elements.len() as isize;
        elements = indexes
            .into_iter()
            .filter_map(|index| {
                let index = if index < 0 { len + index } else { index };
                if index >= 0 {
                    elements.get(index as usize).copied()
                } else {
                    None
                }
            })
            .collect();
    }
    Ok(elements)
}

fn normalize_html_selector(rule: &str) -> String {
    let rule = rule.trim().strip_prefix("css:").unwrap_or(rule.trim());
    xpath_to_css(rule).unwrap_or_else(|| rule.to_string())
}

fn xpath_to_css(rule: &str) -> Option<String> {
    if rule.starts_with('/') && !rule.starts_with("//") {
        let parts = rule
            .trim_start_matches('/')
            .split('/')
            .filter(|part| !part.is_empty())
            .map(xpath_step_to_css)
            .collect::<Option<Vec<_>>>()?;
        if !parts.is_empty() {
            let selector = parts.join(" > ");
            if parts.len() > 2
                && parts[0].eq_ignore_ascii_case("html")
                && parts[1].eq_ignore_ascii_case("body")
            {
                return Some(parts[2..].join(" > "));
            }
            return Some(selector);
        }
    }
    let rest = rule.strip_prefix("//")?;
    let children = rest.ends_with("/*");
    let rest = rest.strip_suffix("/*").unwrap_or(rest);
    let parts = rest
        .split('/')
        .filter(|part| !part.is_empty())
        .map(xpath_step_to_css)
        .collect::<Option<Vec<_>>>()?;
    if parts.is_empty() {
        return None;
    }
    let selector = parts.join(" ");
    Some(if children {
        format!("{selector} > *")
    } else {
        selector
    })
}

fn xpath_step_to_css(step: &str) -> Option<String> {
    if step == "*" {
        return Some("*".to_string());
    }
    let (tag, predicates) = if let Some(index) = step.find('[') {
        let tag = &step[..index];
        let predicates = step[index..]
            .split('[')
            .filter(|part| !part.is_empty())
            .map(|part| part.strip_suffix(']'))
            .collect();
        (tag, predicates)
    } else {
        (step, Vec::new())
    };
    if tag.is_empty()
        || !tag
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '*'))
    {
        return None;
    }
    let mut selector = tag.to_string();
    for predicate in predicates {
        let predicate = predicate?.trim();
        if predicate.eq_ignore_ascii_case("last()") {
            selector.push_str(".-1");
        } else if predicate.chars().all(|ch| ch.is_ascii_digit()) {
            let index = predicate.parse::<isize>().ok()?.saturating_sub(1);
            selector.push('.');
            selector.push_str(&index.to_string());
        } else if let Some(raw) = predicate.strip_prefix('@') {
            if let Some((attr, value)) = raw.split_once('=') {
                append_xpath_attr_selector(&mut selector, attr, value, false)?;
            } else {
                selector.push('[');
                selector.push_str(raw.trim());
                selector.push(']');
            }
        } else if let Some(inner) = predicate
            .strip_prefix("contains(")
            .and_then(|value| value.strip_suffix(')'))
        {
            let (target, value) = split_xpath_call_args(inner)?;
            let value = trim_xpath_literal(value);
            if target.trim() == "text()" || target.trim() == "." {
                selector.push_str(":contains(");
                selector.push_str(&css_escape_double_quoted(value));
                selector.push(')');
            } else if let Some(attr) = target.trim().strip_prefix('@') {
                append_xpath_attr_selector(&mut selector, attr, value, true)?;
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(selector)
}

fn append_xpath_attr_selector(
    selector: &mut String,
    attr: &str,
    value: &str,
    contains: bool,
) -> Option<()> {
    let attr = attr.trim();
    if attr.is_empty()
        || !attr
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '*'))
    {
        return None;
    }
    let value = trim_xpath_literal(value);
    if attr == "id" && !contains {
        selector.push('#');
        selector.push_str(value);
    } else if attr == "class" && !contains && !value.contains(char::is_whitespace) {
        selector.push('.');
        selector.push_str(value);
    } else {
        selector.push('[');
        selector.push_str(attr);
        if contains {
            selector.push_str("*=");
        } else {
            selector.push('=');
        }
        selector.push('"');
        selector.push_str(&css_escape_double_quoted(value));
        selector.push_str("\"]");
    }
    Some(())
}

fn split_xpath_call_args(input: &str) -> Option<(&str, &str)> {
    let (left, right) = input.split_once(',')?;
    Some((left.trim(), right.trim()))
}

fn trim_xpath_literal(input: &str) -> &str {
    input.trim().trim_matches('"').trim_matches('\'')
}

fn css_escape_double_quoted(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

fn selector_from_legacy(rule: &str) -> Result<Selector> {
    let selector = legacy_selector_string(rule);
    Selector::parse(&selector).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::RuleParse,
            format!("invalid CSS selector {selector}: {err:?}"),
        )
    })
}

fn legacy_selector_string(rule: &str) -> String {
    let (selector, _) = split_selector_indexes(rule.trim());
    if let Some(id) = selector.strip_prefix("id.") {
        format!("#{id}")
    } else if let Some(class) = selector.strip_prefix("class.") {
        format!(".{class}")
    } else if let Some(tag) = selector.strip_prefix("tag.") {
        tag.to_string()
    } else {
        selector.to_string()
    }
}

fn split_contains_selector(rule: &str) -> (String, Option<String>) {
    let Some(start) = rule.find(":contains(") else {
        return (rule.to_string(), None);
    };
    let value_start = start + ":contains(".len();
    let Some(end) = rule[value_start..]
        .find(')')
        .map(|offset| value_start + offset)
    else {
        return (rule.to_string(), None);
    };
    let mut selector = String::with_capacity(rule.len());
    selector.push_str(&rule[..start]);
    selector.push_str(&rule[end + 1..]);
    let text = rule[value_start..end]
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    (selector, Some(text))
}

fn split_selector_indexes(rule: &str) -> (&str, Vec<isize>) {
    let Some((prefix, suffix)) = rule.rsplit_once('.') else {
        return (rule, Vec::new());
    };
    if !suffix
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == ':' || ch == '-')
    {
        return (rule, Vec::new());
    }
    if let Some((start, end)) = suffix.split_once(':') {
        let start = start.parse::<isize>().unwrap_or(0);
        let end = end.parse::<isize>().unwrap_or(start);
        let indexes = if end >= start {
            (start..=end).collect()
        } else {
            (end..=start).rev().collect()
        };
        (prefix, indexes)
    } else {
        (
            prefix,
            suffix
                .parse::<isize>()
                .map(|index| vec![index])
                .unwrap_or_default(),
        )
    }
}

fn looks_like_selector(rule: &str) -> bool {
    rule.starts_with('.')
        || rule.starts_with('#')
        || rule.starts_with("id.")
        || rule.starts_with("class.")
        || rule.starts_with("tag.")
        || rule.contains('[')
        || rule.chars().any(|ch| ch == '.' || ch == '>' || ch == ' ')
}

fn split_balanced<'a>(input: &'a str, sep: &str) -> Vec<&'a str> {
    input.split(sep).collect()
}

fn split_rule_at(input: &str) -> Vec<&str> {
    let bytes = input.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut bracket_depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(current_quote) = quote {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == current_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'@' if bracket_depth == 0 => {
                parts.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    parts.push(&input[start..]);
    parts
}

fn split_put_rules(rule: &str) -> (String, Vec<(String, String)>) {
    let mut put_rules = Vec::new();
    for caps in put_rule_re().captures_iter(rule) {
        let Some(body) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for pair in body.split(',') {
            let Some((key, value)) = pair.split_once(':') else {
                continue;
            };
            put_rules.push((
                key.trim().trim_matches('"').trim_matches('\'').to_string(),
                value
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            ));
        }
    }
    (put_rule_re().replace_all(rule, "").into_owned(), put_rules)
}

fn url_js_segment_re() -> &'static Regex {
    static URL_JS_SEGMENT_RE: OnceLock<Regex> = OnceLock::new();
    URL_JS_SEGMENT_RE.get_or_init(|| {
        Regex::new(r"(?is)<js>(.*?)</js>|@js:([\w\W]*)").expect("valid url js regex")
    })
}

fn page_list_re() -> &'static Regex {
    static PAGE_LIST_RE: OnceLock<Regex> = OnceLock::new();
    PAGE_LIST_RE.get_or_init(|| Regex::new(r"<([^<>]*)>").expect("valid page-list regex"))
}

fn put_rule_re() -> &'static Regex {
    static PUT_RULE_RE: OnceLock<Regex> = OnceLock::new();
    PUT_RULE_RE.get_or_init(|| Regex::new(r"@put:\{([^}]*)\}").expect("valid put regex"))
}

pub fn extract_path(value: &Value, path: &str) -> Result<String> {
    extract_path_to_string(value, path)
}

fn extract_path_to_string(value: &Value, path: &str) -> Result<String> {
    let path = path.trim();
    if let Some(parts) = split_logical_paths(path, "||") {
        for part in parts {
            let value = extract_path_to_string(value, part.trim()).unwrap_or_default();
            if !value.is_empty() {
                return Ok(value);
            }
        }
        return Ok(String::new());
    }
    if let Some(parts) = split_logical_paths(path, "&&") {
        let values = parts
            .into_iter()
            .filter_map(|part| extract_path_to_string(value, part.trim()).ok())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        return Ok(values.join("\n"));
    }
    if !path.contains("[*]") {
        return extract_value_path_ref(value, path).map(value_to_string);
    }
    let value = extract_value_path(value, path)?;
    Ok(value_to_string(&value))
}

fn empty_string_on_json_no_match(err: Diagnostic) -> Result<String> {
    if is_json_no_match(&err) {
        Ok(String::new())
    } else {
        Err(err)
    }
}

fn empty_json_array_on_no_match(err: Diagnostic) -> Result<Value> {
    if is_json_no_match(&err) {
        Ok(Value::Array(Vec::new()))
    } else {
        Err(err)
    }
}

fn is_json_no_match(err: &Diagnostic) -> bool {
    err.kind == DiagnosticKind::Extraction
        && (err.message.starts_with("missing path segment ")
            || err.message.contains(" is not an array"))
}

fn extract_value_path_ref<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    let path = path.trim().trim_start_matches("$.").trim_start_matches('$');
    if path.is_empty() {
        return Ok(value);
    }
    let mut current = value;
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        current = current.get(segment).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::Extraction,
                format!("missing path segment {segment} in {path}"),
            )
        })?;
    }
    Ok(current)
}

pub fn extract_value_path(value: &Value, path: &str) -> Result<Value> {
    let path = path.trim().trim_start_matches("$.").trim_start_matches('$');
    if path.is_empty() {
        return Ok(value.clone());
    }
    let segments = path
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    extract_segments(value, &segments, path)
}

fn extract_segments(value: &Value, segments: &[&str], full_path: &str) -> Result<Value> {
    if segments.is_empty() {
        return Ok(value.clone());
    }

    let segment = segments[0];
    if let Value::Array(items) = value {
        let mut out = Vec::new();
        for item in items {
            match extract_segments(item, segments, full_path)? {
                Value::Array(values) => out.extend(values),
                value => out.push(value),
            }
        }
        return Ok(Value::Array(out));
    }

    if let Some(key) = segment.strip_suffix("[*]") {
        let array = value.get(key).and_then(Value::as_array).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::Extraction,
                format!("path segment {segment} is not an array"),
            )
        })?;
        let mut out = Vec::new();
        for item in array {
            match extract_segments(item, &segments[1..], full_path)? {
                Value::Array(values) => out.extend(values),
                value => out.push(value),
            }
        }
        return Ok(Value::Array(out));
    }

    let current = value.get(segment).ok_or_else(|| {
        Diagnostic::new(
            DiagnosticKind::Extraction,
            format!("missing path segment {segment} in {full_path}"),
        )
    })?;
    extract_segments(current, &segments[1..], full_path)
}

fn split_logical_paths<'a>(path: &'a str, sep: &str) -> Option<Vec<&'a str>> {
    if !path.contains(sep) {
        return None;
    }
    let parts = path.split(sep).collect::<Vec<_>>();
    if parts.len() > 1 {
        Some(parts)
    } else {
        None
    }
}

fn value_as_list(value: &Value) -> Result<Vec<Value>> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::Null => Ok(Vec::new()),
        other => Ok(vec![other.clone()]),
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .map(value_to_string)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn value_to_string_content(value: &RuleContent) -> String {
    match value {
        RuleContent::Json(value) => value_to_string(value),
        RuleContent::HtmlDocument(html) | RuleContent::HtmlNode(html) => html.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_json_path() {
        let value: Value = serde_json::json!({"data":{"books":[{"name":"abc"}]}});
        let books = extract_value_path(&value, "data.books").unwrap();
        assert_eq!(books.as_array().unwrap().len(), 1);
        assert_eq!(extract_path(&books[0], "name").unwrap(), "abc");
    }

    #[test]
    fn splits_put_rules() {
        let (rule, puts) = split_put_rules("title@put:{bid:id, cid:chapter.id}");
        assert_eq!(rule, "title");
        assert_eq!(
            puts,
            vec![
                ("bid".to_string(), "id".to_string()),
                ("cid".to_string(), "chapter.id".to_string())
            ]
        );
    }

    #[test]
    fn extracts_array_fields_and_logical_json_paths() {
        let value: Value = serde_json::json!({
            "tags":[{"title":"玄幻"},{"title":"连载"}],
            "words":"100万字",
            "empty":""
        });

        assert_eq!(
            extract_path(&value, "$.tags[*].title").unwrap(),
            "玄幻\n连载"
        );
        assert_eq!(
            extract_path(&value, "$.tags[*].title&&$.words").unwrap(),
            "玄幻\n连载\n100万字"
        );
        assert_eq!(extract_path(&value, "$.empty||$.words").unwrap(), "100万字");
    }

    #[test]
    fn json_path_no_match_matches_android_empty_result() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::Json(serde_json::json!({
            "book_name": "Book",
            "last_chapter_title": "Chapter 1"
        }));
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                "{{$.last_chapter_title}} • {{$.last_update_time}}",
                &value,
                "",
                "https://example.test",
                "ruleExplore.lastChapter",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "Chapter 1 •");
        assert!(engine
            .select_list(
                "$.data",
                &value,
                "",
                "https://example.test",
                "ruleExplore.bookList",
            )
            .expect("list")
            .is_empty());
    }

    #[test]
    fn html_selector_supports_jsoup_contains_filter() {
        let html = r#"
            <div class="detail-sider">
                <div>更新时间 2026</div>
                <div>更新状态 连载</div>
            </div>
        "#;

        let out = extract_html_rule_from_str(html, ".detail-sider div:contains(更新时间)@text")
            .expect("contains selector");

        assert_eq!(out, "更新时间 2026");
    }

    #[test]
    fn html_selector_accepts_explicit_css_prefix() {
        let html = r#"<div class="detail-sider"><div>更新状态 连载</div></div>"#;

        let out = extract_html_rule_from_str(html, "css:.detail-sider div:contains(更新状态)@text")
            .expect("css prefixed selector");

        assert_eq!(out, "更新状态 连载");
    }

    #[test]
    fn splits_replacement_with_empty_replacement() {
        let (rule, replacements) = split_replacements("$.statement##footer");
        assert_eq!(rule, "$.statement");
        assert_eq!(
            replacements,
            vec![ReplacementRule {
                from: "footer".to_string(),
                to: String::new(),
                replace_first: false,
            }]
        );
    }

    #[test]
    fn splits_replacement_with_first_match_marker() {
        let (rule, replacements) = split_replacements("$.statement##第\\d+章##$0###");
        assert_eq!(rule, "$.statement");
        assert_eq!(
            replacements,
            vec![ReplacementRule {
                from: "第\\d+章".to_string(),
                to: "$0".to_string(),
                replace_first: true,
            }]
        );
    }

    #[test]
    fn replacement_first_match_returns_only_first_replaced_match() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::Json(serde_json::json!({"title":"前言 第12章 正文 第13章 结尾"}));
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                "$.title##第\\d+章##命中###",
                &value,
                "",
                "https://example.test",
                "rule.test.replaceFirst",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "命中");
    }

    #[test]
    fn url_rule_replaces_page_lists_like_analyze_url() {
        assert_eq!(
            replace_url_page_list_rules("https://example.test/<a,b,c>?p=<1,2>", 2),
            "https://example.test/b?p=2"
        );
        assert_eq!(
            replace_url_page_list_rules("https://example.test/<a,b,c>", 9),
            "https://example.test/c"
        );
        assert_eq!(
            replace_url_page_list_rules("https://example.test/<a,b,c>", 0),
            "https://example.test/a"
        );
    }

    #[test]
    fn templated_literal_does_not_become_a_path() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::Json(serde_json::json!({"intro":"hello"}));
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                "prefix {{$.intro}} suffix",
                &value,
                "",
                "https://example.test",
                "ruleBookInfo.intro",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "prefix hello suffix");
    }

    #[test]
    fn xpath_rules_cover_common_predicates_and_paths() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::HtmlDocument(
            r#"
            <html><body>
              <main>
                <section class="list">
                  <a data-id="one">First</a>
                  <a data-id="two" href="/two">Second Link</a>
                  <a data-id="three">Third</a>
                </section>
                <p class="summary primary" data-kind="intro">Alpha summary</p>
              </main>
            </body></html>
            "#
            .to_string(),
        );
        let mut engine = RuleEngine::new(&mut runtime);

        let second = engine
            .eval_field_rule(
                "@XPath://section[@class='list']/a[2]",
                &value,
                "",
                "https://example.test",
                "xpath.second",
                "",
                1,
            )
            .expect("second");
        let last = engine
            .eval_field_rule(
                "@XPath://section[@class='list']/a[last()]",
                &value,
                "",
                "https://example.test",
                "xpath.last",
                "",
                1,
            )
            .expect("last");
        let contains_attr = engine
            .eval_field_rule(
                "@XPath://p[contains(@class,'primary')]",
                &value,
                "",
                "https://example.test",
                "xpath.containsAttr",
                "",
                1,
            )
            .expect("contains attr");
        let contains_text = engine
            .eval_field_rule(
                "@XPath://a[contains(text(),'Second')]",
                &value,
                "",
                "https://example.test",
                "xpath.containsText",
                "",
                1,
            )
            .expect("contains text");
        let absolute = engine
            .eval_field_rule(
                "/html/body/main/section/a[1]",
                &value,
                "",
                "https://example.test",
                "xpath.absolute",
                "",
                1,
            )
            .expect("absolute");
        let attr_exists = engine
            .eval_field_rule(
                "@XPath://a[@href]",
                &value,
                "",
                "https://example.test",
                "xpath.attrExists",
                "",
                1,
            )
            .expect("attr exists");

        assert_eq!(second, "Second Link");
        assert_eq!(last, "Third");
        assert_eq!(contains_attr, "Alpha summary");
        assert_eq!(contains_text, "Second Link");
        assert_eq!(absolute, "First");
        assert_eq!(attr_exists, "Second Link");
    }

    #[test]
    fn url_rule_evaluates_embedded_js_before_templates_like_analyze_url() {
        let source: crate::source::BookSource = serde_json::from_value(serde_json::json!({
            "jsLib": "function Get(name) { return name === 'url' ? 'https://site.test' : ''; }"
        }))
        .expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_url_rule(
                "https://prefix.test/@js:`{{Get('url')}}/api/items?page={{page}}`",
                "",
                3,
                "https://source.test",
            )
            .expect("url");

        assert_eq!(out, "https://site.test/api/items?page=3");
    }

    #[test]
    fn field_rule_can_chain_js_snippets() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::Json(serde_json::json!({"title":"第5章 • 2024/11/07 02:41"}));
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                "title<js>result.replace(/\\s\\d+:\\d+/,'')</js><js>result.replace(/\\//g,'-')</js>",
                &value,
                "",
                "https://example.test",
                "ruleBookInfo.lastChapter",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "第5章 • 2024-11-07");
    }

    #[test]
    fn mixed_js_template_uses_previous_js_result_for_template_js() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::HtmlDocument("<h1>Original</h1>".to_string());
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                r#"<js>return JSON.stringify({body:"from-js"})</js><section>{{JSON.parse(result).body}}</section>"#,
                &value,
                "<h1>Original</h1>",
                "https://example.test",
                "rss.ruleContent",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "<section>from-js</section>");
    }

    #[test]
    fn mixed_js_template_keeps_original_html_for_embedded_rules() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::HtmlDocument(r#"<h1 class="h1">Original</h1>"#.to_string());
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                r#"<js>return JSON.stringify({body:"from-js"})</js><section>{{@@.h1@text}}:{{JSON.parse(result).body}}</section>"#,
                &value,
                r#"<h1 class="h1">Original</h1>"#,
                "https://example.test",
                "rss.ruleContent",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "<section>Original:from-js</section>");
    }

    #[test]
    fn mixed_js_json_path_uses_previous_js_result_even_when_original_is_html() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::HtmlDocument("<h1>Original</h1>".to_string());
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                r#"<js>return JSON.stringify({data:{name:"from-js"}})</js>$.data.name"#,
                &value,
                "<h1>Original</h1>",
                "https://example.test",
                "ruleBookInfo.init",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "from-js");
    }

    #[test]
    fn explicit_json_rule_parses_json_string_result_instead_of_css() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value =
            RuleContent::HtmlDocument(r#"{"data":[{"name":"A"},{"name":"B"}]}"#.to_string());
        let mut engine = RuleEngine::new(&mut runtime);

        let items = engine
            .select_list(
                "$.data",
                &value,
                r#"{"data":[{"name":"A"},{"name":"B"}]}"#,
                "https://example.test",
                "ruleSearch.bookList",
            )
            .expect("list");

        assert_eq!(items.len(), 2);
        assert_eq!(
            engine
                .eval_field_rule("name", &items[1], "", "https://example.test", "name", "", 1)
                .expect("name"),
            "B"
        );
    }

    #[test]
    fn mixed_js_detects_leading_and_trailing_js_with_template_between() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::HtmlDocument("<h1>Original</h1>".to_string());
        let mut engine = RuleEngine::new(&mut runtime);

        let out = engine
            .eval_field_rule(
                r#"<js>return JSON.stringify({body:"from-js"})</js><section>{{JSON.parse(result).body}}</section><js>result.replace("section", "article")</js>"#,
                &value,
                "<h1>Original</h1>",
                "https://example.test",
                "rss.ruleContent",
                "",
                1,
            )
            .expect("field");

        assert_eq!(out, "<article>from-js</section>");
    }

    #[test]
    fn select_list_accepts_json_value_marker_from_js_arrays() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let value = RuleContent::HtmlDocument("<html></html>".to_string());
        let mut engine = RuleEngine::new(&mut runtime);

        let items = engine
            .select_list(
                r#"<js>[{name:"A", url:"/a"}, {name:"B", url:"/b"}]</js>"#,
                &value,
                "<html></html>",
                "https://example.test",
                "rss.ruleArticles",
            )
            .expect("list");
        let title = engine
            .eval_field_rule(
                "name",
                &items[0],
                "",
                "https://example.test",
                "rss.ruleTitle",
                "",
                1,
            )
            .expect("title");

        assert_eq!(items.len(), 2);
        assert_eq!(title, "A");
    }

    #[test]
    fn select_list_js_receives_raw_json_body_as_string_like_analyze_rule() {
        let source: crate::source::BookSource =
            serde_json::from_value(serde_json::json!({})).expect("source");
        let mut runtime =
            JsRuntime::new(&source, crate::session::AnalyzerSession::default()).expect("runtime");
        let raw = r#"{"items":[{"name":"A"},{"name":"B"}]}"#;
        let value = RuleContent::from_body(raw);
        let mut engine = RuleEngine::new(&mut runtime);

        let items = engine
            .select_list(
                "<js>JSON.parse(result).items</js>",
                &value,
                raw,
                "https://example.test/api",
                "rss.ruleArticles",
            )
            .expect("list");
        let title = engine
            .eval_field_rule(
                "name",
                &items[1],
                raw,
                "https://example.test/api",
                "rss.ruleTitle",
                "",
                1,
            )
            .expect("title");

        assert_eq!(items.len(), 2);
        assert_eq!(title, "B");
    }
}
