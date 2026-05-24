use ego_tree::NodeRef;
use lol_html::{element, HtmlRewriter, Settings};
use percent_encoding::percent_decode_str;
use regex::Regex;
use scraper::{node::Node, ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlTextArrayOutput {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlCharsetOutput {
    pub charset: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlFormatOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlTitleOutput {
    pub title: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlAlignmentOutput {
    pub alignment: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubNativeEntryOutput {
    pub hrefs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubBookInfoOutput {
    pub is_book_info: bool,
    pub author: String,
    pub intro: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubFootnoteIdsOutput {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubFootnoteTargetOutput {
    pub found: bool,
    pub title: String,
    pub html: String,
    pub text: String,
    pub image_sources: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubReadableLinesOutput {
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubBodyHtmlOutput {
    pub html: String,
    pub document_html: String,
    pub body_html: String,
    pub body_outer_html: String,
    pub body_style: String,
    pub body_background: String,
    pub title: String,
    pub sliced: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubImageOptionsOutput {
    pub src: String,
    pub alt: String,
    pub is_background: bool,
    pub width: String,
    pub height: String,
    pub style: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubImagePageMarksOutput {
    pub html: String,
    pub body_style_append: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubMaterializedImagesOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubMediaPlaceholdersOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubInlineStylesOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubInheritedStylesOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubGeneratedContentOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpubGeneratedContentRuleInput {
    selector: String,
    before: bool,
    declarations: Vec<EpubGeneratedContentDeclarationInput>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpubGeneratedContentDeclarationInput {
    name: String,
    value: String,
}

struct EpubCompiledGeneratedContentRule {
    selector: Selector,
    before: bool,
    declarations: Vec<EpubGeneratedContentDeclarationInput>,
    style: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubResolvedLinksOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubBodyBackgroundImageOutput {
    pub href: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubCssAssetsOutput {
    pub assets: Vec<EpubCssAssetOutput>,
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubCssAssetOutput {
    pub kind: String,
    pub content: String,
    pub href: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubNativeDomOutput {
    pub body: EpubNativeDomNodeOutput,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubAppliedCssOutput {
    pub html: String,
    pub body_style: String,
    pub body_background: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubDebugChapterHtmlOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubNativeDomNodeOutput {
    pub kind: String,
    pub tag_name: String,
    pub attributes: BTreeMap<String, String>,
    pub style: EpubNativeComputedStyleOutput,
    pub children: Vec<EpubNativeDomNodeOutput>,
    pub text: String,
    pub source_path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubNativeComputedStyleOutput {
    pub declarations: BTreeMap<String, EpubNativeStyleValueOutput>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpubNativeStyleValueOutput {
    pub value: String,
    pub important: bool,
    pub source_rank: i32,
    pub specificity: i32,
    pub rule_order: i32,
    pub declaration_order: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpubNativeCssRuleInput {
    selector: String,
    specificity: i32,
    order: i32,
    declarations: Vec<EpubNativeCssDeclarationInput>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpubNativeCssDeclarationInput {
    name: String,
    value: String,
    important: bool,
    order: i32,
}

struct EpubCompiledNativeCssRule {
    selector: Selector,
    specificity: i32,
    order: i32,
    declarations: Vec<EpubNativeCssDeclarationInput>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlReadableTableOutput {
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlRenderFlagsOutput {
    pub tag_name: String,
    pub is_block: bool,
    pub has_image: bool,
    pub has_block_box_style: bool,
    pub has_block_box_descendant: bool,
    pub page_break_before: bool,
    pub page_break_after: bool,
    pub block_spacing_before: bool,
    pub block_spacing_after: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlPageBackgroundOutput {
    pub page_color: String,
    pub background_src: String,
    pub html: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlImageInfoOutput {
    pub src: String,
    pub is_background: bool,
    pub style: String,
    pub width: String,
    pub click: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlRenderPlanOutput {
    pub actions: Vec<HtmlRenderActionOutput>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlRenderActionOutput {
    pub kind: String,
    pub html: String,
    pub page_color: String,
    pub margin_top: String,
    pub padding_top: String,
    pub margin_bottom: String,
    pub padding_bottom: String,
    pub image: HtmlImageInfoOutput,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobiContentOutput {
    pub html: String,
}

pub fn html_text_array(html: &str) -> HtmlTextArrayOutput {
    let html = normalize_breaks(html);
    let document = Html::parse_document(&html);
    let text = document.root_element().text().collect::<Vec<_>>().join(" ");
    HtmlTextArrayOutput {
        lines: split_not_blank(&normalize_whitespace_lines(&text)),
    }
}

pub fn html_charset(html: &str) -> HtmlCharsetOutput {
    let document = Html::parse_fragment(html);
    let selector = Selector::parse("meta").expect("static meta selector");
    for meta in document.select(&selector) {
        if let Some(charset) = meta.value().attr("charset").map(str::trim) {
            if !charset.is_empty() {
                return HtmlCharsetOutput {
                    charset: trim_charset(charset).to_string(),
                };
            }
        }
        let http_equiv = meta.value().attr("http-equiv").unwrap_or_default();
        if http_equiv.eq_ignore_ascii_case("content-type") {
            let content = meta.value().attr("content").unwrap_or_default();
            if let Some(charset) = charset_from_content_type(content) {
                return HtmlCharsetOutput { charset };
            }
        }
    }
    HtmlCharsetOutput::default()
}

pub fn html_format(html: &str) -> HtmlFormatOutput {
    let document = Html::parse_document(html);
    HtmlFormatOutput {
        html: document.root_element().html(),
    }
}

pub fn html_title(html: &str) -> HtmlTitleOutput {
    let document = Html::parse_document(html);
    let selector = Selector::parse("title").expect("static title selector");
    HtmlTitleOutput {
        title: document
            .select(&selector)
            .next()
            .map(|element| normalized_element_text(element.text()))
            .unwrap_or_default(),
    }
}

pub fn html_first_alignment(html: &str) -> HtmlAlignmentOutput {
    let document = Html::parse_fragment(html);
    let selector = Selector::parse("*").expect("static all-elements selector");
    for element in document.select(&selector) {
        if let Some(align) = element_alignment(element.value()) {
            return HtmlAlignmentOutput { alignment: align };
        }
    }
    HtmlAlignmentOutput::default()
}

pub fn epub_css_assets(document_html: &str, body_html: &str) -> EpubCssAssetsOutput {
    let document = Html::parse_document(document_html);
    let body = Html::parse_fragment(body_html);
    let mut assets = Vec::new();

    push_style_assets(&document, "head style", &mut assets);
    push_stylesheet_assets(&document, "head link[href]", &mut assets);
    push_style_assets(&body, "style", &mut assets);
    push_stylesheet_assets(&body, "link[href]", &mut assets);

    EpubCssAssetsOutput {
        assets,
        html: remove_epub_css_asset_nodes(body_html),
    }
}

pub fn epub_native_dom(
    body_outer_html: &str,
    rules_json: &str,
    base_href: &str,
) -> EpubNativeDomOutput {
    let rules = serde_json::from_str::<Vec<EpubNativeCssRuleInput>>(rules_json)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|rule| {
            let selector = Selector::parse(&rule.selector).ok()?;
            Some(EpubCompiledNativeCssRule {
                selector,
                specificity: rule.specificity,
                order: rule.order,
                declarations: rule.declarations,
            })
        })
        .collect::<Vec<_>>();
    let document = Html::parse_document(body_outer_html);
    let body_selector = Selector::parse("body").expect("static body selector");
    if let Some(body) = document.select(&body_selector).next() {
        return EpubNativeDomOutput {
            body: build_epub_native_dom_element(
                body,
                &EpubNativeComputedStyleOutput::default(),
                &rules,
                base_href,
                "body",
            ),
        };
    }
    let fragment = Html::parse_fragment(body_outer_html);
    EpubNativeDomOutput {
        body: build_epub_native_dom_element(
            fragment.root_element(),
            &EpubNativeComputedStyleOutput::default(),
            &rules,
            base_href,
            "body",
        ),
    }
}

pub fn epub_applied_css(body_outer_html: &str, rules_json: &str) -> EpubAppliedCssOutput {
    let rules = serde_json::from_str::<Vec<EpubNativeCssRuleInput>>(rules_json)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|rule| {
            let selector = Selector::parse(&rule.selector).ok()?;
            Some(EpubCompiledNativeCssRule {
                selector,
                specificity: rule.specificity,
                order: rule.order,
                declarations: rule.declarations,
            })
        })
        .collect::<Vec<_>>();
    let document = Html::parse_document(body_outer_html);
    let body_selector = Selector::parse("body").expect("static body selector");
    if let Some(body) = document.select(&body_selector).next() {
        return serialize_epub_applied_css_body(body, &rules);
    }
    let fragment = Html::parse_fragment(body_outer_html);
    serialize_epub_applied_css_body(fragment.root_element(), &rules)
}

pub fn epub_native_entry(html: &str) -> EpubNativeEntryOutput {
    let document = Html::parse_fragment(html);
    let selector = Selector::parse("epub-native[data-href]").expect("static epub-native selector");
    let Some(element) = document.select(&selector).next() else {
        return EpubNativeEntryOutput::default();
    };
    if let Some(hrefs) = element.value().attr("data-hrefs") {
        let values = split_distinct_hrefs(hrefs);
        if !values.is_empty() {
            return EpubNativeEntryOutput { hrefs: values };
        }
    }
    EpubNativeEntryOutput {
        hrefs: split_distinct_hrefs(element.value().attr("data-href").unwrap_or_default()),
    }
}

fn push_style_assets(document: &Html, selector: &str, assets: &mut Vec<EpubCssAssetOutput>) {
    let selector = Selector::parse(selector).expect("static style selector");
    for element in document.select(&selector) {
        let content = element
            .text()
            .collect::<Vec<_>>()
            .join("")
            .trim()
            .to_string();
        let content = if content.is_empty() {
            element.inner_html().trim().to_string()
        } else {
            content
        };
        if !content.is_empty() {
            assets.push(EpubCssAssetOutput {
                kind: "inline".to_string(),
                content,
                href: String::new(),
            });
        }
    }
}

fn push_stylesheet_assets(document: &Html, selector: &str, assets: &mut Vec<EpubCssAssetOutput>) {
    let selector = Selector::parse(selector).expect("static stylesheet selector");
    for element in document.select(&selector) {
        if !element
            .value()
            .attr("rel")
            .is_some_and(|rel| rel_contains_stylesheet(rel))
        {
            continue;
        }
        let href = element.value().attr("href").unwrap_or_default().trim();
        if !href.is_empty() {
            assets.push(EpubCssAssetOutput {
                kind: "stylesheet".to_string(),
                content: String::new(),
                href: href.to_string(),
            });
        }
    }
}

fn remove_epub_css_asset_nodes(html: &str) -> String {
    let mut out = Vec::new();
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("style", |element| {
                    element.remove();
                    Ok(())
                }),
                element!("link[href]", |element| {
                    let rel = element.get_attribute("rel").unwrap_or_default();
                    if rel_contains_stylesheet(&rel) {
                        element.remove();
                    }
                    Ok(())
                }),
            ],
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return html.to_string();
    }
    String::from_utf8(out).unwrap_or_else(|_| html.to_string())
}

fn rel_contains_stylesheet(rel: &str) -> bool {
    rel.split(|ch: char| ch.is_ascii_whitespace())
        .any(|token| token.eq_ignore_ascii_case("stylesheet"))
}

fn resolve_epub_resource_href(base_href: &str, href: &str, resource_hrefs: &[String]) -> String {
    let clean_href = trim_matching_quote(
        strip_url_options(href)
            .split_once('?')
            .map(|(value, _)| value)
            .unwrap_or_else(|| strip_url_options(href))
            .trim(),
    );
    let clean_href_lower = clean_href.to_ascii_lowercase();
    if clean_href.is_empty()
        || clean_href_lower.starts_with("data:")
        || clean_href_lower.starts_with("http://")
        || clean_href_lower.starts_with("https://")
    {
        return clean_href;
    }
    if let Some(found) = find_epub_resource_href(&clean_href, resource_hrefs) {
        return found;
    }
    let resolved = resolve_epub_href(base_href, &clean_href);
    if let Some(found) = find_epub_resource_href(&resolved, resource_hrefs) {
        return found;
    }
    resolved
}

fn find_epub_resource_href(href: &str, resource_hrefs: &[String]) -> Option<String> {
    let clean = trim_matching_quote(
        strip_url_options(href)
            .split_once('?')
            .map(|(value, _)| value)
            .unwrap_or_else(|| strip_url_options(href))
            .trim(),
    );
    if clean.is_empty() {
        return None;
    }
    let mut candidates = Vec::<String>::new();
    push_unique(&mut candidates, clean.clone());
    if let Ok(decoded) = percent_decode_str(&clean).decode_utf8() {
        push_unique(&mut candidates, decoded.to_string());
    }
    let snapshot = candidates.clone();
    for candidate in snapshot {
        push_unique(
            &mut candidates,
            candidate.trim_start_matches('/').to_string(),
        );
        for fallback in epub_path_fallbacks(&candidate) {
            push_unique(&mut candidates, fallback);
        }
        let encoded = encode_uri_component_like_android(&candidate);
        push_unique(&mut candidates, encoded.clone());
        if let Ok(decoded) = percent_decode_str(&encoded).decode_utf8() {
            let decoded = decoded.to_string();
            push_unique(&mut candidates, decoded.clone());
            for fallback in epub_path_fallbacks(&decoded) {
                push_unique(&mut candidates, fallback);
            }
        }
    }
    for candidate in &candidates {
        if let Some(found) = resource_hrefs
            .iter()
            .find(|href| href.as_str() == candidate)
        {
            return Some(found.clone());
        }
    }
    let normalized = candidates
        .iter()
        .map(|value| value.trim_start_matches('/').to_ascii_lowercase())
        .collect::<std::collections::HashSet<_>>();
    let file_name = clean
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    resource_hrefs.iter().find_map(|resource_href| {
        let lower = resource_href.trim_start_matches('/').to_ascii_lowercase();
        (normalized.contains(&lower)
            || lower.ends_with(&format!("/{file_name}"))
            || lower == file_name)
            .then(|| resource_href.clone())
    })
}

fn epub_path_fallbacks(path: &str) -> Vec<String> {
    let clean = path.trim_start_matches('/');
    let parts = clean
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return Vec::new();
    }
    let mut fallbacks = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("OEBPS") || part.eq_ignore_ascii_case("OPS") {
            push_unique(&mut fallbacks, parts[index..].join("/"));
        }
    }
    if let Some(index) = parts
        .iter()
        .rposition(|part| part.eq_ignore_ascii_case("Images") || part.eq_ignore_ascii_case("Image"))
    {
        push_unique(&mut fallbacks, parts[index..].join("/"));
        push_unique(&mut fallbacks, parts[index + 1..].join("/"));
    }
    push_unique(&mut fallbacks, parts[parts.len() - 1].to_string());
    fallbacks
        .into_iter()
        .filter(|fallback| !fallback.is_empty() && fallback != clean)
        .collect()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !value.is_empty() && !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn strip_url_options(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b',' {
            let mut next = index + 1;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            if next < bytes.len() && bytes[next] == b'{' {
                return &value[..index];
            }
        }
        index += 1;
    }
    value
}

pub fn epub_readable_title(html: &str) -> HtmlTitleOutput {
    let document = Html::parse_document(html);
    let selector = Selector::parse(
        "h1,h2,h3,h4,h5,h6,[id^=toc_],.chapter,.chapter-title,.title,.head,\
         .duokan-image-maintitle,.role-title,.vol-title,.extra-h1",
    )
    .expect("static EPUB title selector");
    if let Some(title) = document
        .select(&selector)
        .map(|element| normalized_element_text(element.text()))
        .find(|text| !text.trim().is_empty())
    {
        return HtmlTitleOutput { title };
    }
    html_title(html)
}

pub fn epub_book_info(html: &str) -> EpubBookInfoOutput {
    let document = Html::parse_document(html);
    if !is_epub_book_info_document(&document) {
        return EpubBookInfoOutput::default();
    }

    let selector = Selector::parse("h1,h2,h3,h4,p,div").expect("static EPUB info line selector");
    let mut lines = Vec::new();
    for element in document.select(&selector) {
        if element.value().name() == "div" && div_has_div_or_p_child(&element) {
            continue;
        }
        let line = clean_epub_info_text(&normalized_element_text(element.text()));
        if !line.is_empty() && !lines.iter().any(|existing| existing == &line) {
            lines.push(line);
        }
    }

    let author = lines
        .iter()
        .find_map(|line| substring_after_label(line, "作者"))
        .unwrap_or_default();
    let mut intro_lines = Vec::new();
    let mut in_intro = false;
    for line in &lines {
        let intro = substring_after_label(line, "简介");
        if let Some(intro) = intro {
            in_intro = true;
            if !intro.is_empty() {
                intro_lines.push(intro);
            }
        } else if in_intro && !is_epub_info_meta_line(line) {
            intro_lines.push(line.clone());
        }
    }

    EpubBookInfoOutput {
        is_book_info: true,
        author,
        intro: intro_lines.join("\n").trim().to_string(),
    }
}

pub fn epub_footnote_ids(html: &str) -> EpubFootnoteIdsOutput {
    let document = Html::parse_document(html);
    let selector =
        Selector::parse("aside[id], section[id], div[id], li[id], p[id], span[id], a[id]")
            .expect("static EPUB footnote target selector");
    let mut ids = Vec::new();
    for element in document.select(&selector) {
        let id = element.value().id().unwrap_or_default();
        if !id.is_empty()
            && is_likely_footnote_target(
                id,
                element
                    .value()
                    .attr("epub:type")
                    .or_else(|| element.value().attr("type"))
                    .unwrap_or_default(),
                element.value().attr("role").unwrap_or_default(),
                element.value().attr("class").unwrap_or_default(),
            )
            && !ids.iter().any(|existing| existing == id)
        {
            ids.push(id.to_string());
        }
    }
    EpubFootnoteIdsOutput { ids }
}

pub fn epub_footnote_target(html: &str, target_id: &str) -> EpubFootnoteTargetOutput {
    let document = Html::parse_document(html);
    let selector = Selector::parse("[id]").expect("static id selector");
    let Some(target) = document
        .select(&selector)
        .find(|element| element.value().id() == Some(target_id))
    else {
        return EpubFootnoteTargetOutput::default();
    };
    let title = target
        .value()
        .attr("title")
        .or_else(|| target.value().attr("aria-label"))
        .or_else(|| target.value().attr("epub:type"))
        .or_else(|| target.value().attr("role"))
        .unwrap_or("注解")
        .to_string();
    let image_sources = Arc::new(Mutex::new(Vec::new()));
    let rewritten_html =
        rewrite_epub_footnote_html(&target.inner_html(), target_id, Arc::clone(&image_sources));
    let text = clean_epub_info_text(&normalized_element_text(
        Html::parse_fragment(&rewritten_html).root_element().text(),
    ));
    let html = if rewritten_html.trim().is_empty() {
        text.clone()
    } else {
        rewritten_html.trim().to_string()
    };
    EpubFootnoteTargetOutput {
        found: true,
        title,
        html,
        text,
        image_sources: Arc::try_unwrap(image_sources)
            .ok()
            .and_then(|mutex| mutex.into_inner().ok())
            .unwrap_or_default(),
    }
}

pub fn epub_readable_lines(html: &str, delete_ruby: bool) -> EpubReadableLinesOutput {
    let document = Html::parse_fragment(html);
    let root = document.root_element();
    let mut context = EpubReadableContext {
        delete_ruby,
        cover_seen: false,
        lines: Vec::new(),
    };
    let mut builder = String::new();
    for child in root.children() {
        walk_epub_readable_node(
            child,
            &mut context,
            &mut builder,
            ReadableInlineStyle::default(),
        );
    }
    push_readable_line(&mut context.lines, &mut builder);
    EpubReadableLinesOutput {
        lines: context.lines,
    }
}

pub fn epub_body_html(
    html: &str,
    start_fragment_id: Option<&str>,
    end_fragment_id: Option<&str>,
) -> EpubBodyHtmlOutput {
    let cleaned = strip_script_tags(html);
    let rewritten = rewrite_epub_body_html(&cleaned);
    let start_fragment_id = start_fragment_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let end_fragment_id = end_fragment_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if start_fragment_id.is_none() && end_fragment_id.is_none() {
        return epub_body_html_output(rewritten, false);
    }

    let document = Html::parse_document(&rewritten);
    let body_selector = Selector::parse("body").expect("static body selector");
    let mut body_html = document
        .select(&body_selector)
        .next()
        .map(|body| body.html())
        .unwrap_or_else(|| rewritten.clone());
    let original = body_html.clone();
    let id_selector = Selector::parse("[id]").expect("static id selector");
    if let Some(start_id) = start_fragment_id {
        if let Some(target) = document
            .select(&id_selector)
            .find(|element| element.value().id() == Some(start_id))
        {
            let target_html = target.html();
            let tag_start = target_html.split('\n').next().unwrap_or(&target_html);
            if body_html.contains(tag_start) {
                let (before, after) = body_html.split_once(tag_start).unwrap_or(("", ""));
                body_html = format!("{}{tag_start}{after}", page_background_prefix(before));
            }
        }
    }
    if let Some(end_id) = end_fragment_id {
        if Some(end_id) != start_fragment_id {
            if let Some(target) = document
                .select(&id_selector)
                .find(|element| element.value().id() == Some(end_id))
            {
                let target_html = target.html();
                let tag_start = target_html.split('\n').next().unwrap_or(&target_html);
                if let Some((before, _)) = body_html.split_once(tag_start) {
                    body_html = before.to_string();
                }
            }
        }
    }
    epub_body_html_output(body_html.clone(), body_html != original)
}

pub fn epub_debug_chapter_html(bodies_json: &str, delete_ruby: bool) -> EpubDebugChapterHtmlOutput {
    let bodies = serde_json::from_str::<Vec<String>>(bodies_json).unwrap_or_default();
    let mut cover_count = 0usize;
    let html = bodies
        .iter()
        .map(|body| {
            let document = Html::parse_document(body);
            let root = document.root_element();
            let body_element = root
                .descendants()
                .filter_map(ElementRef::wrap)
                .find(|element| element.value().name().eq_ignore_ascii_case("body"));
            let mut out = String::new();
            if let Some(body_element) = body_element {
                for child in body_element.children() {
                    serialize_epub_debug_chapter_node(
                        child,
                        delete_ruby,
                        &mut cover_count,
                        &mut out,
                    );
                }
            } else {
                for child in root.children() {
                    serialize_epub_debug_chapter_node(
                        child,
                        delete_ruby,
                        &mut cover_count,
                        &mut out,
                    );
                }
            }
            out.trim().to_string()
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    EpubDebugChapterHtmlOutput { html }
}

pub fn html_readable_table(html: &str) -> HtmlReadableTableOutput {
    let document = Html::parse_fragment(html);
    let root = document.root_element();
    let Some(element) = root.children().find_map(ElementRef::wrap) else {
        return HtmlReadableTableOutput::default();
    };
    HtmlReadableTableOutput {
        html: readable_table_element_html(element),
    }
}

fn readable_table_element_html(element: ElementRef<'_>) -> String {
    let row_selector = Selector::parse("tr").expect("static table row selector");
    let rows = element.select(&row_selector).collect::<Vec<_>>();
    let row_elements = if rows.is_empty() {
        element
            .children()
            .filter_map(ElementRef::wrap)
            .collect::<Vec<_>>()
    } else {
        rows
    };
    let mut row_html = Vec::new();
    for row in row_elements {
        let cell_selector = Selector::parse("th,td").expect("static table cell selector");
        let cells = row.select(&cell_selector).collect::<Vec<_>>();
        let cell_elements = if cells.is_empty() {
            row.children()
                .filter_map(ElementRef::wrap)
                .collect::<Vec<_>>()
        } else {
            cells
        };
        let cells = cell_elements
            .iter()
            .filter_map(|cell| {
                let html = readable_inline_html(*cell);
                (!html.trim().is_empty()).then_some(html)
            })
            .collect::<Vec<_>>();
        let row_text = if cells.is_empty() {
            readable_inline_html(row)
        } else {
            cells.join("　")
        };
        let row_text = row_text.trim().to_string();
        if !row_text.is_empty() {
            row_html.push(row_text);
        }
    }

    let align = html_align_attr(element);
    if row_html.is_empty() {
        let text = readable_inline_html(element);
        if text.trim().is_empty() {
            String::new()
        } else {
            format!("<p{}>{}</p>", align, text.trim())
        }
    } else {
        row_html
            .into_iter()
            .map(|row| format!("<p{}>{}</p>", align, row))
            .collect::<String>()
    }
}

pub fn html_render_flags(html: &str) -> HtmlRenderFlagsOutput {
    let document = Html::parse_fragment(html);
    let root = document.root_element();
    let Some(element) = root.children().find_map(ElementRef::wrap) else {
        return HtmlRenderFlagsOutput::default();
    };
    let declarations = css_declarations(element.value().attr("style").unwrap_or_default());
    HtmlRenderFlagsOutput {
        tag_name: element.value().name().to_string(),
        is_block: is_readable_block(element.value().name()),
        has_image: element_has_image(element),
        has_block_box_style: declarations_have_block_box_style(&declarations),
        has_block_box_descendant: element_has_block_box_descendant(element),
        page_break_before: css_value_with_shorthand(&declarations, "page-break-before")
            .is_some_and(|value| is_epub_always_break(&value))
            || css_value_with_shorthand(&declarations, "break-before")
                .is_some_and(|value| is_epub_always_break(&value)),
        page_break_after: css_value_with_shorthand(&declarations, "page-break-after")
            .is_some_and(|value| is_epub_always_break(&value))
            || css_value_with_shorthand(&declarations, "break-after")
                .is_some_and(|value| is_epub_always_break(&value)),
        block_spacing_before: css_value_with_shorthand(&declarations, "margin-top")
            .is_some_and(|value| is_large_epub_spacing(&value))
            || css_value_with_shorthand(&declarations, "padding-top")
                .is_some_and(|value| is_large_epub_spacing(&value)),
        block_spacing_after: css_value_with_shorthand(&declarations, "margin-bottom")
            .is_some_and(|value| is_large_epub_spacing(&value))
            || css_value_with_shorthand(&declarations, "padding-bottom")
                .is_some_and(|value| is_large_epub_spacing(&value)),
    }
}

pub fn html_page_background(html: &str) -> HtmlPageBackgroundOutput {
    let document = Html::parse_fragment(html);
    let page_selector = Selector::parse("[data-epub-page-bg]").expect("static page bg selector");
    let image_selector =
        Selector::parse("img[data-epub-background=true]").expect("static page bg image selector");
    let page_color = document
        .select(&page_selector)
        .next()
        .and_then(|element| element.value().attr("data-epub-page-bg"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let background_src = document
        .select(&image_selector)
        .next()
        .and_then(|element| element.value().attr("src"))
        .unwrap_or_default()
        .trim()
        .to_string();
    HtmlPageBackgroundOutput {
        page_color,
        background_src,
        html: remove_page_background_nodes(html),
    }
}

pub fn html_image_info(html: &str) -> HtmlImageInfoOutput {
    let document = Html::parse_fragment(html);
    let root = document.root_element();
    let Some(element) = root.children().find_map(ElementRef::wrap) else {
        return HtmlImageInfoOutput::default();
    };
    let style = element.value().attr("style").unwrap_or_default();
    HtmlImageInfoOutput {
        src: element
            .value()
            .attr("src")
            .unwrap_or_default()
            .trim()
            .to_string(),
        is_background: element.value().attr("data-epub-background") == Some("true"),
        style: element
            .value()
            .attr("data-legado-style")
            .unwrap_or_default()
            .trim()
            .to_string(),
        width: element
            .value()
            .attr("data-legado-width")
            .or_else(|| element.value().attr("width"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| css_declaration_value(style, "width"))
            .unwrap_or_default(),
        click: element
            .value()
            .attr("data-legado-click")
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

pub fn html_render_plan(html: &str, classic_epub: bool) -> HtmlRenderPlanOutput {
    let document = Html::parse_fragment(html);
    let mut actions = Vec::new();
    let root = document.root_element();
    for child in root.children() {
        render_plan_node(child, classic_epub, &mut actions);
    }
    HtmlRenderPlanOutput { actions }
}

pub fn epub_image_options(html: &str) -> EpubImageOptionsOutput {
    let document = Html::parse_fragment(html);
    let root = document.root_element();
    let Some(element) = root.children().find_map(ElementRef::wrap) else {
        return EpubImageOptionsOutput::default();
    };
    let style_attr = element.value().attr("style").unwrap_or_default();
    let width = element
        .value()
        .attr("data-legado-width")
        .or_else(|| element.value().attr("width"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(normalize_epub_image_width)
        .or_else(|| {
            css_declaration_value(style_attr, "width")
                .and_then(|value| normalize_epub_image_width(&value))
        })
        .unwrap_or_default();
    let height = element
        .value()
        .attr("data-legado-height")
        .or_else(|| element.value().attr("height"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(normalize_epub_image_length)
        .or_else(|| {
            css_declaration_value(style_attr, "height")
                .and_then(|value| normalize_epub_image_length(&value))
        })
        .unwrap_or_default();
    let mut style = element
        .value()
        .attr("data-legado-style")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut width = width;
    if element.value().attr("data-epub-single-page") == Some("true") {
        style = "SINGLE".to_string();
        if width.is_empty() {
            width = "100%".to_string();
        }
    } else if style.is_empty() && is_inline_epub_image_width(&width) {
        style = "text".to_string();
    }
    EpubImageOptionsOutput {
        src: first_attr(
            element,
            &[
                "src",
                "data-src",
                "data-original",
                "data-lazy-src",
                "data-url",
                "xlink:href",
                "href",
            ],
        ),
        alt: element
            .value()
            .attr("alt")
            .unwrap_or_default()
            .trim()
            .to_string(),
        is_background: element.value().attr("data-epub-background") == Some("true"),
        width,
        height,
        style,
    }
}

pub fn epub_image_page_marks(html: &str) -> EpubImagePageMarksOutput {
    let info = analyze_epub_image_page(html);
    let mut image_index = 0usize;
    let mut out = Vec::with_capacity(html.len());
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("img", |element| {
                    image_index += 1;
                    let is_background =
                        element.get_attribute("data-epub-background").as_deref() == Some("true");
                    if info.mark_single && image_index == 1 {
                        element.set_attribute("data-epub-single-page", "true")?;
                    }
                    if info.mark_overlay && image_index == 1 {
                        element.set_attribute("data-epub-background", "true")?;
                    }
                    if info.mark_gallery && !is_background {
                        if element
                            .get_attribute("data-legado-width")
                            .unwrap_or_default()
                            .trim()
                            .is_empty()
                        {
                            element.set_attribute("data-legado-width", "100%")?;
                        }
                        if !info.duokan_gallery
                            && element
                                .get_attribute("data-legado-style")
                                .unwrap_or_default()
                                .trim()
                                .is_empty()
                        {
                            element.set_attribute("data-legado-style", "SINGLE")?;
                        }
                        let style = element.get_attribute("style").unwrap_or_default();
                        element.set_attribute(
                            "style",
                            &format!(
                                "{style};display:block;margin:0 auto;max-width:100%;height:auto"
                            ),
                        )?;
                    }
                    Ok(())
                }),
                element!(
                    ".duokan-image-gallery,.duokan-image-gallery-cell,.duokan-gallery,.gallery",
                    |element| {
                        if info.mark_gallery && info.duokan_gallery {
                            let style = element.get_attribute("style").unwrap_or_default();
                            element.set_attribute(
                            "style",
                            &format!("{style};display:block;margin:0 auto;text-align:center;max-width:100%"),
                        )?;
                        }
                        Ok(())
                    }
                ),
            ],
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return EpubImagePageMarksOutput {
            html: html.to_string(),
            body_style_append: String::new(),
        };
    }
    let body_style_append = if info.mark_gallery {
        if info.duokan_gallery {
            ";margin:0;padding:0;text-indent:0;text-align:center"
        } else {
            ";margin:0;padding:0;text-indent:0;text-align:center;line-height:1"
        }
        .to_string()
    } else {
        String::new()
    };
    EpubImagePageMarksOutput {
        html: String::from_utf8(out)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
        body_style_append,
    }
}

pub fn epub_materialized_images(
    html: &str,
    base_href: &str,
    resource_hrefs_json: &str,
) -> EpubMaterializedImagesOutput {
    let resource_hrefs =
        serde_json::from_str::<Vec<String>>(resource_hrefs_json).unwrap_or_default();
    let mut out = Vec::with_capacity(html.len());
    let base_href = base_href.to_string();
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![element!("img", move |element| {
                let image = epub_image_options_from_element(element);
                let resolved_href =
                    resolve_epub_resource_href(&base_href, image.src.trim(), &resource_hrefs);
                element.replace(
                    &materialized_epub_image_html(&resolved_href, &image),
                    lol_html::html_content::ContentType::Html,
                );
                Ok(())
            })],
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return EpubMaterializedImagesOutput {
            html: html.to_string(),
        };
    }
    EpubMaterializedImagesOutput {
        html: String::from_utf8(out).unwrap_or_else(|_| html.to_string()),
    }
}

pub fn epub_media_placeholders(html: &str, base_href: &str) -> EpubMediaPlaceholdersOutput {
    let document = Html::parse_fragment(html);
    let mut out = String::new();
    let root = document.root_element();
    for child in root.children() {
        serialize_epub_media_node(child, base_href, &mut out);
    }
    EpubMediaPlaceholdersOutput { html: out }
}

pub fn epub_inline_styles(html: &str, body_style: &str) -> EpubInlineStylesOutput {
    let document = Html::parse_fragment(html);
    let mut out = String::new();
    let root = document.root_element();
    for child in root.children() {
        serialize_epub_inline_style_node(child, &mut out);
    }
    EpubInlineStylesOutput {
        html: apply_epub_inline_style_to_inner("body", body_style, out, None).unwrap_or_default(),
    }
}

pub fn epub_inherited_styles(html: &str, body_style: &str) -> EpubInheritedStylesOutput {
    let document = Html::parse_fragment(html);
    let mut out = String::new();
    let parent_style = ordered_css_declarations(body_style);
    let root = document.root_element();
    for child in root.children() {
        serialize_epub_inherited_style_node(child, &parent_style, &mut out);
    }
    EpubInheritedStylesOutput { html: out }
}

pub fn epub_generated_content(
    body_outer_html: &str,
    rules_json: &str,
) -> EpubGeneratedContentOutput {
    let rules = serde_json::from_str::<Vec<EpubGeneratedContentRuleInput>>(rules_json)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|rule| {
            let selector = Selector::parse(&rule.selector).ok()?;
            let style = rule
                .declarations
                .iter()
                .filter(|declaration| !declaration.name.eq_ignore_ascii_case("content"))
                .map(|declaration| format!("{}:{}", declaration.name, declaration.value))
                .collect::<Vec<_>>()
                .join(";");
            Some(EpubCompiledGeneratedContentRule {
                selector,
                before: rule.before,
                declarations: rule.declarations,
                style,
            })
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        return EpubGeneratedContentOutput {
            html: body_outer_html.to_string(),
        };
    }
    let document = Html::parse_document(body_outer_html);
    let root = document.root_element();
    if let Some(body) = root
        .descendants()
        .filter_map(ElementRef::wrap)
        .find(|element| element.value().name().eq_ignore_ascii_case("body"))
    {
        let mut out = String::new();
        serialize_epub_generated_content_children(body, &rules, &mut out);
        return EpubGeneratedContentOutput { html: out };
    }
    let mut out = String::new();
    for child in root.children() {
        serialize_epub_generated_content_node(child, &rules, &mut out);
    }
    EpubGeneratedContentOutput { html: out }
}

pub fn epub_resolved_links(html: &str, base_href: &str) -> EpubResolvedLinksOutput {
    let document = Html::parse_fragment(html);
    let mut out = String::new();
    let root = document.root_element();
    for child in root.children() {
        serialize_epub_resolved_link_node(child, base_href, &mut out);
    }
    EpubResolvedLinksOutput { html: out }
}

pub fn epub_body_background_image(
    body_style: &str,
    body_background: &str,
) -> EpubBodyBackgroundImageOutput {
    let declarations = css_declaration_map(body_style);
    let background = declarations
        .get("background-image")
        .or_else(|| declarations.get("background"))
        .map(String::as_str)
        .or_else(|| {
            let clean = body_background.trim();
            if clean.is_empty() {
                None
            } else {
                Some(clean)
            }
        });
    let href = background
        .and_then(|value| extract_css_url(value).or_else(|| Some(value.to_string())))
        .map(|value| trim_matching_quote(&value))
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"))
        .unwrap_or_default();
    EpubBodyBackgroundImageOutput { href }
}

pub fn mobi_content_html(html: &str, rewrite_recindex_images: bool) -> MobiContentOutput {
    let mut out = Vec::with_capacity(html.len());
    let mut handlers = vec![
        element!("title", |element| {
            element.remove();
            Ok(())
        }),
        element!("[style]", |element| {
            let style = element.get_attribute("style").unwrap_or_default();
            if style
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase()
                .contains("display:none")
            {
                element.remove();
            }
            Ok(())
        }),
    ];
    if rewrite_recindex_images {
        handlers.push(element!("img[recindex]", |element| {
            let recindex = element.get_attribute("recindex").unwrap_or_default();
            element.replace(
                &format!(r#"<img src="recindex:{}">"#, escape_html_attr(&recindex)),
                lol_html::html_content::ContentType::Html,
            );
            Ok(())
        }));
    }
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: handlers,
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return MobiContentOutput {
            html: html.to_string(),
        };
    }
    MobiContentOutput {
        html: String::from_utf8(out)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()),
    }
}

fn strip_script_tags(html: &str) -> String {
    let block = Regex::new("(?is)<script\\b[^>]*>.*?</script>").expect("static script regex");
    let self_closing = Regex::new("(?is)<script\\b[^>]*/>").expect("static script regex");
    self_closing
        .replace_all(&block.replace_all(html, ""), "")
        .to_string()
}

fn epub_body_html_output(html: String, sliced: bool) -> EpubBodyHtmlOutput {
    let document = Html::parse_document(&html);
    let root = document.root_element();
    let title_selector = Selector::parse("title").expect("static title selector");
    let title = document
        .select(&title_selector)
        .next()
        .map(|element| clean_epub_info_text(&element.text().collect::<Vec<_>>().join(" ")))
        .unwrap_or_default();
    if let Some(body) = root
        .descendants()
        .filter_map(ElementRef::wrap)
        .find(|element| element.value().name().eq_ignore_ascii_case("body"))
    {
        let body_html = body.html();
        let body_style = body.value().attr("style").unwrap_or_default().to_string();
        let body_background = body
            .value()
            .attr("background")
            .unwrap_or_default()
            .to_string();
        let body_outer_html = serialize_element_outer_html(body);
        return EpubBodyHtmlOutput {
            html,
            document_html: root.html(),
            body_html,
            body_outer_html,
            body_style,
            body_background,
            title,
            sliced,
        };
    }
    let body_outer_html = format!("<body>{html}</body>");
    EpubBodyHtmlOutput {
        document_html: html.clone(),
        body_html: html.clone(),
        body_outer_html,
        html,
        title,
        sliced,
        ..EpubBodyHtmlOutput::default()
    }
}

fn serialize_element_outer_html(element: ElementRef<'_>) -> String {
    let tag = element.value().name();
    let mut out = String::new();
    out.push('<');
    out.push_str(tag);
    for (name, value) in element.value().attrs() {
        out.push(' ');
        out.push_str(name);
        out.push_str(r#"=""#);
        out.push_str(&escape_html_attr(value));
        out.push('"');
    }
    if is_void_html_tag(tag) {
        out.push('>');
        return out;
    }
    out.push('>');
    out.push_str(&element.html());
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
    out
}

fn serialize_epub_debug_chapter_node(
    node: NodeRef<'_, scraper::node::Node>,
    delete_ruby: bool,
    cover_count: &mut usize,
    out: &mut String,
) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            if tag.eq_ignore_ascii_case("title") {
                return;
            }
            if delete_ruby && (tag.eq_ignore_ascii_case("rp") || tag.eq_ignore_ascii_case("rt")) {
                return;
            }
            if element_ref
                .value()
                .attr("style")
                .map(|style| {
                    let clean = style.to_ascii_lowercase().replace(' ', "");
                    clean.contains("display:none")
                })
                .unwrap_or(false)
            {
                return;
            }
            if tag.eq_ignore_ascii_case("img")
                && element_ref
                    .value()
                    .attr("src")
                    .map(|src| src.eq_ignore_ascii_case("cover.jpeg"))
                    .unwrap_or(false)
            {
                *cover_count += 1;
                if *cover_count > 1 {
                    return;
                }
            }
            out.push('<');
            out.push_str(tag);
            for (name, value) in element.attrs() {
                out.push(' ');
                out.push_str(name);
                out.push_str(r#"=""#);
                out.push_str(&escape_html_attr(value));
                out.push('"');
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            for child in element_ref.children() {
                serialize_epub_debug_chapter_node(child, delete_ruby, cover_count, out);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn rewrite_epub_body_html(html: &str) -> String {
    let mut out = Vec::with_capacity(html.len());
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("[id]", |element| {
                    let tag = element.tag_name();
                    if matches!(tag.as_str(), "aside" | "section" | "div" | "li")
                        && is_likely_footnote_target(
                            element.get_attribute("id").unwrap_or_default().as_str(),
                            element
                                .get_attribute("epub:type")
                                .or_else(|| element.get_attribute("type"))
                                .unwrap_or_default()
                                .as_str(),
                            element.get_attribute("role").unwrap_or_default().as_str(),
                            element.get_attribute("class").unwrap_or_default().as_str(),
                        )
                    {
                        let style = element.get_attribute("style").unwrap_or_default();
                        element.set_attribute("style", &format!("{};display:none", style))?;
                    }
                    Ok(())
                }),
                element!("image", |element| {
                    let src = element
                        .get_attribute("xlink:href")
                        .or_else(|| element.get_attribute("href"))
                        .unwrap_or_default();
                    element.set_tag_name("img")?;
                    if !src.trim().is_empty() {
                        element.set_attribute("src", src.trim())?;
                    }
                    Ok(())
                }),
                element!("body", |element| {
                    if let Some(color_tag) = element
                        .get_attribute("bgcolor")
                        .and_then(|value| to_epub_color_tag(&value))
                        .or_else(|| {
                            let style = element.get_attribute("style").unwrap_or_default();
                            css_declaration_value(&style, "background-color")
                                .and_then(|value| to_epub_color_tag(&value))
                                .or_else(|| {
                                    css_declaration_value(&style, "background")
                                        .and_then(|value| extract_css_color(&value))
                                        .and_then(|value| to_epub_color_tag(&value))
                                })
                        })
                    {
                        element.prepend(
                            &format!(r#"<span data-epub-page-bg="{}"></span>"#, color_tag),
                            lol_html::html_content::ContentType::Html,
                        );
                    }
                    Ok(())
                }),
            ],
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return html.to_string();
    }
    String::from_utf8(out)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

fn remove_page_background_nodes(html: &str) -> String {
    let mut out = Vec::with_capacity(html.len());
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("[data-epub-page-bg]", |element| {
                    element.remove();
                    Ok(())
                }),
                element!("img[data-epub-background=true]", |element| {
                    element.remove();
                    Ok(())
                }),
            ],
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return html.to_string();
    }
    String::from_utf8(out)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

fn page_background_prefix(html: &str) -> String {
    let Some(start) = html.rfind("<span data-epub-page-bg") else {
        return String::new();
    };
    let Some(relative_end) = html[start..].find("</span>") else {
        return String::new();
    };
    html[start..start + relative_end + "</span>".len()].to_string()
}

fn readable_inline_html(element: ElementRef<'_>) -> String {
    let mut builder = String::new();
    for child in element.children() {
        match child.value() {
            Node::Text(text) => builder.push_str(&escape_html_text(text.text.as_ref())),
            Node::Element(_) => {
                let Some(child_element) = ElementRef::wrap(child) else {
                    continue;
                };
                match child_element.value().name() {
                    "br" => builder.push_str("<br>"),
                    "img" => {
                        if child_element
                            .value()
                            .attr("src")
                            .unwrap_or_default()
                            .is_empty()
                        {
                            if let Some(alt) = child_element.value().attr("alt") {
                                if !alt.is_empty() {
                                    builder.push_str(&escape_html_text(alt));
                                }
                            }
                        } else {
                            builder.push_str(&child_element.html());
                        }
                    }
                    "b" | "strong" => {
                        builder.push_str("<b>");
                        builder.push_str(&readable_inline_html(child_element));
                        builder.push_str("</b>");
                    }
                    "i" | "em" => {
                        builder.push_str("<i>");
                        builder.push_str(&readable_inline_html(child_element));
                        builder.push_str("</i>");
                    }
                    "font" => builder.push_str(&child_element.html()),
                    _ => builder.push_str(&readable_inline_html(child_element)),
                }
            }
            _ => {}
        }
    }
    let own = builder.trim().to_string();
    if !own.is_empty() {
        return own;
    }
    normalized_element_text(element.text()).trim().to_string()
}

fn html_align_attr(element: ElementRef<'_>) -> String {
    element_alignment(element.value())
        .map(|align| format!(r#" align="{}""#, align))
        .unwrap_or_default()
}

fn element_has_image(element: ElementRef<'_>) -> bool {
    element.value().name() == "img"
        || element
            .children()
            .filter_map(ElementRef::wrap)
            .any(element_has_image)
}

fn element_has_block_box_descendant(element: ElementRef<'_>) -> bool {
    element
        .children()
        .filter_map(ElementRef::wrap)
        .any(|child| {
            let declarations = css_declarations(child.value().attr("style").unwrap_or_default());
            is_readable_block(child.value().name())
                && declarations_have_block_box_style(&declarations)
                || element_has_block_box_descendant(child)
        })
}

fn render_plan_node(
    node: NodeRef<'_, scraper::node::Node>,
    classic_epub: bool,
    actions: &mut Vec<HtmlRenderActionOutput>,
) {
    match node.value() {
        Node::Text(text) => push_html_action(actions, escape_html_text(text.text.as_ref())),
        Node::Element(_) => {
            let Some(element) = ElementRef::wrap(node) else {
                return;
            };
            render_plan_element(element, classic_epub, actions);
        }
        _ => {}
    }
}

fn render_plan_element(
    element: ElementRef<'_>,
    classic_epub: bool,
    actions: &mut Vec<HtmlRenderActionOutput>,
) {
    let node_html = element.html();
    let flags = html_render_flags_for_element(element);
    let declarations = css_declarations(element.value().attr("style").unwrap_or_default());

    if classic_epub {
        if let Some(page_color) = element
            .value()
            .attr("data-epub-page-bg")
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            push_control_action(actions, "flush");
            actions.push(HtmlRenderActionOutput {
                kind: "pageColor".to_string(),
                page_color: page_color.to_string(),
                ..HtmlRenderActionOutput::default()
            });
            return;
        }
        if flags.page_break_before {
            push_control_action(actions, "flush");
            push_control_action(actions, "pageBreak");
        }
        if flags.is_block && flags.block_spacing_before {
            push_control_action(actions, "flush");
            actions.push(HtmlRenderActionOutput {
                kind: "spacingBefore".to_string(),
                margin_top: css_value_with_shorthand(&declarations, "margin-top")
                    .unwrap_or_default(),
                padding_top: css_value_with_shorthand(&declarations, "padding-top")
                    .unwrap_or_default(),
                ..HtmlRenderActionOutput::default()
            });
        }
    }

    if classic_epub && flags.is_block && flags.has_block_box_style && !flags.has_image {
        push_control_action(actions, "flush");
        actions.push(HtmlRenderActionOutput {
            kind: "blockBox".to_string(),
            html: node_html,
            ..HtmlRenderActionOutput::default()
        });
    } else if flags.tag_name == "table" {
        push_control_action(actions, "flush");
        actions.push(HtmlRenderActionOutput {
            kind: "htmlText".to_string(),
            html: readable_table_element_html(element),
            ..HtmlRenderActionOutput::default()
        });
    } else if flags.tag_name == "img" {
        push_control_action(actions, "flush");
        actions.push(HtmlRenderActionOutput {
            kind: "image".to_string(),
            image: html_image_info_for_element(element),
            ..HtmlRenderActionOutput::default()
        });
    } else if flags.has_image || classic_epub && flags.has_block_box_descendant {
        if flags.is_block {
            push_control_action(actions, "flush");
        }
        for child in element.children() {
            render_plan_node(child, classic_epub, actions);
        }
        if flags.is_block {
            push_html_action(actions, "<br>".to_string());
            push_control_action(actions, "flush");
        }
    } else {
        push_html_action(actions, node_html);
        if flags.is_block {
            push_control_action(actions, "flush");
        }
    }

    if classic_epub {
        if flags.is_block && flags.block_spacing_after {
            push_control_action(actions, "flush");
            actions.push(HtmlRenderActionOutput {
                kind: "spacingAfter".to_string(),
                margin_bottom: css_value_with_shorthand(&declarations, "margin-bottom")
                    .unwrap_or_default(),
                padding_bottom: css_value_with_shorthand(&declarations, "padding-bottom")
                    .unwrap_or_default(),
                ..HtmlRenderActionOutput::default()
            });
        }
        if flags.page_break_after {
            push_control_action(actions, "flush");
            push_control_action(actions, "pageBreak");
        }
    }
}

fn push_html_action(actions: &mut Vec<HtmlRenderActionOutput>, html: String) {
    if html.is_empty() {
        return;
    }
    if let Some(last) = actions.last_mut() {
        if last.kind == "html" {
            last.html.push_str(&html);
            return;
        }
    }
    actions.push(HtmlRenderActionOutput {
        kind: "html".to_string(),
        html,
        ..HtmlRenderActionOutput::default()
    });
}

fn push_control_action(actions: &mut Vec<HtmlRenderActionOutput>, kind: &str) {
    if kind == "flush" && actions.last().is_some_and(|last| last.kind == "flush") {
        return;
    }
    actions.push(HtmlRenderActionOutput {
        kind: kind.to_string(),
        ..HtmlRenderActionOutput::default()
    });
}

fn html_render_flags_for_element(element: ElementRef<'_>) -> HtmlRenderFlagsOutput {
    let declarations = css_declarations(element.value().attr("style").unwrap_or_default());
    HtmlRenderFlagsOutput {
        tag_name: element.value().name().to_string(),
        is_block: is_readable_block(element.value().name()),
        has_image: element_has_image(element),
        has_block_box_style: declarations_have_block_box_style(&declarations),
        has_block_box_descendant: element_has_block_box_descendant(element),
        page_break_before: css_value_with_shorthand(&declarations, "page-break-before")
            .is_some_and(|value| is_epub_always_break(&value))
            || css_value_with_shorthand(&declarations, "break-before")
                .is_some_and(|value| is_epub_always_break(&value)),
        page_break_after: css_value_with_shorthand(&declarations, "page-break-after")
            .is_some_and(|value| is_epub_always_break(&value))
            || css_value_with_shorthand(&declarations, "break-after")
                .is_some_and(|value| is_epub_always_break(&value)),
        block_spacing_before: css_value_with_shorthand(&declarations, "margin-top")
            .is_some_and(|value| is_large_epub_spacing(&value))
            || css_value_with_shorthand(&declarations, "padding-top")
                .is_some_and(|value| is_large_epub_spacing(&value)),
        block_spacing_after: css_value_with_shorthand(&declarations, "margin-bottom")
            .is_some_and(|value| is_large_epub_spacing(&value))
            || css_value_with_shorthand(&declarations, "padding-bottom")
                .is_some_and(|value| is_large_epub_spacing(&value)),
    }
}

fn html_image_info_for_element(element: ElementRef<'_>) -> HtmlImageInfoOutput {
    let style = element.value().attr("style").unwrap_or_default();
    HtmlImageInfoOutput {
        src: element
            .value()
            .attr("src")
            .unwrap_or_default()
            .trim()
            .to_string(),
        is_background: element.value().attr("data-epub-background") == Some("true"),
        style: element
            .value()
            .attr("data-legado-style")
            .unwrap_or_default()
            .trim()
            .to_string(),
        width: element
            .value()
            .attr("data-legado-width")
            .or_else(|| element.value().attr("width"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| css_declaration_value(style, "width"))
            .unwrap_or_default(),
        click: element
            .value()
            .attr("data-legado-click")
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

fn declarations_have_block_box_style(declarations: &[(String, String)]) -> bool {
    declarations.iter().any(|(key, _)| {
        key == "background"
            || key == "background-color"
            || key == "border"
            || key == "border-color"
            || key == "border-width"
            || key == "border-style"
            || key == "border-radius"
            || key.starts_with("border-")
    })
}

fn css_declarations(style: &str) -> Vec<(String, String)> {
    style
        .split(';')
        .filter_map(|declaration| {
            let (key, value) = declaration.split_once(':')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn css_value_with_shorthand(declarations: &[(String, String)], name: &str) -> Option<String> {
    if let Some((_, value)) = declarations.iter().find(|(key, _)| key == name) {
        return Some(value.clone());
    }
    let shorthand = if name.starts_with("margin-") {
        "margin"
    } else if name.starts_with("padding-") {
        "padding"
    } else {
        return None;
    };
    let (_, value) = declarations.iter().find(|(key, _)| key == shorthand)?;
    let values = split_css_value_list(value);
    if values.is_empty() {
        return None;
    }
    let top = values.first().cloned().unwrap_or_default();
    let right = values.get(1).cloned().unwrap_or_else(|| top.clone());
    let bottom = values.get(2).cloned().unwrap_or_else(|| top.clone());
    let left = values.get(3).cloned().unwrap_or_else(|| right.clone());
    match name
        .rsplit_once('-')
        .map(|(_, side)| side)
        .unwrap_or_default()
    {
        "top" => Some(top),
        "right" => Some(right),
        "bottom" => Some(bottom),
        "left" => Some(left),
        _ => None,
    }
}

fn split_css_value_list(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn split_css_component_values(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut quote = None;
    let mut paren_depth = 0usize;
    let mut start = 0usize;
    for (index, ch) in value.char_indices() {
        if let Some(active_quote) = quote {
            if ch == active_quote && !value[..index].ends_with('\\') {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ' ' | '\t' | '\r' | '\n' if paren_depth == 0 => {
                let item = value[start..index].trim();
                if !item.is_empty() {
                    result.push(item.to_string());
                }
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    let item = value[start..].trim();
    if !item.is_empty() {
        result.push(item.to_string());
    }
    result
}

fn is_epub_always_break(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "always" | "page" | "left" | "right"
    )
}

fn is_large_epub_spacing(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || value == "0" {
        return false;
    }
    if let Some(value) = value.strip_suffix("em") {
        return value.parse::<f32>().unwrap_or_default() >= 1.0;
    }
    if let Some(value) = value.strip_suffix("rem") {
        return value.parse::<f32>().unwrap_or_default() >= 1.0;
    }
    if let Some(value) = value.strip_suffix('%') {
        return value.parse::<f32>().unwrap_or_default() >= 8.0;
    }
    if let Some(value) = value.strip_suffix("px") {
        return value.parse::<f32>().unwrap_or_default() >= 16.0;
    }
    value.parse::<f32>().unwrap_or_default() >= 16.0
}

#[derive(Clone, Copy, Debug, Default)]
struct ReadableInlineStyle {
    underline: bool,
    bold: bool,
    italic: bool,
    strike: bool,
    script: i8,
}

struct EpubReadableContext {
    delete_ruby: bool,
    cover_seen: bool,
    lines: Vec<String>,
}

fn walk_epub_readable_node(
    node: ego_tree::NodeRef<'_, Node>,
    context: &mut EpubReadableContext,
    builder: &mut String,
    style: ReadableInlineStyle,
) {
    match node.value() {
        Node::Text(text) => append_readable_text(builder, text.text.as_ref(), style),
        Node::Element(_) => {
            let Some(element) = ElementRef::wrap(node) else {
                return;
            };
            walk_epub_readable_element(element, context, builder, style);
        }
        _ => {}
    }
}

fn walk_epub_readable_element(
    element: ElementRef<'_>,
    context: &mut EpubReadableContext,
    builder: &mut String,
    parent_style: ReadableInlineStyle,
) {
    let name = element.value().name();
    if matches!(name, "title" | "script" | "style") {
        return;
    }
    if context.delete_ruby && matches!(name, "rp" | "rt") {
        return;
    }
    if is_display_none(element.value().attr("style").unwrap_or_default())
        || element.value().attr("data-epub-page-bg").is_some()
        || (name == "img" && element.value().attr("data-epub-background") == Some("true"))
    {
        return;
    }
    if name == "img" && element.value().attr("src") == Some("cover.jpeg") {
        if context.cover_seen {
            return;
        }
        context.cover_seen = true;
    }

    let style = readable_inline_style(element, parent_style);
    match name {
        "br" => push_readable_line(&mut context.lines, builder),
        "img" => {
            push_readable_line(&mut context.lines, builder);
            let src = element.value().attr("src").unwrap_or_default().trim();
            if !src.is_empty() {
                context
                    .lines
                    .push(format!(r#"<img src="{}">"#, escape_html_attr(src)));
            }
        }
        _ => {
            let is_block = is_readable_block(name);
            if is_block && !builder.trim().is_empty() {
                push_readable_line(&mut context.lines, builder);
            }
            for child in element.children() {
                walk_epub_readable_node(child, context, builder, style);
            }
            if is_block {
                push_readable_line(&mut context.lines, builder);
            }
        }
    }
}

fn readable_inline_style(
    element: ElementRef<'_>,
    parent: ReadableInlineStyle,
) -> ReadableInlineStyle {
    let tag = element.value().name();
    let style = element.value().attr("style").unwrap_or_default();
    let text_decoration = [
        css_declaration_value(style, "text-decoration"),
        css_declaration_value(style, "text-decoration-line"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    let font_weight = css_declaration_value(style, "font-weight")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let font_style = css_declaration_value(style, "font-style")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let vertical_align = css_declaration_value(style, "vertical-align")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let css_bold = font_weight == "bold"
        || font_weight
            .parse::<i32>()
            .map(|weight| weight >= 600)
            .unwrap_or(false);
    let script = if tag == "sup" || vertical_align == "super" || vertical_align == "sup" {
        1
    } else if tag == "sub" || vertical_align == "sub" {
        -1
    } else {
        parent.script
    };
    ReadableInlineStyle {
        underline: parent.underline || tag == "u" || text_decoration.contains("underline"),
        bold: parent.bold || tag == "b" || tag == "strong" || css_bold,
        italic: parent.italic
            || tag == "i"
            || tag == "em"
            || font_style == "italic"
            || font_style == "oblique",
        strike: parent.strike
            || matches!(tag, "s" | "del" | "strike")
            || text_decoration.contains("line-through"),
        script,
    }
}

fn append_readable_text(builder: &mut String, value: &str, style: ReadableInlineStyle) {
    let normalized = Regex::new(r"\s+")
        .expect("static whitespace regex")
        .replace_all(&value.replace('\u{E10C}', ""), " ")
        .to_string();
    if normalized.trim().is_empty() {
        return;
    }
    if !builder.is_empty() && !builder.ends_with(' ') && !normalized.starts_with(' ') {
        builder.push(' ');
    }
    append_readable_style_start(builder, style);
    builder.push_str(&normalized);
    append_readable_style_end(builder, style);
}

fn append_readable_style_start(builder: &mut String, style: ReadableInlineStyle) {
    if style.bold {
        builder.push('\u{E10C}');
        builder.push('B');
    }
    if style.italic {
        builder.push('\u{E10C}');
        builder.push('I');
    }
    if style.underline {
        builder.push('\u{E10C}');
        builder.push('U');
    }
    if style.strike {
        builder.push('\u{E10C}');
        builder.push('S');
    }
    if style.script > 0 {
        builder.push('\u{E10C}');
        builder.push('P');
    }
    if style.script < 0 {
        builder.push('\u{E10C}');
        builder.push('D');
    }
}

fn append_readable_style_end(builder: &mut String, style: ReadableInlineStyle) {
    if style.script < 0 {
        builder.push('\u{E10C}');
        builder.push('d');
    }
    if style.script > 0 {
        builder.push('\u{E10C}');
        builder.push('p');
    }
    if style.strike {
        builder.push('\u{E10C}');
        builder.push('s');
    }
    if style.underline {
        builder.push('\u{E10C}');
        builder.push('u');
    }
    if style.italic {
        builder.push('\u{E10C}');
        builder.push('i');
    }
    if style.bold {
        builder.push('\u{E10C}');
        builder.push('b');
    }
}

fn push_readable_line(lines: &mut Vec<String>, builder: &mut String) {
    let line = builder.trim();
    if !line.is_empty() {
        lines.push(line.to_string());
    }
    builder.clear();
}

fn is_display_none(style: &str) -> bool {
    style
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
        .contains("display:none")
}

fn epub_image_options_from_element(
    element: &lol_html::html_content::Element<'_, '_>,
) -> EpubImageOptionsOutput {
    let style_attr = element.get_attribute("style").unwrap_or_default();
    let width = element
        .get_attribute("data-legado-width")
        .or_else(|| element.get_attribute("width"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .and_then(|value| normalize_epub_image_width(&value))
        .or_else(|| {
            css_declaration_value(&style_attr, "width")
                .and_then(|value| normalize_epub_image_width(&value))
        })
        .unwrap_or_default();
    let height = element
        .get_attribute("data-legado-height")
        .or_else(|| element.get_attribute("height"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .and_then(|value| normalize_epub_image_length(&value))
        .or_else(|| {
            css_declaration_value(&style_attr, "height")
                .and_then(|value| normalize_epub_image_length(&value))
        })
        .unwrap_or_default();
    let mut style = element
        .get_attribute("data-legado-style")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut width = width;
    if element.get_attribute("data-epub-single-page").as_deref() == Some("true") {
        style = "SINGLE".to_string();
        if width.is_empty() {
            width = "100%".to_string();
        }
    } else if style.is_empty() && is_inline_epub_image_width(&width) {
        style = "text".to_string();
    }
    EpubImageOptionsOutput {
        src: first_element_attr(
            element,
            &[
                "src",
                "data-src",
                "data-original",
                "data-lazy-src",
                "data-url",
                "xlink:href",
                "href",
            ],
        ),
        alt: element
            .get_attribute("alt")
            .unwrap_or_default()
            .trim()
            .to_string(),
        is_background: element.get_attribute("data-epub-background").as_deref() == Some("true"),
        width,
        height,
        style,
    }
}

fn first_element_attr(element: &lol_html::html_content::Element<'_, '_>, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| element.get_attribute(name))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn materialized_epub_image_html(resolved_href: &str, image: &EpubImageOptionsOutput) -> String {
    let mut attrs = vec![format!(r#"src="{}""#, escape_html_attr(resolved_href))];
    if image.is_background {
        attrs.push(r#"data-epub-background="true""#.to_string());
    }
    if !image.alt.is_empty() {
        attrs.push(format!(r#"alt="{}""#, escape_html_attr(&image.alt)));
    }
    if !image.width.is_empty() {
        attrs.push(format!(
            r#"data-legado-width="{}""#,
            escape_html_attr(&image.width)
        ));
    }
    if !image.style.is_empty() {
        attrs.push(format!(
            r#"data-legado-style="{}""#,
            escape_html_attr(&image.style)
        ));
    }
    let mut options = Vec::new();
    if !image.width.is_empty() {
        options.push(("width", image.width.as_str()));
    }
    if !image.height.is_empty() {
        options.push(("height", image.height.as_str()));
    }
    if !image.style.is_empty() {
        options.push(("style", image.style.as_str()));
    }
    if !image.is_background && !options.is_empty() {
        let src = format!("{resolved_href},{}", epub_image_options_json(&options));
        attrs[0] = format!(r#"src="{}""#, escape_html_attr(&src));
    }
    format!("<img {}>", attrs.join(" "))
}

fn epub_image_options_json(options: &[(&str, &str)]) -> String {
    let body = options
        .iter()
        .map(|(key, value)| {
            format!(
                r#""{}":"{}""#,
                escape_json_string(key),
                escape_json_string(value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

fn css_declaration_value(style: &str, name: &str) -> Option<String> {
    for declaration in style.split(';') {
        let Some((key, value)) = declaration.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn css_declaration_map(style: &str) -> std::collections::HashMap<String, String> {
    let mut declarations = std::collections::HashMap::new();
    for declaration in style.split(';') {
        let Some((key, value)) = declaration.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if !key.is_empty() {
            declarations.insert(key, value.trim().to_string());
        }
    }
    declarations
}

fn ordered_css_declarations(style: &str) -> Vec<(String, String)> {
    let mut declarations = Vec::<(String, String)>::new();
    for declaration in split_css_declarations(style) {
        let Some((name, value)) = declaration.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().replace('"', "'");
        if name.is_empty() || value.is_empty() {
            continue;
        }
        if let Some(existing) = declarations
            .iter_mut()
            .find(|(existing_name, _)| existing_name == &name)
        {
            existing.1 = value;
        } else {
            declarations.push((name, value));
        }
    }
    declarations
}

fn split_css_declarations(style: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut quote = None;
    let mut paren_depth = 0usize;
    let mut start = 0usize;
    for (index, ch) in style.char_indices() {
        if let Some(active_quote) = quote {
            if ch == active_quote && !style[..index].ends_with('\\') {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ';' if paren_depth == 0 => {
                result.push(&style[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    if start < style.len() {
        result.push(&style[start..]);
    }
    result
}

fn merge_epub_inherited_style(
    own_style: &[(String, String)],
    parent_style: &[(String, String)],
) -> (Vec<(String, String)>, bool) {
    let mut merged = own_style.to_vec();
    let mut changed = false;
    for (name, value) in parent_style {
        if is_epub_inheritable_style(name) && !merged.iter().any(|(own_name, _)| own_name == name) {
            merged.push((name.clone(), value.clone()));
            changed = true;
        }
    }
    (merged, changed)
}

fn inherited_css_declarations(style: &[(String, String)]) -> Vec<(String, String)> {
    style
        .iter()
        .filter(|(name, _)| is_epub_inheritable_style(name))
        .cloned()
        .collect()
}

fn is_epub_inheritable_style(name: &str) -> bool {
    matches!(
        name,
        "color"
            | "font-family"
            | "font-size"
            | "font-style"
            | "font-weight"
            | "line-height"
            | "text-align"
            | "text-decoration"
            | "text-indent"
    )
}

fn css_declarations_to_style(declarations: &[(String, String)]) -> String {
    declarations
        .iter()
        .map(|(name, value)| format!("{name}:{value}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn extract_css_url(value: &str) -> Option<String> {
    let start = value.to_ascii_lowercase().find("url(")?;
    let value_start = start + 4;
    let end = value[value_start..].find(')')? + value_start;
    Some(value[value_start..end].trim().to_string())
}

fn trim_matching_quote(value: &str) -> String {
    let clean = value.trim();
    if clean.len() >= 2 {
        let first = clean.as_bytes()[0];
        let last = clean.as_bytes()[clean.len() - 1];
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return clean[1..clean.len() - 1].to_string();
        }
    }
    clean.to_string()
}

fn first_attr(element: ElementRef<'_>, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| element.value().attr(name))
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[derive(Debug, Clone, Copy, Default)]
struct EpubImagePageInfo {
    mark_single: bool,
    mark_overlay: bool,
    mark_gallery: bool,
    duokan_gallery: bool,
}

fn analyze_epub_image_page(html: &str) -> EpubImagePageInfo {
    let document = Html::parse_fragment(html);
    let root = document.root_element();
    let img_selector = Selector::parse("img").expect("static img selector");
    let images = document.select(&img_selector).collect::<Vec<_>>();
    let text = clean_epub_info_text(&root.text().collect::<Vec<_>>().join(" "));
    if images.len() == 1 && text.is_empty() {
        return EpubImagePageInfo {
            mark_single: true,
            ..EpubImagePageInfo::default()
        };
    }
    let mark_overlay = images.len() == 1
        && images
            .first()
            .and_then(|image| image.value().attr("data-epub-background"))
            != Some("true")
        && !text.is_empty()
        && text.chars().count() <= 80
        && first_content_element_has_first_image(root)
        && selector_has_match(&document, "h1,h2,h3,h4,h5,h6,table,.vol-title");
    if mark_overlay {
        return EpubImagePageInfo {
            mark_overlay: true,
            ..EpubImagePageInfo::default()
        };
    }
    let foreground_images = images
        .iter()
        .filter(|image| image.value().attr("data-epub-background") != Some("true"))
        .count();
    if foreground_images < 2 {
        return EpubImagePageInfo::default();
    }
    let duokan_gallery = selector_has_match(&document, ".duokan-image-gallery-cell");
    if duokan_gallery || text.chars().count() <= 120 {
        return EpubImagePageInfo {
            mark_gallery: true,
            duokan_gallery,
            ..EpubImagePageInfo::default()
        };
    }
    EpubImagePageInfo::default()
}

fn first_content_element_has_first_image(root: ElementRef<'_>) -> bool {
    let first = root.children().filter_map(ElementRef::wrap).find(|child| {
        !matches!(
            child.value().name(),
            "style" | "link" | "script" | "html" | "head"
        )
    });
    let Some(first) = first else {
        return false;
    };
    if first.value().name() == "body" {
        return first_content_element_has_first_image(first);
    }
    first.value().name() == "img" || element_first_image(first).is_some()
}

fn element_first_image(element: ElementRef<'_>) -> Option<ElementRef<'_>> {
    if element.value().name() == "img" {
        return Some(element);
    }
    element
        .children()
        .filter_map(ElementRef::wrap)
        .find_map(element_first_image)
}

fn selector_has_match(document: &Html, selector: &str) -> bool {
    Selector::parse(selector)
        .ok()
        .and_then(|selector| document.select(&selector).next())
        .is_some()
}

fn serialize_epub_media_node(
    node: NodeRef<'_, scraper::node::Node>,
    base_href: &str,
    out: &mut String,
) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            if is_epub_media_tag(tag) {
                out.push_str(&epub_media_placeholder_html(element_ref, base_href));
                return;
            }
            out.push('<');
            out.push_str(tag);
            for (name, value) in element.attrs() {
                out.push(' ');
                out.push_str(name);
                out.push_str("=\"");
                out.push_str(&escape_html_attr(value));
                out.push('"');
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            for child in element_ref.children() {
                serialize_epub_media_node(child, base_href, out);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn epub_media_placeholder_html(element: ElementRef<'_>, base_href: &str) -> String {
    let tag = element.value().name();
    let src = first_attr(element, &["src", "href", "data"])
        .if_blank(|| {
            let selector = Selector::parse("source[src]").expect("static source selector");
            element
                .select(&selector)
                .next()
                .and_then(|source| source.value().attr("src"))
                .unwrap_or_default()
                .trim()
                .to_string()
        })
        .trim()
        .to_string();
    let resolved_href = if src.is_empty() {
        String::new()
    } else {
        resolve_epub_href(base_href, &src)
    };
    let label = if tag.eq_ignore_ascii_case("audio") {
        "EPUB音频"
    } else {
        "EPUB视频"
    };
    let title = element
        .value()
        .attr("title")
        .or_else(|| element.value().attr("alt"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            resolved_href
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or(label)
                .to_string()
        });
    let href = if resolved_href.is_empty() {
        "legado-epub-media:missing".to_string()
    } else {
        format!(
            "legado-epub-media:{}",
            encode_uri_component_like_android(&resolved_href)
        )
    };
    format!(
        r#"<p class="epub-media-placeholder" style="margin:1em 5%;padding:0.8em;text-align:center;background:rgba(68,150,211,0.12);border:1px solid rgba(68,150,211,0.55);border-radius:8px;color:#225577"><a href="{}">[{}] {}</a></p>"#,
        escape_html_attr(&href),
        label,
        escape_html_text(&title)
    )
}

fn serialize_epub_inline_style_node(node: NodeRef<'_, scraper::node::Node>, out: &mut String) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            let mut inner = String::new();
            if !is_void_html_tag(tag) {
                for child in element_ref.children() {
                    serialize_epub_inline_style_node(child, &mut inner);
                }
            }
            let style = element_ref.value().attr("style").unwrap_or_default();
            let mut attrs = element
                .attrs()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<Vec<_>>();
            let Some(inner) = apply_epub_inline_style_to_inner(tag, style, inner, Some(&mut attrs))
            else {
                return;
            };
            out.push('<');
            out.push_str(tag);
            for (name, value) in attrs {
                out.push(' ');
                out.push_str(&name);
                out.push_str("=\"");
                out.push_str(&escape_html_attr(&value));
                out.push('"');
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            out.push_str(&inner);
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn serialize_epub_inherited_style_node(
    node: NodeRef<'_, scraper::node::Node>,
    parent_style: &[(String, String)],
    out: &mut String,
) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            let own_style =
                ordered_css_declarations(element_ref.value().attr("style").unwrap_or_default());
            let (merged_style, changed) = merge_epub_inherited_style(&own_style, parent_style);
            let next_style = inherited_css_declarations(&merged_style);

            out.push('<');
            out.push_str(tag);
            let mut wrote_style = false;
            for (name, value) in element.attrs() {
                if name.eq_ignore_ascii_case("style") {
                    wrote_style = true;
                    if changed {
                        let style = css_declarations_to_style(&merged_style);
                        if !style.is_empty() {
                            out.push_str(r#" style=""#);
                            out.push_str(&escape_html_attr(&style));
                            out.push('"');
                        }
                    } else {
                        out.push_str(r#" style=""#);
                        out.push_str(&escape_html_attr(value));
                        out.push('"');
                    }
                } else {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str(r#"=""#);
                    out.push_str(&escape_html_attr(value));
                    out.push('"');
                }
            }
            if !wrote_style && changed {
                let style = css_declarations_to_style(&merged_style);
                if !style.is_empty() {
                    out.push_str(r#" style=""#);
                    out.push_str(&escape_html_attr(&style));
                    out.push('"');
                }
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            for child in element_ref.children() {
                serialize_epub_inherited_style_node(child, &next_style, out);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn serialize_epub_generated_content_children(
    element_ref: ElementRef<'_>,
    rules: &[EpubCompiledGeneratedContentRule],
    out: &mut String,
) {
    append_epub_generated_content(element_ref, rules, true, out);
    for child in element_ref.children() {
        serialize_epub_generated_content_node(child, rules, out);
    }
    append_epub_generated_content(element_ref, rules, false, out);
}

fn serialize_epub_generated_content_node(
    node: NodeRef<'_, scraper::node::Node>,
    rules: &[EpubCompiledGeneratedContentRule],
    out: &mut String,
) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            out.push('<');
            out.push_str(tag);
            for (name, value) in element.attrs() {
                out.push(' ');
                out.push_str(name);
                out.push_str(r#"=""#);
                out.push_str(&escape_html_attr(value));
                out.push('"');
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            serialize_epub_generated_content_children(element_ref, rules, out);
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn append_epub_generated_content(
    element_ref: ElementRef<'_>,
    rules: &[EpubCompiledGeneratedContentRule],
    before: bool,
    out: &mut String,
) {
    for rule in rules {
        if rule.before != before || !rule.selector.matches(&element_ref) {
            continue;
        }
        let Some(content) = epub_generated_content_text(&rule.declarations, element_ref) else {
            continue;
        };
        out.push_str(r#"<span data-epub-generated="true""#);
        if !rule.style.is_empty() {
            out.push_str(r#" style=""#);
            out.push_str(&escape_html_attr(&rule.style));
            out.push('"');
        }
        out.push('>');
        out.push_str(&escape_html_text(&content));
        out.push_str("</span>");
    }
}

fn epub_generated_content_text(
    declarations: &[EpubGeneratedContentDeclarationInput],
    element_ref: ElementRef<'_>,
) -> Option<String> {
    let value = declarations
        .iter()
        .rev()
        .find(|declaration| declaration.name.eq_ignore_ascii_case("content"))?
        .value
        .trim();
    if value.eq_ignore_ascii_case("none") || value.eq_ignore_ascii_case("normal") {
        return None;
    }
    let mut counter_fallback = 1usize;
    let content = split_css_component_values(value)
        .into_iter()
        .map(|token| {
            let clean = token.trim();
            if clean.len() >= 2
                && ((clean.starts_with('\'') && clean.ends_with('\''))
                    || (clean.starts_with('"') && clean.ends_with('"')))
            {
                clean[1..clean.len() - 1].to_string()
            } else if clean.eq_ignore_ascii_case("open-quote") {
                "“".to_string()
            } else if clean.eq_ignore_ascii_case("close-quote") {
                "”".to_string()
            } else if clean.eq_ignore_ascii_case("no-open-quote")
                || clean.eq_ignore_ascii_case("no-close-quote")
            {
                String::new()
            } else if clean.to_ascii_lowercase().starts_with("counter(")
                || clean.to_ascii_lowercase().starts_with("counters(")
            {
                let value = counter_fallback.to_string();
                counter_fallback += 1;
                value
            } else if clean.to_ascii_lowercase().starts_with("attr(") && clean.ends_with(')') {
                let name = clean
                    .split_once('(')
                    .map(|(_, rest)| rest.trim_end_matches(')').trim())
                    .unwrap_or_default();
                element_ref
                    .value()
                    .attr(name)
                    .unwrap_or_default()
                    .to_string()
            } else {
                String::new()
            }
        })
        .collect::<String>()
        .replace("\\A", "\n")
        .replace("\\a", "\n");
    (!content.is_empty()).then_some(content)
}

fn serialize_epub_resolved_link_node(
    node: NodeRef<'_, scraper::node::Node>,
    base_href: &str,
    out: &mut String,
) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            out.push('<');
            out.push_str(tag);
            for (name, value) in element.attrs() {
                out.push(' ');
                out.push_str(name);
                out.push_str("=\"");
                let resolved;
                let attr_value = if tag.eq_ignore_ascii_case("a")
                    && name.eq_ignore_ascii_case("href")
                    && !value.trim().is_empty()
                    && !value.trim().starts_with('#')
                {
                    resolved = resolve_epub_href(base_href, value);
                    resolved.as_str()
                } else {
                    value
                };
                out.push_str(&escape_html_attr(attr_value));
                out.push('"');
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            for child in element_ref.children() {
                serialize_epub_resolved_link_node(child, base_href, out);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn apply_epub_inline_style_to_inner(
    tag: &str,
    style: &str,
    mut inner: String,
    mut attrs: Option<&mut Vec<(String, String)>>,
) -> Option<String> {
    if style.trim().is_empty() {
        return Some(inner);
    }
    let declarations = css_declaration_map(style);
    if let Some(align) = declarations
        .get("text-align")
        .map(|value| value.to_ascii_lowercase())
    {
        if matches!(align.as_str(), "center" | "left" | "right") {
            if let Some(attrs) = attrs.as_mut() {
                set_html_attr(attrs, "align", &align);
            }
        }
    }
    if let Some(color) = declarations
        .get("color")
        .and_then(|value| to_html_color_attr(value))
    {
        if tag.eq_ignore_ascii_case("font") {
            if let Some(attrs) = attrs.as_mut() {
                set_html_attr(attrs, "color", &color);
            }
        } else {
            inner = wrap_inner_html(tag, inner, "font", &format!(" color=\"{color}\""));
        }
    }
    if declarations
        .get("font-weight")
        .map(|weight| {
            let normalized = weight.to_ascii_lowercase();
            normalized == "bold"
                || normalized
                    .parse::<i32>()
                    .map(|weight| weight >= 600)
                    .unwrap_or(false)
        })
        .unwrap_or(false)
    {
        inner = wrap_inner_html(tag, inner, "b", "");
    }
    if declarations
        .get("font-style")
        .map(|style| style.eq_ignore_ascii_case("italic") || style.eq_ignore_ascii_case("oblique"))
        .unwrap_or(false)
    {
        inner = wrap_inner_html(tag, inner, "i", "");
    }
    if let Some(decoration) = declarations
        .get("text-decoration")
        .map(|value| value.to_ascii_lowercase())
    {
        if decoration.contains("underline") {
            inner = wrap_inner_html(tag, inner, "u", "");
        }
        if decoration.contains("line-through") {
            inner = wrap_inner_html(tag, inner, "strike", "");
        }
    }
    if declarations
        .get("display")
        .map(|display| display.eq_ignore_ascii_case("none"))
        .unwrap_or(false)
    {
        return None;
    }
    let use_block_decoration = is_epub_decorated_block(tag, &declarations);
    let background_color = declarations
        .get("background-color")
        .and_then(|value| to_epub_color_tag(value))
        .or_else(|| {
            declarations
                .get("background")
                .and_then(|value| extract_css_color(value))
                .and_then(|value| to_epub_color_tag(&value))
        });
    if !tag.eq_ignore_ascii_case("body") && !use_block_decoration {
        if let Some(color_tag) = background_color {
            inner = wrap_inner_html(tag, inner, &format!("epubbg{color_tag}"), "");
        }
        if let Some(color_tag) = declarations
            .get("border")
            .and_then(|value| extract_css_color(value))
            .and_then(|value| to_epub_color_tag(&value))
        {
            inner = wrap_inner_html(tag, inner, &format!("epubbg{color_tag}"), "");
        }
    }
    if let Some(size) = declarations
        .get("font-size")
        .map(|value| value.trim().to_ascii_lowercase())
    {
        let numeric_percent = size
            .strip_suffix('%')
            .and_then(|value| value.parse::<f32>().ok());
        let numeric_em = size
            .strip_suffix("em")
            .and_then(|value| value.parse::<f32>().ok());
        if size.contains("small")
            || size.ends_with("smaller")
            || numeric_percent.map(|value| value < 90.0).unwrap_or(false)
            || numeric_em.map(|value| value < 0.9).unwrap_or(false)
        {
            inner = wrap_inner_html(tag, inner, "small", "");
        } else if size.contains("large")
            || numeric_percent.map(|value| value > 110.0).unwrap_or(false)
            || numeric_em.map(|value| value > 1.1).unwrap_or(false)
        {
            inner = wrap_inner_html(tag, inner, "big", "");
        }
    }
    Some(inner)
}

fn set_html_attr(attrs: &mut Vec<(String, String)>, name: &str, value: &str) {
    if let Some((_, existing)) = attrs
        .iter_mut()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
    {
        *existing = value.to_string();
    } else {
        attrs.push((name.to_string(), value.to_string()));
    }
}

fn wrap_inner_html(current_tag: &str, inner: String, tag: &str, attrs: &str) -> String {
    if current_tag.eq_ignore_ascii_case(tag) || inner.trim().is_empty() {
        return inner;
    }
    format!("<{tag}{attrs}>{inner}</{tag}>")
}

fn is_epub_decorated_block(
    tag: &str,
    declarations: &std::collections::HashMap<String, String>,
) -> bool {
    let is_block = matches!(
        tag,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "body"
            | "dd"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "td"
            | "th"
            | "tr"
            | "ul"
    );
    is_block
        && (declarations.contains_key("border")
            || declarations.contains_key("border-color")
            || declarations.contains_key("border-radius")
            || declarations.contains_key("padding")
            || declarations.keys().any(|key| key.starts_with("padding-")))
}

fn is_epub_media_tag(tag: &str) -> bool {
    matches!(
        tag,
        "video" | "audio" | "source" | "iframe" | "embed" | "object"
    )
}

fn is_void_html_tag(tag: &str) -> bool {
    matches!(
        tag,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn resolve_epub_href(base_href: &str, href: &str) -> String {
    let href = href.trim();
    if href.is_empty()
        || href.starts_with("data:")
        || href.starts_with("http://")
        || href.starts_with("https://")
        || href.starts_with("legado-epub-media:")
    {
        return href.to_string();
    }
    let mut parts = Vec::new();
    if !href.starts_with('/') {
        if let Some((dir, _)) = base_href.rsplit_once('/') {
            for part in dir.split('/') {
                if !part.is_empty() {
                    parts.push(part.to_string());
                }
            }
        }
    }
    for part in href.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value.to_string()),
        }
    }
    percent_decode_str(&parts.join("/"))
        .decode_utf8_lossy()
        .into_owned()
}

fn build_epub_native_dom_node(
    node: NodeRef<'_, Node>,
    parent_style: &EpubNativeComputedStyleOutput,
    rules: &[EpubCompiledNativeCssRule],
    base_href: &str,
    source_path: &str,
) -> Option<EpubNativeDomNodeOutput> {
    match node.value() {
        Node::Text(text) => Some(EpubNativeDomNodeOutput {
            kind: "text".to_string(),
            text: text.text.to_string(),
            source_path: source_path.to_string(),
            ..EpubNativeDomNodeOutput::default()
        }),
        Node::Element(_) => ElementRef::wrap(node).map(|element| {
            build_epub_native_dom_element(element, parent_style, rules, base_href, source_path)
        }),
        _ => None,
    }
}

fn serialize_epub_applied_css_body(
    body: ElementRef<'_>,
    rules: &[EpubCompiledNativeCssRule],
) -> EpubAppliedCssOutput {
    let body_style = merged_epub_css_style(body, rules)
        .unwrap_or_else(|| body.value().attr("style").unwrap_or_default().to_string());
    let mut html = String::new();
    for child in body.children() {
        serialize_epub_applied_css_node(child, rules, &mut html);
    }
    EpubAppliedCssOutput {
        html,
        body_style,
        body_background: body
            .value()
            .attr("background")
            .unwrap_or_default()
            .to_string(),
    }
}

fn serialize_epub_applied_css_node(
    node: NodeRef<'_, Node>,
    rules: &[EpubCompiledNativeCssRule],
    out: &mut String,
) {
    match node.value() {
        Node::Text(text) => out.push_str(&escape_html_text(text.text.as_ref())),
        Node::Element(element) => {
            let Some(element_ref) = ElementRef::wrap(node) else {
                return;
            };
            let tag = element.name();
            let merged_style = merged_epub_css_style(element_ref, rules);
            out.push('<');
            out.push_str(tag);
            let mut wrote_style = false;
            for (name, value) in element.attrs() {
                if name.eq_ignore_ascii_case("style") {
                    wrote_style = true;
                    if let Some(style) = &merged_style {
                        if !style.is_empty() {
                            out.push_str(r#" style=""#);
                            out.push_str(&escape_html_attr(style));
                            out.push('"');
                        }
                    } else {
                        out.push_str(r#" style=""#);
                        out.push_str(&escape_html_attr(value));
                        out.push('"');
                    }
                } else {
                    out.push(' ');
                    out.push_str(name);
                    out.push_str(r#"=""#);
                    out.push_str(&escape_html_attr(value));
                    out.push('"');
                }
            }
            if !wrote_style {
                if let Some(style) = &merged_style {
                    if !style.is_empty() {
                        out.push_str(r#" style=""#);
                        out.push_str(&escape_html_attr(style));
                        out.push('"');
                    }
                }
            }
            if is_void_html_tag(tag) {
                out.push('>');
                return;
            }
            out.push('>');
            for child in element_ref.children() {
                serialize_epub_applied_css_node(child, rules, out);
            }
            out.push_str("</");
            out.push_str(tag);
            out.push('>');
        }
        _ => {}
    }
}

fn merged_epub_css_style(
    element: ElementRef<'_>,
    rules: &[EpubCompiledNativeCssRule],
) -> Option<String> {
    let matched_rules = rules
        .iter()
        .filter(|rule| rule.selector.matches(&element))
        .collect::<Vec<_>>();
    if matched_rules.is_empty() {
        return None;
    }
    let mut merged = BTreeMap::<String, EpubNativeStyleValueOutput>::new();
    for rule in matched_rules {
        for declaration in &rule.declarations {
            put_epub_native_declaration(
                &mut merged,
                declaration.clone(),
                0,
                rule.specificity,
                rule.order,
            );
        }
    }
    for declaration in
        parse_epub_native_inline_declarations(element.value().attr("style").unwrap_or_default())
    {
        put_epub_native_declaration(&mut merged, declaration, 1, 1000, i32::MAX);
    }
    Some(epub_native_style_to_css(&merged))
}

fn epub_native_style_to_css(declarations: &BTreeMap<String, EpubNativeStyleValueOutput>) -> String {
    declarations
        .iter()
        .map(|(name, value)| {
            if value.important {
                format!("{name}:{} !important", value.value)
            } else {
                format!("{name}:{}", value.value)
            }
        })
        .collect::<Vec<_>>()
        .join(";")
}

fn build_epub_native_dom_element(
    element: ElementRef<'_>,
    parent_style: &EpubNativeComputedStyleOutput,
    rules: &[EpubCompiledNativeCssRule],
    base_href: &str,
    source_path: &str,
) -> EpubNativeDomNodeOutput {
    let tag_name = element.value().name().to_ascii_lowercase();
    let style = compute_epub_native_style(element, parent_style, rules, base_href);
    let attributes = element
        .value()
        .attrs()
        .map(|(name, value)| {
            let resolved = match name.to_ascii_lowercase().as_str() {
                "src" | "href" | "xlink:href" if !value.trim().is_empty() => {
                    resolve_epub_href(base_href, value)
                }
                _ => value.to_string(),
            };
            (name.to_string(), resolved)
        })
        .collect::<BTreeMap<_, _>>();
    if tag_name == "ruby" {
        return EpubNativeDomNodeOutput {
            kind: "element".to_string(),
            tag_name: "span".to_string(),
            attributes,
            style,
            children: vec![EpubNativeDomNodeOutput {
                kind: "text".to_string(),
                text: epub_native_ruby_fallback_text(element),
                source_path: source_path.to_string(),
                ..EpubNativeDomNodeOutput::default()
            }],
            source_path: source_path.to_string(),
            ..EpubNativeDomNodeOutput::default()
        };
    }
    let child_parent_style = epub_native_inherited_only(&style);
    let children = element
        .children()
        .enumerate()
        .filter_map(|(index, child)| {
            build_epub_native_dom_node(
                child,
                &child_parent_style,
                rules,
                base_href,
                &format!("{source_path}/{tag_name}[{index}]"),
            )
        })
        .collect::<Vec<_>>();
    EpubNativeDomNodeOutput {
        kind: "element".to_string(),
        tag_name,
        attributes,
        style,
        children,
        source_path: source_path.to_string(),
        ..EpubNativeDomNodeOutput::default()
    }
}

fn compute_epub_native_style(
    element: ElementRef<'_>,
    parent_style: &EpubNativeComputedStyleOutput,
    rules: &[EpubCompiledNativeCssRule],
    base_href: &str,
) -> EpubNativeComputedStyleOutput {
    let mut merged = parent_style.declarations.clone();
    for declaration in epub_native_tag_default_declarations(element) {
        put_epub_native_declaration(&mut merged, declaration, -1, 0, -1);
    }
    if let Some(align) = element
        .value()
        .attr("align")
        .and_then(|value| normalize_epub_text_align(value.trim()))
    {
        put_epub_native_declaration(
            &mut merged,
            EpubNativeCssDeclarationInput {
                name: "text-align".to_string(),
                value: align.to_string(),
                important: false,
                order: -1,
            },
            -1,
            0,
            -1,
        );
    }
    for rule in rules {
        if rule.selector.matches(&element) {
            for declaration in &rule.declarations {
                put_epub_native_declaration(
                    &mut merged,
                    declaration.clone(),
                    0,
                    rule.specificity,
                    rule.order,
                );
            }
        }
    }
    for declaration in
        parse_epub_native_inline_declarations(element.value().attr("style").unwrap_or_default())
    {
        put_epub_native_declaration(&mut merged, declaration, 1, 1000, i32::MAX);
    }
    normalize_epub_native_vertical_writing_fallback(&mut merged);
    normalize_epub_native_relative_font_size(&mut merged, parent_style);
    resolve_epub_native_background_urls(&mut merged, base_href);
    EpubNativeComputedStyleOutput {
        declarations: merged,
    }
}

fn put_epub_native_declaration(
    merged: &mut BTreeMap<String, EpubNativeStyleValueOutput>,
    declaration: EpubNativeCssDeclarationInput,
    source_rank: i32,
    specificity: i32,
    rule_order: i32,
) {
    let name = declaration.name.trim().to_ascii_lowercase();
    if name.is_empty() {
        return;
    }
    let value = EpubNativeStyleValueOutput {
        value: declaration.value,
        important: declaration.important,
        source_rank: source_rank + if declaration.important { 2 } else { 0 },
        specificity,
        rule_order,
        declaration_order: declaration.order,
    };
    let replace = merged
        .get(&name)
        .map(|current| epub_native_style_priority(&value) > epub_native_style_priority(current))
        .unwrap_or(true);
    if replace {
        merged.insert(name, value);
    }
}

fn epub_native_style_priority(value: &EpubNativeStyleValueOutput) -> (i32, i32, i32, i32) {
    (
        value.source_rank,
        value.specificity,
        value.rule_order,
        value.declaration_order,
    )
}

fn parse_epub_native_inline_declarations(style: &str) -> Vec<EpubNativeCssDeclarationInput> {
    split_css_declarations(style)
        .into_iter()
        .enumerate()
        .filter_map(|(index, declaration)| {
            let (name, value) = declaration.split_once(':')?;
            let name = name.trim().to_ascii_lowercase();
            let mut value = value.trim().to_string();
            if name.is_empty() || value.is_empty() {
                return None;
            }
            let important = value.to_ascii_lowercase().contains("!important");
            if important {
                value = value
                    .replace("!important", "")
                    .replace("!IMPORTANT", "")
                    .trim()
                    .to_string();
            }
            Some(EpubNativeCssDeclarationInput {
                name,
                value,
                important,
                order: index as i32,
            })
        })
        .collect()
}

fn epub_native_tag_default_declarations(
    element: ElementRef<'_>,
) -> Vec<EpubNativeCssDeclarationInput> {
    let tag_name = element.value().name().to_ascii_lowercase();
    let mut declarations = Vec::new();
    let mut add = |name: &str, value: &str| {
        declarations.push(EpubNativeCssDeclarationInput {
            name: name.to_string(),
            value: value.to_string(),
            important: false,
            order: declarations.len() as i32,
        });
    };
    match tag_name.as_str() {
        "b" | "strong" => add("font-weight", "bold"),
        "i" | "em" | "cite" => add("font-style", "italic"),
        "u" => add("text-decoration", "underline"),
        "strike" | "s" | "del" => add("text-decoration", "line-through"),
        "big" => add("font-size", "larger"),
        "small" => add("font-size", "smaller"),
        "sup" => {
            add("font-size", "smaller");
            add("vertical-align", "super");
        }
        "sub" => {
            add("font-size", "smaller");
            add("vertical-align", "sub");
        }
        "a" => {
            add("text-decoration", "underline");
            add("color", "#3366CC");
        }
        "center" => add("text-align", "center"),
        "h1" => {
            add("font-size", "2em");
            add("font-weight", "bold");
        }
        "h2" => {
            add("font-size", "1.5em");
            add("font-weight", "bold");
        }
        "h3" => {
            add("font-size", "1.17em");
            add("font-weight", "bold");
        }
        "h4" | "h5" | "h6" => add("font-weight", "bold"),
        "th" => {
            add("font-weight", "bold");
            add("text-align", "center");
        }
        "caption" => add("text-align", "center"),
        _ => {}
    }
    if tag_name == "font" {
        if let Some(color) = element
            .value()
            .attr("color")
            .filter(|value| !value.is_empty())
        {
            add("color", color);
        }
        if let Some(face) = element
            .value()
            .attr("face")
            .filter(|value| !value.is_empty())
        {
            add("font-family", face);
        }
        if let Some(size) = element.value().attr("size").and_then(html_font_size) {
            add("font-size", size);
        }
    }
    if let Some(color) = epub_background_color_tag(&tag_name) {
        add("background-color", &color);
    }
    declarations
}

fn epub_native_inherited_only(
    style: &EpubNativeComputedStyleOutput,
) -> EpubNativeComputedStyleOutput {
    EpubNativeComputedStyleOutput {
        declarations: style
            .declarations
            .iter()
            .filter(|(name, _)| is_epub_native_inheritable_style(name))
            .map(|(name, value)| {
                let mut inherited = value.clone();
                inherited.source_rank = -1;
                inherited.specificity = 0;
                inherited.rule_order = -1;
                inherited.declaration_order = -1;
                (name.clone(), inherited)
            })
            .collect(),
    }
}

fn is_epub_native_inheritable_style(name: &str) -> bool {
    matches!(
        name,
        "color"
            | "font-family"
            | "font-size"
            | "font-style"
            | "font-weight"
            | "font-variant"
            | "font-variant-caps"
            | "letter-spacing"
            | "line-height"
            | "text-align"
            | "text-decoration"
            | "text-decoration-color"
            | "text-decoration-line"
            | "text-decoration-style"
            | "text-shadow"
            | "text-transform"
            | "visibility"
            | "white-space"
            | "word-break"
            | "word-spacing"
            | "writing-mode"
            | "-epub-writing-mode"
            | "-webkit-writing-mode"
            | "direction"
    )
}

fn html_font_size(value: &str) -> Option<&'static str> {
    match value.trim().trim_start_matches('+') {
        "1" => Some("xx-small"),
        "2" => Some("small"),
        "3" => Some("medium"),
        "4" => Some("large"),
        "5" => Some("x-large"),
        "6" => Some("xx-large"),
        "7" => Some("2em"),
        _ => None,
    }
}

fn epub_background_color_tag(tag_name: &str) -> Option<String> {
    let clean = tag_name.strip_prefix("epubbg")?;
    if clean.len() == 8 || clean.len() == 6 {
        Some(format!("#{clean}"))
    } else {
        None
    }
}

fn normalize_epub_text_align(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "center" | "middle" | "-webkit-center" | "-moz-center" => Some("center"),
        "left" | "start" => Some("left"),
        "right" | "end" => Some("right"),
        "justify" => Some("justify"),
        _ => None,
    }
}

fn normalize_epub_native_vertical_writing_fallback(
    declarations: &mut BTreeMap<String, EpubNativeStyleValueOutput>,
) {
    let writing_mode = declarations
        .get("writing-mode")
        .or_else(|| declarations.get("-epub-writing-mode"))
        .or_else(|| declarations.get("-webkit-writing-mode"))
        .cloned();
    let Some(writing_mode) = writing_mode else {
        return;
    };
    if !writing_mode
        .value
        .to_ascii_lowercase()
        .starts_with("vertical")
    {
        return;
    }
    declarations
        .entry("text-align".to_string())
        .or_insert_with(|| EpubNativeStyleValueOutput {
            value: "center".to_string(),
            ..writing_mode.clone()
        });
    declarations
        .entry("line-height".to_string())
        .or_insert_with(|| EpubNativeStyleValueOutput {
            value: "1.45".to_string(),
            ..writing_mode
        });
}

fn normalize_epub_native_relative_font_size(
    declarations: &mut BTreeMap<String, EpubNativeStyleValueOutput>,
    parent_style: &EpubNativeComputedStyleOutput,
) {
    let Some(current) = declarations.get("font-size").cloned() else {
        return;
    };
    if current.source_rank < 0 && current.declaration_order < 0 {
        return;
    }
    let parent_multiplier = parent_style
        .declarations
        .get("font-size")
        .and_then(|value| font_size_multiplier(&value.value, 1.0))
        .unwrap_or(1.0);
    let Some(normalized) = font_size_multiplier(&current.value, parent_multiplier) else {
        return;
    };
    declarations.insert(
        "font-size".to_string(),
        EpubNativeStyleValueOutput {
            value: format!("{}%", normalized * 100.0),
            ..current
        },
    );
}

fn font_size_multiplier(value: &str, parent_multiplier: f32) -> Option<f32> {
    let clean = value.trim().to_ascii_lowercase();
    match clean.as_str() {
        "xx-small" => Some(0.58),
        "x-small" => Some(0.68),
        "small" => Some(0.82),
        "medium" => Some(1.0),
        "large" => Some(1.18),
        "x-large" => Some(1.36),
        "xx-large" => Some(1.55),
        "smaller" => Some(parent_multiplier * 0.85),
        "larger" => Some(parent_multiplier * 1.18),
        _ if clean.ends_with('%') => clean
            .strip_suffix('%')?
            .parse::<f32>()
            .ok()
            .map(|value| parent_multiplier * value / 100.0),
        _ if clean.ends_with("rem") => clean.strip_suffix("rem")?.parse::<f32>().ok(),
        _ if clean.ends_with("em") => clean
            .strip_suffix("em")?
            .parse::<f32>()
            .ok()
            .map(|value| parent_multiplier * value),
        _ => None,
    }
}

fn resolve_epub_native_background_urls(
    declarations: &mut BTreeMap<String, EpubNativeStyleValueOutput>,
    base_href: &str,
) {
    for name in ["background", "background-image"] {
        let Some(value) = declarations.get(name).cloned() else {
            continue;
        };
        let resolved =
            rewrite_epub_css_urls(&value.value, |href| resolve_epub_href(base_href, href));
        if resolved != value.value {
            declarations.insert(
                name.to_string(),
                EpubNativeStyleValueOutput {
                    value: resolved,
                    ..value
                },
            );
        }
    }
}

fn rewrite_epub_css_urls(value: &str, resolve: impl Fn(&str) -> String) -> String {
    let mut out = String::with_capacity(value.len());
    let mut index = 0usize;
    while index < value.len() {
        let Some(relative_start) = value[index..].to_ascii_lowercase().find("url(") else {
            out.push_str(&value[index..]);
            break;
        };
        let start = index + relative_start;
        out.push_str(&value[index..start]);
        let value_start = start + 4;
        let Some(end) = find_css_url_end(value, value_start) else {
            out.push_str(&value[start..]);
            break;
        };
        let raw = value[value_start..end].trim();
        let quote = raw.chars().next().filter(|ch| *ch == '\'' || *ch == '"');
        let clean = trim_matching_quote(raw);
        let resolved = if clean.starts_with("data:")
            || clean.starts_with("http://")
            || clean.starts_with("https://")
        {
            clean
        } else {
            resolve(&clean)
        };
        out.push_str("url(");
        if let Some(quote) = quote {
            out.push(quote);
            out.push_str(&resolved);
            out.push(quote);
        } else {
            out.push_str(&resolved);
        }
        out.push(')');
        index = end + 1;
    }
    out
}

fn find_css_url_end(value: &str, start: usize) -> Option<usize> {
    let mut quote = None;
    for (relative_index, ch) in value[start..].char_indices() {
        let index = start + relative_index;
        if let Some(active_quote) = quote {
            if ch == active_quote && !value[..index].ends_with('\\') {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ')' => return Some(index),
            _ => {}
        }
    }
    None
}

fn epub_native_ruby_fallback_text(element: ElementRef<'_>) -> String {
    let mut out = String::new();
    for child in element.children() {
        match child.value() {
            Node::Text(text) => out.push_str(&text.text),
            Node::Element(_) => {
                let Some(child_element) = ElementRef::wrap(child) else {
                    continue;
                };
                match child_element.value().name() {
                    "rt" => {
                        let text = child_element
                            .text()
                            .collect::<Vec<_>>()
                            .join("")
                            .trim()
                            .to_string();
                        if !text.is_empty() {
                            out.push('（');
                            out.push_str(&text);
                            out.push('）');
                        }
                    }
                    "rp" => {}
                    _ => out.push_str(&child_element.text().collect::<Vec<_>>().join("")),
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        element.text().collect::<Vec<_>>().join("")
    } else {
        out
    }
}

fn encode_uri_component_like_android(value: &str) -> String {
    const SAFE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'%')
        .add(b'<')
        .add(b'>')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'`')
        .add(b'{')
        .add(b'|')
        .add(b'}');
    percent_encoding::utf8_percent_encode(value, SAFE).to_string()
}

trait BlankStringExt {
    fn if_blank(self, fallback: impl FnOnce() -> String) -> String;
}

impl BlankStringExt for String {
    fn if_blank(self, fallback: impl FnOnce() -> String) -> String {
        if self.trim().is_empty() {
            fallback()
        } else {
            self
        }
    }
}

fn normalize_epub_image_width(width: &str) -> Option<String> {
    normalize_epub_image_length(width).or_else(|| Some("100%".to_string()))
}

fn normalize_epub_image_length(width: &str) -> Option<String> {
    let clean = width.trim().to_ascii_lowercase();
    if clean.ends_with('%') || clean.ends_with("em") || clean.ends_with("rem") {
        return Some(clean);
    }
    if clean.ends_with("px") {
        return Some(
            clean
                .trim_end_matches("px")
                .split('.')
                .next()
                .unwrap_or_default()
                .to_string(),
        );
    }
    clean.parse::<i64>().ok().map(|_| clean)
}

fn is_inline_epub_image_width(width: &str) -> bool {
    let clean = width.trim().to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    if clean.ends_with("rem") {
        return clean
            .trim_end_matches("rem")
            .parse::<f32>()
            .unwrap_or(f32::MAX)
            <= 3.0;
    }
    if clean.ends_with("em") {
        return clean
            .trim_end_matches("em")
            .parse::<f32>()
            .unwrap_or(f32::MAX)
            <= 3.0;
    }
    if clean.ends_with("px") {
        return clean
            .trim_end_matches("px")
            .parse::<f32>()
            .unwrap_or(f32::MAX)
            <= 96.0;
    }
    if clean.ends_with('%') {
        return clean
            .trim_end_matches('%')
            .parse::<f32>()
            .unwrap_or(f32::MAX)
            <= 12.0;
    }
    clean.parse::<f32>().unwrap_or(f32::MAX) <= 96.0
}

fn extract_css_color(value: &str) -> Option<String> {
    let clean = value.trim();
    if clean.starts_with('#') || clean.to_ascii_lowercase().starts_with("rgb") {
        return Some(clean.to_string());
    }
    clean
        .split([' ', ',', '/'])
        .map(str::trim)
        .find(|part| {
            !part.is_empty()
                && (part.starts_with('#')
                    || part.to_ascii_lowercase().starts_with("rgb")
                    || named_css_color(part).is_some())
        })
        .map(ToOwned::to_owned)
}

fn to_epub_color_tag(value: &str) -> Option<String> {
    let color = parse_css_color(value)?;
    Some(format!("{:08X}", color))
}

fn to_html_color_attr(value: &str) -> Option<String> {
    let color = parse_css_color(value)?;
    let alpha = color >> 24;
    if alpha == 255 {
        Some(format!("#{:06X}", color & 0x00FF_FFFF))
    } else {
        Some(format!("#{:08X}", color))
    }
}

fn parse_css_color(value: &str) -> Option<u32> {
    let clean = value.trim().trim_matches(['\'', '"']);
    let lower = clean.to_ascii_lowercase();
    if lower.starts_with("rgb") {
        return parse_rgb_css_color(clean);
    }
    if clean.starts_with('#') {
        return parse_hex_css_color(clean);
    }
    named_css_color(clean).and_then(parse_hex_css_color)
}

fn parse_hex_css_color(value: &str) -> Option<u32> {
    let hex = value.trim().trim_start_matches('#');
    let expanded = match hex.len() {
        3 => hex.chars().flat_map(|ch| [ch, ch]).collect::<String>(),
        4 => hex.chars().flat_map(|ch| [ch, ch]).collect::<String>(),
        6 | 8 => hex.to_string(),
        _ => return None,
    };
    let raw = u32::from_str_radix(&expanded, 16).ok()?;
    if expanded.len() == 8 {
        Some(raw)
    } else {
        Some(0xFF00_0000 | raw)
    }
}

fn parse_rgb_css_color(value: &str) -> Option<u32> {
    let start = value.find('(')?;
    let end = value.rfind(')')?;
    if end <= start {
        return None;
    }
    let parts = value[start + 1..end]
        .split([',', ' ', '/'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }
    fn component(value: &str) -> u32 {
        let raw = if let Some(percent) = value.strip_suffix('%') {
            percent.parse::<f32>().unwrap_or(0.0) * 2.55
        } else {
            value.parse::<f32>().unwrap_or(0.0)
        };
        (raw as u32).min(255)
    }
    let alpha = parts
        .get(3)
        .map(|value| {
            if let Some(percent) = value.strip_suffix('%') {
                percent.parse::<f32>().unwrap_or(100.0) * 2.55
            } else {
                value.parse::<f32>().unwrap_or(1.0) * 255.0
            }
        })
        .unwrap_or(255.0) as u32;
    Some(
        (alpha.min(255) << 24)
            | (component(parts[0]) << 16)
            | (component(parts[1]) << 8)
            | component(parts[2]),
    )
}

fn named_css_color(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "black" => Some("#000000"),
        "white" => Some("#FFFFFF"),
        "red" => Some("#FF0000"),
        "green" => Some("#008000"),
        "blue" => Some("#0000FF"),
        "cyan" | "aqua" => Some("#00FFFF"),
        "magenta" | "fuchsia" => Some("#FF00FF"),
        "yellow" => Some("#FFFF00"),
        "gray" | "grey" => Some("#808080"),
        "silver" => Some("#C0C0C0"),
        "maroon" => Some("#800000"),
        "purple" => Some("#800080"),
        "teal" => Some("#008080"),
        "navy" => Some("#000080"),
        "orange" => Some("#FFA500"),
        "transparent" => Some("#00000000"),
        _ => None,
    }
}

fn is_readable_block(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "center"
            | "dd"
            | "dialog"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "tbody"
            | "td"
            | "tfoot"
            | "th"
            | "thead"
            | "tr"
            | "ul"
    )
}

fn rewrite_epub_footnote_html(
    html: &str,
    target_id: &str,
    image_sources: Arc<Mutex<Vec<String>>>,
) -> String {
    let mut out = Vec::with_capacity(html.len());
    let target_id = target_id.to_string();
    let target_id_for_links = target_id.clone();
    let image_sources_for_handler = Arc::clone(&image_sources);
    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("a[href]", move |element| {
                    let href = element.get_attribute("href").unwrap_or_default();
                    let link_target = decode_epub_fragment(
                        href.rsplit_once('#')
                            .map(|(_, target)| target)
                            .unwrap_or_default(),
                    );
                    let rel = element
                        .get_attribute("rel")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    let type_attr = element
                        .get_attribute("epub:type")
                        .or_else(|| element.get_attribute("type"))
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    let class_name = element
                        .get_attribute("class")
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if link_target == target_id_for_links {
                        element.remove();
                    } else if href.starts_with('#')
                        || link_target.ends_with("-back")
                        || link_target.ends_with("_back")
                        || link_target.contains("back")
                        || rel.contains("backlink")
                        || type_attr.contains("backlink")
                        || class_name.contains("backlink")
                        || class_name.contains("noteref")
                    {
                        element.remove_and_keep_content();
                    }
                    Ok(())
                }),
                element!("img", move |element| {
                    let src = element
                        .get_attribute("src")
                        .or_else(|| element.get_attribute("data-src"))
                        .or_else(|| element.get_attribute("xlink:href"))
                        .or_else(|| element.get_attribute("href"))
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    if !src.is_empty() {
                        if let Ok(mut sources) = image_sources_for_handler.lock() {
                            let index = sources.len();
                            sources.push(src);
                            element.set_attribute(
                                "src",
                                &format!("__LEGADO_EPUB_FOOTNOTE_IMG_{}__", index),
                            )?;
                        }
                    }
                    Ok(())
                }),
            ],
            ..Settings::default()
        },
        |chunk: &[u8]| out.extend_from_slice(chunk),
    );
    if rewriter.write(html.as_bytes()).is_err() || rewriter.end().is_err() {
        return html.to_string();
    }
    String::from_utf8(out)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

fn normalize_breaks(html: &str) -> String {
    let mut out = String::with_capacity(html.len() + 16);
    let mut chars = html.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '<' {
            let mut tag = String::new();
            tag.push(ch);
            while let Some(next) = chars.next() {
                tag.push(next);
                if next == '>' {
                    break;
                }
            }
            if is_breaking_tag(&tag) {
                out.push('\n');
            }
            out.push_str(&tag);
            if is_block_end_tag(&tag) {
                out.push('\n');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_breaking_tag(tag: &str) -> bool {
    let tag = tag.trim_start_matches('<').trim_start_matches('/').trim();
    let name = tag
        .split(|ch: char| ch == '>' || ch == '/' || ch.is_whitespace())
        .next()
        .unwrap_or_default();
    matches!(
        name.to_ascii_lowercase().as_str(),
        "br" | "p"
            | "div"
            | "section"
            | "article"
            | "header"
            | "footer"
            | "main"
            | "li"
            | "tr"
            | "table"
            | "ul"
            | "ol"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
    )
}

fn is_block_end_tag(tag: &str) -> bool {
    let trimmed = tag.trim_start_matches('<').trim();
    if !trimmed.starts_with('/') {
        return false;
    }
    is_breaking_tag(tag)
}

fn normalize_whitespace_lines(text: &str) -> String {
    text.lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn split_not_blank(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalized_element_text<'a>(text: impl Iterator<Item = &'a str>) -> String {
    text.collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn element_alignment(element: &scraper::node::Element) -> Option<String> {
    if let Some(align) = valid_alignment(element.attr("align").unwrap_or_default()) {
        return Some(align);
    }
    let style = element.attr("style").unwrap_or_default();
    for declaration in style.split(';') {
        let Some((name, value)) = declaration.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("text-align") {
            return valid_alignment(value.trim());
        }
    }
    None
}

fn valid_alignment(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    matches!(value.as_str(), "left" | "center" | "right").then_some(value)
}

fn split_distinct_hrefs(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    for href in value
        .split('|')
        .map(str::trim)
        .filter(|href| !href.is_empty())
    {
        if !out.iter().any(|existing| existing == href) {
            out.push(href.to_string());
        }
    }
    out
}

fn div_has_div_or_p_child(element: &scraper::ElementRef<'_>) -> bool {
    element.children().any(|child| {
        child
            .value()
            .as_element()
            .map(|element| matches!(element.name(), "div" | "p"))
            .unwrap_or(false)
    })
}

fn is_epub_book_info_document(document: &Html) -> bool {
    let title_selector = Selector::parse("[title*=书籍信息], [title*=版权信息], [title*=简介]")
        .expect("static EPUB info title selector");
    if document.select(&title_selector).next().is_some() {
        return true;
    }

    let text = clean_epub_info_text(&document.root_element().text().collect::<Vec<_>>().join(" "));
    let has_intro = text.contains("简介");
    let has_book_meta = text.contains("作者") || text.contains("首发") || text.contains("完本");
    let class_selector = Selector::parse(".sjmc,.jj01,.jj02,.copyright,.book-info")
        .expect("static EPUB info class selector");
    has_intro && has_book_meta && document.select(&class_selector).next().is_some()
}

fn clean_epub_info_text(text: &str) -> String {
    text.replace('\u{00A0}', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches('\u{3000}')
        .trim()
        .to_string()
}

fn substring_after_label(text: &str, label: &str) -> Option<String> {
    let trimmed = text.trim_start();
    let rest = trimmed.strip_prefix(label)?.trim_start();
    let rest = rest
        .strip_prefix('：')
        .or_else(|| rest.strip_prefix(':'))?
        .trim();
    Some(clean_epub_info_text(rest))
}

fn decode_epub_fragment(fragment: &str) -> String {
    percent_decode_str(fragment)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .unwrap_or_else(|_| fragment.to_string())
}

fn is_epub_info_meta_line(line: &str) -> bool {
    substring_after_label(line, "作者").is_some()
        || substring_after_label(line, "首发").is_some()
        || substring_after_label(line, "完本").is_some()
        || line.eq_ignore_ascii_case("简介")
        || line.eq_ignore_ascii_case("简介：")
}

fn is_likely_footnote_target(id: &str, type_attr: &str, role: &str, class_name: &str) -> bool {
    let id = id.to_ascii_lowercase();
    let type_attr = type_attr.to_ascii_lowercase();
    let role = role.to_ascii_lowercase();
    let class_name = class_name.to_ascii_lowercase();
    type_attr.contains("footnote")
        || type_attr.contains("endnote")
        || role == "doc-footnote"
        || role == "doc-endnote"
        || class_name.split(' ').any(|class| {
            matches!(
                class,
                "footnote"
                    | "endnote"
                    | "note"
                    | "annotation"
                    | "duokan-footnote"
                    | "doc-footnote"
                    | "doc-endnote"
            )
        })
        || id.starts_with("fn")
        || id.starts_with("note")
        || id.starts_with("n_")
        || id.ends_with("-note")
        || id.contains("footnote")
        || id.contains("endnote")
}

fn escape_html_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_json_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_html_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn charset_from_content_type(content: &str) -> Option<String> {
    let lower = content.to_ascii_lowercase();
    let index = lower.find("charset=")?;
    let charset = &content[index + "charset=".len()..];
    let charset = charset.split(';').next().unwrap_or_default().trim();
    if charset.is_empty() {
        None
    } else {
        Some(trim_charset(charset).to_string())
    }
}

fn trim_charset(value: &str) -> &str {
    value.trim_matches(|ch| ch == '"' || ch == '\'' || ch == ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_text_array_keeps_block_and_br_line_breaks() {
        let out = html_text_array(
            "<article><h1>Title</h1><p>Alpha<br>Beta</p><div>Gamma</div></article>",
        );
        assert_eq!(out.lines, vec!["Title", "Alpha", "Beta", "Gamma"]);
    }

    #[test]
    fn html_charset_reads_charset_meta() {
        let out = html_charset(r#"<head><meta charset="GBK"></head>"#);
        assert_eq!(out.charset, "GBK");
    }

    #[test]
    fn html_charset_reads_http_equiv_content_type() {
        let out = html_charset(
            r#"<meta http-equiv="Content-Type" content="text/html; charset='big5'; other=1">"#,
        );
        assert_eq!(out.charset, "big5");
    }

    #[test]
    fn html_format_serializes_parseable_document() {
        let out = html_format("<p>Alpha</p>");
        assert!(out.html.contains("<html"));
        assert!(out.html.contains("Alpha"));
    }

    #[test]
    fn html_title_extracts_normalized_title() {
        let out = html_title("<html><head><title>  Alpha\n Beta </title></head></html>");
        assert_eq!(out.title, "Alpha Beta");
    }

    #[test]
    fn html_first_alignment_reads_align_and_style() {
        assert_eq!(
            html_first_alignment(r#"<p align="center">A</p><p align="right">B</p>"#).alignment,
            "center"
        );
        assert_eq!(
            html_first_alignment(
                r#"<div><span style="color:red;text-align: right">B</span></div>"#
            )
            .alignment,
            "right"
        );
    }

    #[test]
    fn epub_css_assets_collect_head_and_body_stylesheets_in_android_order() {
        let out = epub_css_assets(
            r#"<html><head>
                <style>h1{color:red}</style>
                <link rel="preload" href="preload.css">
                <link rel="alternate stylesheet" href="head.css">
            </head><body><p>Body</p></body></html>"#,
            r#"<section>
                <style>p{font-weight:bold}</style>
                <link rel="stylesheet" href="../body.css">
            </section>"#,
        );

        assert_eq!(out.assets.len(), 4);
        assert_eq!(out.assets[0].kind, "inline");
        assert_eq!(out.assets[0].content, "h1{color:red}");
        assert_eq!(out.assets[1].kind, "stylesheet");
        assert_eq!(out.assets[1].href, "head.css");
        assert_eq!(out.assets[2].kind, "inline");
        assert_eq!(out.assets[2].content, "p{font-weight:bold}");
        assert_eq!(out.assets[3].kind, "stylesheet");
        assert_eq!(out.assets[3].href, "../body.css");
        assert!(!out.html.contains("<style"));
        assert!(!out.html.contains("stylesheet"));
        assert!(out.html.contains("<section>"));
    }

    #[test]
    fn epub_native_entry_prefers_distinct_data_hrefs() {
        let out = epub_native_entry(
            r#"<epub-native data-href="a.xhtml" data-hrefs=" a.xhtml | b.xhtml | a.xhtml " />"#,
        );
        assert_eq!(out.hrefs, vec!["a.xhtml", "b.xhtml"]);
    }

    #[test]
    fn epub_readable_title_prefers_heading_like_android_epub_file() {
        let out = epub_readable_title(
            "<html><head><title>Fallback</title></head><body><h2>正文标题</h2></body></html>",
        );
        assert_eq!(out.title, "正文标题");
    }

    #[test]
    fn epub_book_info_extracts_author_and_intro_lines() {
        let out = epub_book_info(
            r#"<div class="book-info" title="书籍信息">
                <p>作者：张三</p>
                <p>简介：第一行</p>
                <p>第二行</p>
                <p>首发：站点</p>
            </div>"#,
        );
        assert!(out.is_book_info);
        assert_eq!(out.author, "张三");
        assert_eq!(out.intro, "第一行\n第二行");
    }

    #[test]
    fn epub_footnote_ids_match_likely_targets() {
        let out = epub_footnote_ids(
            r#"<section id="fn1" epub:type="footnote">A</section>
               <p id="plain">B</p>
               <aside id="note-2" role="doc-endnote">C</aside>"#,
        );
        assert_eq!(out.ids, vec!["fn1", "note-2"]);
    }

    #[test]
    fn epub_footnote_target_cleans_backlinks_and_tracks_images() {
        let out = epub_footnote_target(
            r##"<section id="fn1" title="脚注">
                <a href="#fn1">self</a>
                <a href="#ref-back">back</a>
                <p>Note <img data-src="img/note.png"></p>
            </section>"##,
            "fn1",
        );
        assert!(out.found);
        assert_eq!(out.title, "脚注");
        assert_eq!(out.text, "back Note");
        assert!(!out.html.contains("self"));
        assert!(out.html.contains("back"));
        assert!(out.html.contains("__LEGADO_EPUB_FOOTNOTE_IMG_0__"));
        assert_eq!(out.image_sources, vec!["img/note.png"]);
    }

    #[test]
    fn epub_readable_lines_preserve_inline_style_markers_and_images() {
        let out = epub_readable_lines(
            r#"<body>
                <h1>标题</h1>
                <p>第一 <strong>粗体</strong><br><em>斜体</em><sup>1</sup></p>
                <p style="display:none">隐藏</p>
                <img src="cover.jpeg"><img src="cover.jpeg"><img src="pic.png">
                <p><ruby>汉<rt>han</rt><rp>)</rp></ruby></p>
            </body>"#,
            true,
        );
        assert_eq!(
            out.lines,
            vec![
                "标题",
                "第一 \u{E10C}B粗体\u{E10C}b",
                "\u{E10C}I斜体\u{E10C}i \u{E10C}P1\u{E10C}p",
                r#"<img src="cover.jpeg">"#,
                r#"<img src="pic.png">"#,
                "汉",
            ]
        );
    }

    #[test]
    fn epub_body_html_slices_fragments_and_prepares_xhtml() {
        let out = epub_body_html(
            r#"<html><head><style>p{color:red}</style><script>alert(1)</script></head>
               <body style="background: red"><p id="start">Start</p><image xlink:href="pic.svg"/>
               <aside id="fn1" epub:type="footnote">Note</aside><p id="end">End</p><p>After</p></body></html>"#,
            Some("start"),
            Some("end"),
        );
        assert!(out.sliced);
        assert!(out.body_html.contains(r#"<p id="start">"#));
        assert!(out.body_outer_html.starts_with("<body"));
        assert!(out.body_style.is_empty());
        assert!(out.body_background.is_empty());
        assert!(out.html.contains(r#"<p id="start">"#));
        assert!(out.html.contains("<img"));
        assert!(out.html.contains(r#"src="pic.svg""#));
        assert!(out.html.contains("display:none"));
        assert!(out.html.contains(r#"data-epub-page-bg="FFFF0000""#));
        assert!(!out.html.contains("<script"));
        assert!(!out.html.contains("id=\"end\""));

        let full = epub_body_html(
            r##"<html><head><style>p{color:red}</style></head><body bgcolor="#123"><p>Body</p></body></html>"##,
            None,
            None,
        );
        assert!(!full.sliced);
        assert!(full.html.contains("<style>p{color:red}</style>"));
        assert!(full.html.contains(r#"data-epub-page-bg="FF112233""#));
        assert!(full.body_background.is_empty());
        assert!(full.body_outer_html.contains(r##"bgcolor="#123""##));
        assert!(full.body_html.contains("<p>Body</p>"));
    }

    #[test]
    fn epub_debug_chapter_html_removes_reader_hidden_nodes() {
        let out = epub_debug_chapter_html(
            r#"["<body><title>Hidden</title><p>A</p><p style=\"display: none\">Hide</p><img src=\"cover.jpeg\"><ruby>字<rt>zi</rt></ruby></body>","<body><img src=\"cover.jpeg\"><p>B</p></body>"]"#,
            true,
        );
        assert!(out.html.contains("<p>A</p>"));
        assert!(out.html.contains("<p>B</p>"));
        assert!(!out.html.contains("Hidden"));
        assert!(!out.html.contains("Hide"));
        assert!(!out.html.contains("<rt>"));
        assert_eq!(out.html.matches(r#"src="cover.jpeg""#).count(), 1);
    }

    #[test]
    fn html_readable_table_flattens_rows_and_inline_tags() {
        let out = html_readable_table(
            r#"<table align="center">
                <tr><th><strong>A</strong></th><td>B<img alt="ALT"></td></tr>
                <tr><td><em>C</em><br>D</td><td><img src="pic.png"></td></tr>
            </table>"#,
        );
        assert_eq!(
            out.html,
            r#"<p align="center"><b>A</b>　BALT</p><p align="center"><i>C</i><br>D　<img src="pic.png"></p>"#
        );
    }

    #[test]
    fn html_render_flags_report_reader_dom_predicates() {
        let out = html_render_flags(
            r#"<div style="margin-top:1.2em;page-break-after:always;background:#fff">
                <p style="border:1px solid #333">Box</p>
                <span><img src="pic.png"></span>
            </div>"#,
        );
        assert_eq!(out.tag_name, "div");
        assert!(out.is_block);
        assert!(out.has_image);
        assert!(out.has_block_box_style);
        assert!(out.has_block_box_descendant);
        assert!(!out.page_break_before);
        assert!(out.page_break_after);
        assert!(out.block_spacing_before);
        assert!(!out.block_spacing_after);
    }

    #[test]
    fn html_render_plan_flattens_reader_actions_without_android_jsoup() {
        let out = html_render_plan(
            r#"<p>Alpha <img src="pic.png" data-legado-width="40"></p><table align="center"><tr><td>A</td><td>B</td></tr></table><div style="margin-top:1.2em;page-break-after:always;background:#fff">Box</div>"#,
            true,
        );
        let kinds = out
            .actions
            .iter()
            .map(|action| action.kind.as_str())
            .collect::<Vec<_>>();
        assert!(kinds.contains(&"image"));
        assert!(kinds.contains(&"htmlText"));
        assert!(kinds.contains(&"spacingBefore"));
        assert!(kinds.contains(&"blockBox"));
        assert!(kinds.contains(&"pageBreak"));

        let image = out
            .actions
            .iter()
            .find(|action| action.kind == "image")
            .expect("image action");
        assert_eq!(image.image.src, "pic.png");
        assert_eq!(image.image.width, "40");

        let table = out
            .actions
            .iter()
            .find(|action| action.kind == "htmlText")
            .expect("table text action");
        assert_eq!(table.html, r#"<p align="center">A　B</p>"#);

        let spacing = out
            .actions
            .iter()
            .find(|action| action.kind == "spacingBefore")
            .expect("spacing action");
        assert_eq!(spacing.margin_top, "1.2em");
    }

    #[test]
    fn html_page_background_extracts_and_removes_background_nodes() {
        let out = html_page_background(
            r#"<span data-epub-page-bg="epubbg11223344"></span><p>Text</p><img data-epub-background="true" src="bg.png"><img src="inline.png">"#,
        );
        assert_eq!(out.page_color, "epubbg11223344");
        assert_eq!(out.background_src, "bg.png");
        assert!(out.html.contains("<p>Text</p>"));
        assert!(out.html.contains("inline.png"));
        assert!(!out.html.contains("data-epub-page-bg"));
        assert!(!out.html.contains("data-epub-background"));
    }

    #[test]
    fn html_image_info_prefers_legado_width_then_css_width() {
        let out = html_image_info(
            r#"<img src="pic.png" data-epub-background="true" data-legado-style="full" data-legado-click="go" width="10" style="width:50%">"#,
        );
        assert_eq!(out.src, "pic.png");
        assert!(out.is_background);
        assert_eq!(out.style, "full");
        assert_eq!(out.width, "10");
        assert_eq!(out.click, "go");

        let css = html_image_info(r#"<img src="pic.png" style="width:50%">"#);
        assert_eq!(css.width, "50%");
    }

    #[test]
    fn epub_image_options_match_android_epub_file_rules() {
        let out = epub_image_options(
            r#"<img data-src="pic.png" alt="Cover" data-epub-background="true" width="80px" height="2em">"#,
        );
        assert_eq!(out.src, "pic.png");
        assert_eq!(out.alt, "Cover");
        assert!(out.is_background);
        assert_eq!(out.width, "80");
        assert_eq!(out.height, "2em");
        assert_eq!(out.style, "text");

        let single = epub_image_options(
            r#"<img src="single.png" data-epub-single-page="true" style="width:50%;height:120px">"#,
        );
        assert_eq!(single.width, "50%");
        assert_eq!(single.height, "120");
        assert_eq!(single.style, "SINGLE");

        let invalid_width = epub_image_options(r#"<img src="pic.png" width="wide">"#);
        assert_eq!(invalid_width.width, "100%");
    }

    #[test]
    fn epub_image_page_marks_single_overlay_and_gallery_pages() {
        let single = epub_image_page_marks(r#"<div><img src="cover.png"></div>"#);
        assert!(single.html.contains(r#"data-epub-single-page="true""#));
        assert!(single.body_style_append.is_empty());

        let overlay = epub_image_page_marks(
            r#"<div><img src="cover.png"><h1>Title</h1><p>Subtitle</p></div>"#,
        );
        assert!(overlay.html.contains(r#"data-epub-background="true""#));
        assert!(overlay.body_style_append.is_empty());

        let gallery = epub_image_page_marks(
            r#"<div class="gallery"><img src="a.png"><img src="b.png"></div>"#,
        );
        assert!(gallery
            .body_style_append
            .contains("text-align:center;line-height:1"));
        assert!(gallery.html.contains(r#"data-legado-width="100%""#));
        assert!(gallery.html.contains(r#"data-legado-style="SINGLE""#));
        assert!(gallery.html.contains("display:block;margin:0 auto"));

        let duokan = epub_image_page_marks(
            r#"<div class="duokan-image-gallery"><div class="duokan-image-gallery-cell"><img src="a.png"></div><div class="duokan-image-gallery-cell"><img src="b.png"></div></div>"#,
        );
        assert!(duokan.body_style_append.contains("text-align:center"));
        assert!(!duokan.body_style_append.contains("line-height:1"));
        assert!(duokan
            .html
            .contains("display:block;margin:0 auto;text-align:center"));
        assert!(!duokan.html.contains(r#"data-legado-style="SINGLE""#));
    }

    #[test]
    fn epub_materialized_images_rewrites_all_images_like_epub_file_loop() {
        let out = epub_materialized_images(
            r#"<p><img data-src="../Images/pic.png" alt="A" width="10%" height="2em"><img src="cover.jpeg" data-epub-background="true" width="100%"></p>"#,
            "OPS/text/ch1.xhtml",
            r#"["OPS/Images/pic.png","cover.jpeg"]"#,
        );
        assert!(
            out.html.contains(
                r#"src="OPS/Images/pic.png,{&quot;width&quot;:&quot;10%&quot;,&quot;height&quot;:&quot;2em&quot;,&quot;style&quot;:&quot;text&quot;}""#
            ),
            "{}",
            out.html
        );
        assert!(out.html.contains(r#"data-legado-width="10%""#));
        assert!(out.html.contains(r#"data-legado-style="text""#));
        assert!(out.html.contains(r#"alt="A""#));
        assert!(out.html.contains(r#"src="cover.jpeg""#));
        assert!(out.html.contains(r#"data-epub-background="true""#));
    }

    #[test]
    fn epub_inherited_styles_propagates_reader_css_like_epub_file() {
        let out = epub_inherited_styles(
            r#"<section><p style="font-weight:bold">A <span>B</span></p><p style="color:blue">C</p><img src="x.png"></section>"#,
            "color:red;font-size:120%;text-align:center;background:#fff",
        );
        assert!(out
            .html
            .contains(r#"<section style="color:red;font-size:120%;text-align:center">"#));
        assert!(out.html.contains(
            r#"<p style="font-weight:bold;color:red;font-size:120%;text-align:center">A <span style="font-weight:bold;color:red;font-size:120%;text-align:center">B</span></p>"#
        ));
        assert!(out
            .html
            .contains(r#"<p style="color:blue;font-size:120%;text-align:center">C</p>"#));
        assert!(out
            .html
            .contains(r#"<img src="x.png" style="color:red;font-size:120%;text-align:center">"#));
        assert!(!out.html.contains("background:#fff"));
    }

    #[test]
    fn epub_generated_content_injects_before_after_spans_like_dom_builder() {
        let rules = r##"[
            {
                "selector":"body",
                "before":true,
                "declarations":[
                    {"name":"content","value":"'Start ' attr(data-title)","important":false,"order":0},
                    {"name":"color","value":"red","important":false,"order":1}
                ]
            },
            {
                "selector":"h1.title",
                "before":false,
                "declarations":[
                    {"name":"content","value":"open-quote attr(title) close-quote counter(chapter)","important":false,"order":0},
                    {"name":"font-weight","value":"bold","important":false,"order":1}
                ]
            }
        ]"##;
        let out = epub_generated_content(
            r#"<body data-title="Book"><h1 class="title" title="One">Chapter</h1><p>Text</p></body>"#,
            rules,
        );
        assert!(
            out.html.starts_with(
                r#"<span data-epub-generated="true" style="color:red">Start Book</span>"#
            ),
            "{}",
            out.html
        );
        assert!(out.html.contains(r#"<h1 "#));
        assert!(out.html.contains(r#"class="title""#));
        assert!(out.html.contains(r#"title="One""#));
        assert!(out.html.contains(
            r#"Chapter<span data-epub-generated="true" style="font-weight:bold">“One”1</span></h1>"#
        ));
        assert!(out.html.contains("<p>Text</p>"));
    }

    #[test]
    fn epub_native_dom_builds_tree_and_cascaded_styles_like_dom_builder() {
        let rules = r##"[
            {
                "selector":"p.note",
                "style":"color:blue;font-size:120%",
                "specificity":11,
                "order":0,
                "declarations":[
                    {"name":"color","value":"blue","important":false,"order":0},
                    {"name":"font-size","value":"120%","important":false,"order":1}
                ]
            },
            {
                "selector":"span",
                "style":"font-weight:bold;background-image:url(../img/bg.png)",
                "specificity":1,
                "order":1,
                "declarations":[
                    {"name":"font-weight","value":"bold","important":false,"order":0},
                    {"name":"background-image","value":"url(../img/bg.png)","important":false,"order":1}
                ]
            }
        ]"##;
        let out = epub_native_dom(
            r#"<body><p class="note" align="right">A <span style="font-size:smaller">B</span></p><ruby>字<rp>(</rp><rt>zi</rt><rp>)</rp></ruby><a href="../nav.xhtml">Next</a></body>"#,
            rules,
            "OPS/text/ch1.xhtml",
        );
        assert_eq!(out.body.kind, "element");
        assert_eq!(out.body.tag_name, "body");
        let paragraph = out
            .body
            .children
            .iter()
            .find(|node| node.tag_name == "p")
            .expect("paragraph node");
        assert_eq!(
            paragraph.attributes.get("class").map(String::as_str),
            Some("note")
        );
        assert_eq!(
            paragraph
                .style
                .declarations
                .get("color")
                .map(|value| value.value.as_str()),
            Some("blue")
        );
        assert_eq!(
            paragraph
                .style
                .declarations
                .get("text-align")
                .map(|value| value.value.as_str()),
            Some("right")
        );
        let span = paragraph
            .children
            .iter()
            .find(|node| node.tag_name == "span")
            .expect("span node");
        assert_eq!(
            span.style
                .declarations
                .get("font-weight")
                .map(|value| value.value.as_str()),
            Some("bold")
        );
        assert_eq!(
            span.style
                .declarations
                .get("font-size")
                .map(|value| value.value.as_str()),
            Some("102.00001%")
        );
        assert_eq!(
            span.style
                .declarations
                .get("background-image")
                .map(|value| value.value.as_str()),
            Some("url(OPS/img/bg.png)")
        );
        let ruby = out
            .body
            .children
            .iter()
            .find(|node| node.source_path == "body/body[1]")
            .expect("ruby fallback node");
        assert_eq!(ruby.tag_name, "span");
        assert_eq!(
            ruby.children.first().map(|node| node.text.as_str()),
            Some("字（zi）")
        );
        let link = out
            .body
            .children
            .iter()
            .find(|node| node.tag_name == "a")
            .expect("link node");
        assert_eq!(
            link.attributes.get("href").map(String::as_str),
            Some("OPS/nav.xhtml")
        );
    }

    #[test]
    fn epub_applied_css_rewrites_matched_body_and_descendant_styles() {
        let rules = r##"[
            {
                "selector":"body",
                "style":"background:#fff;color:black",
                "specificity":1,
                "order":0,
                "declarations":[
                    {"name":"background","value":"#fff","important":false,"order":0},
                    {"name":"color","value":"black","important":false,"order":1}
                ]
            },
            {
                "selector":"p.note",
                "style":"color:blue;font-weight:bold",
                "specificity":11,
                "order":1,
                "declarations":[
                    {"name":"color","value":"blue","important":false,"order":0},
                    {"name":"font-weight","value":"bold","important":false,"order":1}
                ]
            },
            {
                "selector":"span",
                "style":"color:red !important",
                "specificity":1,
                "order":2,
                "declarations":[
                    {"name":"color","value":"red","important":true,"order":0}
                ]
            }
        ]"##;
        let out = epub_applied_css(
            r#"<body background="bg.png"><p class="note" style="color:green">A <span style="color:yellow">B</span></p><em>Keep</em></body>"#,
            rules,
        );
        assert_eq!(out.body_style, "background:#fff;color:black");
        assert_eq!(out.body_background, "bg.png");
        assert!(out.html.contains(r#"<p "#), "{}", out.html);
        assert!(out.html.contains(r#"class="note""#), "{}", out.html);
        assert!(
            out.html.contains(r#"style="color:green;font-weight:bold""#),
            "{}",
            out.html
        );
        assert!(
            out.html
                .contains(r#"<span style="color:red !important">B</span>"#),
            "{}",
            out.html
        );
        assert!(out.html.contains("<em>Keep</em>"));
    }

    #[test]
    fn epub_media_placeholders_replace_media_tags_and_resolve_sources() {
        let out = epub_media_placeholders(
            r#"<div><video title="Clip"><source src="../media/a b.mp4"></video><audio src="sound.mp3" alt="Sound"></audio><iframe></iframe><p>Keep</p></div>"#,
            "OPS/text/ch1.xhtml",
        );
        assert!(out.html.contains("epub-media-placeholder"));
        assert!(out.html.contains("[EPUB视频] Clip"));
        assert!(out.html.contains("legado-epub-media:OPS/media/a%20b.mp4"));
        assert!(out.html.contains("[EPUB音频] Sound"));
        assert!(out.html.contains("legado-epub-media:OPS/text/sound.mp3"));
        assert!(out.html.contains("legado-epub-media:missing"));
        assert!(!out.html.contains("<video"));
        assert!(!out.html.contains("<audio"));
        assert!(out.html.contains("<p>Keep</p>"));
    }

    #[test]
    fn epub_inline_styles_materialize_reader_compatible_tags() {
        let out = epub_inline_styles(
            r#"<p style="text-align:center;color:red;font-weight:700;font-style:italic;text-decoration:underline line-through;font-size:120%;background-color:#abc">Hi</p><span style="display:none">Hide</span><div style="border:1px solid #000;background:#fff">Box</div><font style="color:rgba(0, 0, 255, 0.5)">Blue</font>"#,
            "font-size:80%;color:green",
        );
        assert!(out.html.contains(r#"<p style="text-align:center;color:red;font-weight:700;font-style:italic;text-decoration:underline line-through;font-size:120%;background-color:#abc" align="center">"#));
        assert!(out.html.contains("<big><epubbgFFAABBCC><strike><u><i><b><font color=\"#FF0000\">Hi</font></b></i></u></strike></epubbgFFAABBCC></big>"));
        assert!(!out.html.contains("Hide"));
        assert!(out
            .html
            .contains("<div style=\"border:1px solid #000;background:#fff\">Box</div>"));
        assert!(out.html.contains(
            "<font style=\"color:rgba(0, 0, 255, 0.5)\" color=\"#7F0000FF\">Blue</font>"
        ));
        assert!(out.html.starts_with("<small><font color=\"#008000\">"));
    }

    #[test]
    fn epub_resolved_links_and_body_background_match_epub_file_helpers() {
        let links = epub_resolved_links(
            r##"<p><a href="../note.xhtml#n1">Note</a><a href="#local">Local</a><a href="https://example.test/x">Web</a></p>"##,
            "OPS/text/ch1.xhtml",
        );
        assert!(links.html.contains(r#"href="OPS/note.xhtml#n1""#));
        assert!(links.html.contains(r##"href="#local""##));
        assert!(links.html.contains(r#"href="https://example.test/x""#));

        let css_bg = epub_body_background_image(
            r#"background-image: url("../Images/bg cover.png"); color: red"#,
            "",
        );
        assert_eq!(css_bg.href, "../Images/bg cover.png");
        let attr_bg = epub_body_background_image("", "images/page.png");
        assert_eq!(attr_bg.href, "images/page.png");
        let none_bg = epub_body_background_image("background: none", "");
        assert_eq!(none_bg.href, "");
    }

    #[test]
    fn mobi_content_removes_hidden_nodes_and_rewrites_recindex_images() {
        let out = mobi_content_html(
            r#"<html><head><title>T</title></head><body><p>Keep</p><p style="display: none">Hide</p><img recindex="42" alt="x"></body></html>"#,
            true,
        );
        assert!(!out.html.contains("<title>"));
        assert!(!out.html.contains("Hide"));
        assert!(out.html.contains(r#"<img src="recindex:42">"#));
        assert!(!out.html.contains("alt=\"x\""));
    }
}
