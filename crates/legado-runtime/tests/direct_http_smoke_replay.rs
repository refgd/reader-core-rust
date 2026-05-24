use std::fs;
use std::path::{Path, PathBuf};

use legado_runtime::request::parse_session_cookie_json;
use legado_runtime::{Analyzer, AnalyzerInput, AnalyzerSession, BookSource};
use regex::Regex;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn load_source(path: &str) -> BookSource {
    let text = fs::read_to_string(workspace_root().join(path)).expect("source fixture");
    BookSource::parse_first(&text).expect("source parse")
}

fn load_session(path: &str) -> AnalyzerSession {
    let text = fs::read_to_string(workspace_root().join(path)).expect("session fixture");
    AnalyzerSession {
        cookies: parse_session_cookie_json(&text),
        ..AnalyzerSession::default()
    }
}

fn assert_smoke_replay_with_session(source_path: &str, session: AnalyzerSession) {
    let source = load_source(source_path);
    let mut analyzer = Analyzer::new(source, session).expect("analyzer");
    let search = analyzer
        .search(AnalyzerInput {
            key: "我的".to_string(),
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("search");
    let first = search
        .books
        .first()
        .cloned()
        .expect("search returned books");
    assert!(!first.name.is_empty(), "first search result has a name");
    assert!(!first.book_url.is_empty(), "first search result has a URL");

    let detail = analyzer
        .detail(AnalyzerInput {
            book_url: first.book_url,
            ..AnalyzerInput::default()
        })
        .expect("detail");
    let book = detail.book.expect("detail returned book");
    assert!(!book.name.is_empty(), "detail has a name");
    assert!(!book.toc_url.is_empty(), "detail has a toc URL");
    assert!(
        !contains_text_html_tag(&book.intro),
        "detail intro is formatted for display, not raw HTML: {}",
        book.intro
    );

    let toc = analyzer
        .toc(AnalyzerInput {
            toc_url: book.toc_url,
            ..AnalyzerInput::default()
        })
        .expect("toc");
    let chapter = toc
        .chapters
        .iter()
        .find(|chapter| !chapter.is_volume.eq_ignore_ascii_case("true"))
        .or_else(|| toc.chapters.first())
        .cloned()
        .expect("toc returned chapters");
    assert!(!chapter.title.is_empty(), "first chapter has a title");
    assert!(!chapter.url.is_empty(), "first chapter has a URL");

    let content = analyzer
        .content(AnalyzerInput {
            chapter_url: chapter.url,
            ..AnalyzerInput::default()
        })
        .expect("content")
        .content
        .expect("content output");
    assert!(
        !content.content.trim().is_empty(),
        "content body is not empty"
    );
    assert!(
        !contains_text_html_tag(&content.content),
        "content is formatted for reading, not raw HTML: {}",
        content.content
    );
    assert!(
        !content
            .content
            .chars()
            .any(|ch| ('\u{e800}'..='\u{e863}').contains(&ch)),
        "content private-use glyphs were normalized"
    );
}

fn contains_text_html_tag(value: &str) -> bool {
    Regex::new(r"(?i)</?(?:p|div|span|br|article|section|h\d|dd|dl)\b")
        .expect("valid html tag smoke regex")
        .is_match(value)
}

fn assert_smoke_replay(source_path: &str) {
    assert_smoke_replay_with_session(source_path, AnalyzerSession::default());
}

#[test]
fn qimao_smoke_replays_from_cache() {
    assert_smoke_replay("sources/bookSource_七猫小说.json");
}

#[test]
fn qimao_explore_category_uses_rule_book_url_script() {
    let source = load_source("sources/bookSource_七猫小说.json");
    let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).expect("analyzer");
    let explore = analyzer
        .explore(AnalyzerInput {
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("explore kinds");
    let category_url = explore
        .explore
        .iter()
        .find(|item| item.title == "历史")
        .expect("历史 category")
        .url
        .clone();
    assert!(
        category_url.contains("baidu.com/category/"),
        "七猫 exploreUrl keeps the original placeholder URL for baseUrl semantics"
    );

    let books = analyzer
        .explore(AnalyzerInput {
            explore_url: category_url,
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("explore books");
    let first = books.books.first().expect("explore returned books");
    assert!(!first.name.is_empty(), "explore book has a name");
    assert!(
        first
            .book_url
            .contains("api-bc.wtzw.com/api/v4/book/detail"),
        "ruleExplore.bookUrl JS rewrites the placeholder into a real detail API URL: {}",
        first.book_url
    );
    assert!(
        !first.book_url.contains("baidu.com/category"),
        "bookUrl must not leak the explore placeholder URL: {}",
        first.book_url
    );
}

#[test]
fn yueyou_smoke_replays_from_cache() {
    assert_smoke_replay("sources/bookSource_阅友小说.json");
}

#[test]
fn yodu_smoke_replays_from_cache() {
    assert_smoke_replay("sources/bookSource_有度中文.json");
}

#[test]
fn guangyu_smoke_replays_from_cache_with_session() {
    assert_smoke_replay_with_session(
        "sources/bookSource_光遇聚合.json",
        load_session(".legado-cli/session.json"),
    );
}

#[test]
fn guangyu_explore_replays_from_cache_with_platform_diagnostics() {
    let source = load_source("sources/bookSource_光遇聚合.json");
    let mut analyzer =
        Analyzer::new(source, load_session(".legado-cli/session.json")).expect("analyzer");
    let explore = analyzer
        .explore(AnalyzerInput {
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("explore kinds");
    assert!(
        explore
            .explore
            .iter()
            .any(|item| item.title.contains("玄幻")),
        "exploreUrl returned discover categories"
    );
    assert!(
        explore
            .diagnostics
            .iter()
            .any(|item| item.contains("UnsupportedPlatformApi")
                && item.contains("java.startBrowser")
                && item.contains("rulePath=exploreUrl")),
        "browser/login UI actions are reported as platform boundaries"
    );

    let category_url = explore
        .explore
        .iter()
        .find(|item| item.title == "玄幻")
        .expect("玄幻 category")
        .url
        .clone();
    let books = analyzer
        .explore(AnalyzerInput {
            explore_url: category_url,
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("explore books");
    let first = books.books.first().expect("explore returned books");
    assert!(!first.name.is_empty(), "explore book has a name");
    assert!(
        first.book_url.starts_with("data:"),
        "explore book URL is routed through source detail data URL"
    );
}

#[test]
fn dahuilang_explore_missing_json_fields_do_not_abort() {
    let source = load_source("sources/bookSource_大灰狼.json");
    let mut analyzer = Analyzer::new(source, AnalyzerSession::default()).expect("analyzer");
    let explore = analyzer
        .explore(AnalyzerInput {
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("explore kinds");
    let category_url = explore
        .explore
        .iter()
        .find(|item| item.title == "巅峰榜(男女合频)")
        .expect("巅峰榜 category")
        .url
        .clone();

    let books = analyzer
        .explore(AnalyzerInput {
            explore_url: category_url,
            page: 1,
            ..AnalyzerInput::default()
        })
        .expect("explore books");
    let first = books.books.first().expect("explore returned books");
    assert!(!first.name.is_empty(), "explore book has a name");
    assert!(
        first.book_url.starts_with("data:"),
        "explore book URL is routed through source detail data URL"
    );
}
