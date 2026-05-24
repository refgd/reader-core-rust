use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use legado_runtime::request::parse_session_cookie_json;
use legado_runtime::{
    Analyzer, AnalyzerInput, AnalyzerSession, BookSource, PlatformHost, RssAnalyzer, RssArticle,
    RssSource,
};

#[derive(Parser)]
#[command(name = "legado-cli")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Smoke {
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "我的")]
        keyword: String,
        #[arg(long)]
        session: Option<PathBuf>,
        #[arg(long)]
        timings: bool,
        #[arg(long)]
        book_url: Option<String>,
        #[arg(long)]
        skip_content: bool,
    },
    Search {
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "我的")]
        keyword: String,
        #[arg(long)]
        session: Option<PathBuf>,
    },
    Explore {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value_t = 1)]
        page: i32,
        #[arg(long)]
        session: Option<PathBuf>,
    },
    RssSmoke {
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "柯南")]
        keyword: String,
        #[arg(long, default_value_t = 1)]
        page: i32,
        #[arg(long)]
        session: Option<PathBuf>,
    },
    RssArticles {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value = "柯南")]
        keyword: String,
        #[arg(long, default_value_t = 1)]
        page: i32,
        #[arg(long)]
        session: Option<PathBuf>,
    },
    RssSorts {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        session: Option<PathBuf>,
    },
    RssContent {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        article_json: PathBuf,
        #[arg(long)]
        session: Option<PathBuf>,
        #[arg(long, hide = true)]
        mock_platform_ok: bool,
    },
}

struct MockPlatformOk;

impl PlatformHost for MockPlatformOk {
    fn handle_platform_action(&self, api: &str, _source_name: &str, args_json: &str) -> String {
        let url = serde_json::from_str::<serde_json::Value>(args_json)
            .ok()
            .and_then(|value| {
                value
                    .get("args")
                    .and_then(serde_json::Value::as_array)
                    .and_then(|args| args.get(1))
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .unwrap_or_default();
        serde_json::json!({
            "url": url,
            "body": "ok",
            "code": 200,
            "message": "OK",
            "api": api
        })
        .to_string()
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Smoke {
            source,
            keyword,
            session,
            timings,
            book_url,
            skip_content,
        } => {
            let (source, session) = load(source, session)?;
            let started = Instant::now();
            let mut analyzer = Analyzer::new(source, session)?;
            let analyzer_ms = started.elapsed().as_millis();
            let (first, search_ms) = if let Some(book_url) = book_url {
                (
                    legado_runtime::BookItem {
                        book_url,
                        ..legado_runtime::BookItem::default()
                    },
                    0,
                )
            } else {
                let search_started = Instant::now();
                let search = analyzer.search(AnalyzerInput {
                    key: keyword,
                    page: 1,
                    ..AnalyzerInput::default()
                })?;
                let search_ms = search_started.elapsed().as_millis();
                let first = search
                    .books
                    .first()
                    .cloned()
                    .context("search returned no books")?;
                (first, search_ms)
            };
            let detail_started = Instant::now();
            let detail = analyzer.detail(AnalyzerInput {
                book_url: first.book_url.clone(),
                ..AnalyzerInput::default()
            })?;
            let detail_ms = detail_started.elapsed().as_millis();
            let book = detail.book.clone().context("detail returned no book")?;
            let toc_started = Instant::now();
            let toc = analyzer.toc(AnalyzerInput {
                toc_url: book.toc_url.clone(),
                ..AnalyzerInput::default()
            })?;
            let toc_ms = toc_started.elapsed().as_millis();
            let chapter = toc
                .chapters
                .iter()
                .find(|chapter| !chapter.is_volume.eq_ignore_ascii_case("true"))
                .or_else(|| toc.chapters.first())
                .cloned()
                .context("toc returned no chapters")?;
            let (content, final_session, content_ms) = if skip_content {
                (None, toc.session.clone(), 0)
            } else {
                let content_started = Instant::now();
                let content_out = analyzer.content(AnalyzerInput {
                    chapter_url: chapter.url.clone(),
                    ..AnalyzerInput::default()
                })?;
                (
                    content_out.content,
                    content_out.session,
                    content_started.elapsed().as_millis(),
                )
            };
            let total_ms = started.elapsed().as_millis();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "timings": timings.then_some(serde_json::json!({
                        "analyzerInitMs": analyzer_ms,
                        "searchMs": search_ms,
                        "detailMs": detail_ms,
                        "tocMs": toc_ms,
                        "contentMs": content_ms,
                        "totalMs": total_ms
                    })),
                    "searchFirst": first,
                    "detail": detail.book,
                    "tocFirst": chapter,
                    "chapterCount": toc.chapters.len(),
                    "content": content,
                    "session": final_session
                }))?
            );
        }
        Command::Search {
            source,
            keyword,
            session,
        } => {
            let (source, session) = load(source, session)?;
            let mut analyzer = Analyzer::new(source, session)?;
            let out = analyzer.search(AnalyzerInput {
                key: keyword,
                page: 1,
                ..AnalyzerInput::default()
            })?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::Explore {
            source,
            url,
            page,
            session,
        } => {
            let (source, session) = load(source, session)?;
            let mut analyzer = Analyzer::new(source, session)?;
            let out = analyzer.explore(AnalyzerInput {
                explore_url: url.unwrap_or_default(),
                page,
                ..AnalyzerInput::default()
            })?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::RssSmoke {
            source,
            keyword,
            page,
            session,
        } => {
            let (source, session) = load_rss(source, session)?;
            let mut analyzer = RssAnalyzer::new(source, session)?;
            let articles = analyzer.search(&keyword, page)?;
            let first = articles
                .articles
                .first()
                .cloned()
                .context("RSS search returned no articles")?;
            let content = analyzer.content(first.clone())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "first": first,
                    "articleCount": articles.articles.len(),
                    "nextUrl": articles.next_url,
                    "content": content.content,
                    "session": content.session
                }))?
            );
        }
        Command::RssArticles {
            source,
            url,
            keyword,
            page,
            session,
        } => {
            let (source, session) = load_rss(source, session)?;
            let mut analyzer = RssAnalyzer::new(source, session)?;
            let out = if let Some(url) = url {
                analyzer.articles("CLI", &url, &keyword, page)?
            } else {
                analyzer.search(&keyword, page)?
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::RssSorts { source, session } => {
            let (source, session) = load_rss(source, session)?;
            let mut analyzer = RssAnalyzer::new(source, session)?;
            let out = analyzer.sort_urls()?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::RssContent {
            source,
            article_json,
            session,
            mock_platform_ok,
        } => {
            let (source, session) = load_rss(source, session)?;
            let article_text = fs::read_to_string(&article_json)
                .with_context(|| format!("failed to read {}", article_json.display()))?;
            let article: RssArticle = serde_json::from_str(&article_text)
                .with_context(|| format!("failed to parse {}", article_json.display()))?;
            let platform =
                mock_platform_ok.then(|| Rc::new(MockPlatformOk) as Rc<dyn PlatformHost>);
            let mut analyzer = RssAnalyzer::new_with_platform(source, session, platform)?;
            let out = analyzer.content(article)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }
    Ok(())
}

fn load(source: PathBuf, session_path: Option<PathBuf>) -> Result<(BookSource, AnalyzerSession)> {
    let source_json = fs::read_to_string(&source)
        .with_context(|| format!("failed to read {}", source.display()))?;
    let source = BookSource::parse_first(&source_json).map_err(anyhow::Error::msg)?;
    let mut session = AnalyzerSession::default();
    if let Some(session_path) = session_path {
        let session_json = fs::read_to_string(&session_path)
            .with_context(|| format!("failed to read {}", session_path.display()))?;
        session.cookies = parse_session_cookie_json(&session_json);
    }
    Ok((source, session))
}

fn load_rss(
    source: PathBuf,
    session_path: Option<PathBuf>,
) -> Result<(RssSource, AnalyzerSession)> {
    let source_json = fs::read_to_string(&source)
        .with_context(|| format!("failed to read {}", source.display()))?;
    let source = RssSource::parse_first(&source_json).map_err(anyhow::Error::msg)?;
    let mut session = AnalyzerSession::default();
    if let Some(session_path) = session_path {
        let session_json = fs::read_to_string(&session_path)
            .with_context(|| format!("failed to read {}", session_path.display()))?;
        session.cookies = parse_session_cookie_json(&session_json);
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&session_json) {
            if let Some(variables) = value
                .get("variables")
                .and_then(serde_json::Value::as_object)
            {
                session.variables = variables
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect();
            }
            if let Some(source_variable) = value
                .get("sourceVariable")
                .and_then(serde_json::Value::as_str)
            {
                session.source_variable = source_variable.to_string();
            }
            if let Some(cache) = value.get("cache").and_then(serde_json::Value::as_object) {
                session.cache = cache
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect();
            }
            if let Some(store) = value
                .get("sourceStore")
                .and_then(serde_json::Value::as_object)
            {
                session.source_store = store
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.to_string()))
                    })
                    .collect();
            }
        }
    }
    Ok((source, session))
}
