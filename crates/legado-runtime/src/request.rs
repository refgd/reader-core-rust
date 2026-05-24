use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Method, Proxy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};
use crate::session::AnalyzerSession;

pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 LegadoRustAnalyzer/0.1";
const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct RequestEngine {
    client: Client,
    no_redirect_client: Client,
    default_headers: Vec<(String, String)>,
    rate_limit: Arc<Mutex<Option<RateLimitConfig>>>,
}

#[derive(Debug, Clone)]
struct RateLimitConfig {
    key: String,
    access_limit: u32,
    interval_ms: u64,
}

#[derive(Debug, Clone)]
struct RateLimitRecord {
    window_start: Instant,
    frequency: u32,
    access_limit: u32,
    interval_ms: u64,
}

static CONCURRENT_RECORDS: OnceLock<Mutex<HashMap<String, RateLimitRecord>>> = OnceLock::new();

fn concurrent_records() -> &'static Mutex<HashMap<String, RateLimitRecord>> {
    CONCURRENT_RECORDS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Clone)]
pub struct RequestOutput {
    pub url: String,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct RawRequestOutput {
    pub url: String,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MultipartFilePart {
    pub field_name: String,
    pub file_name: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegadoRequest {
    pub url: String,
    pub options_json: Option<String>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub body_base64: Option<String>,
    pub charset: Option<String>,
    pub dns_ip: Option<String>,
    pub origin: Option<String>,
    pub call_timeout_ms: Option<u64>,
    pub proxy: Option<String>,
    pub follow_redirects: bool,
    pub retry_attempts: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CachedResponseMeta {
    cache_version: u8,
    request_url: String,
    final_url: String,
    method: String,
    status: Option<u16>,
    body_file: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    content_type: Option<String>,
}

impl RequestEngine {
    pub fn new() -> Result<Self> {
        Self::new_with_default_headers(Vec::new())
    }

    pub fn new_with_default_headers(default_headers: Vec<(String, String)>) -> Result<Self> {
        Self::new_with_default_headers_and_rate_limit(default_headers, "", "")
    }

    pub fn new_with_default_headers_and_rate_limit(
        default_headers: Vec<(String, String)>,
        source_key: &str,
        concurrent_rate: &str,
    ) -> Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_CALL_TIMEOUT)
            .build()
            .map_err(|err| Diagnostic::new(DiagnosticKind::Request, err.to_string()))?;
        let no_redirect_client = Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_CALL_TIMEOUT)
            .build()
            .map_err(|err| Diagnostic::new(DiagnosticKind::Request, err.to_string()))?;
        Ok(Self {
            client,
            no_redirect_client,
            default_headers,
            rate_limit: Arc::new(Mutex::new(parse_rate_limit(source_key, concurrent_rate))),
        })
    }

    pub fn update_concurrent_rate(&self, source_key: &str, concurrent_rate: &str) {
        let mut rate_limit = self.rate_limit.lock().expect("rate limit poisoned");
        *rate_limit = parse_rate_limit(source_key, concurrent_rate);
    }

    pub fn get_text(&self, raw_url: &str, session: &mut AnalyzerSession) -> Result<RequestOutput> {
        let parsed = parse_legado_request(raw_url)?;
        self.execute_parsed_text(parsed, session)
    }

    pub fn get_text_with_timeout(
        &self,
        raw_url: &str,
        headers: Vec<(String, String)>,
        call_timeout_ms: Option<u64>,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        let mut parsed = parse_legado_request(raw_url)?;
        parsed.headers = merge_header_pairs(headers, parsed.headers);
        parsed.call_timeout_ms = call_timeout_ms;
        self.execute_parsed_text(parsed, session)
    }

    pub fn get_text_with_timeout_and_rate_limit(
        &self,
        raw_url: &str,
        headers: Vec<(String, String)>,
        call_timeout_ms: Option<u64>,
        skip_rate_limit: bool,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        let mut parsed = parse_legado_request(raw_url)?;
        parsed.headers = merge_header_pairs(headers, parsed.headers);
        parsed.call_timeout_ms = call_timeout_ms;
        self.execute_parsed_text_with_rate_limit(parsed, session, skip_rate_limit)
    }

    pub fn get_raw(
        &self,
        raw_url: &str,
        session: &mut AnalyzerSession,
    ) -> Result<RawRequestOutput> {
        let parsed = parse_legado_request(raw_url)?;
        self.execute_parsed_raw(parsed, session)
    }

    pub fn get_raw_with_timeout_and_rate_limit(
        &self,
        raw_url: &str,
        headers: Vec<(String, String)>,
        call_timeout_ms: Option<u64>,
        skip_rate_limit: bool,
        session: &mut AnalyzerSession,
    ) -> Result<RawRequestOutput> {
        let mut parsed = parse_legado_request(raw_url)?;
        parsed.headers = merge_header_pairs(headers, parsed.headers);
        parsed.call_timeout_ms = call_timeout_ms;
        self.execute_parsed_raw_with_rate_limit(parsed, session, skip_rate_limit)
    }

    pub fn request_text(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        self.request_text_with_timeout(url, method, headers, body, None, session)
    }

    pub fn request_text_with_timeout(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
        call_timeout_ms: Option<u64>,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        self.request_text_with_timeout_and_redirects(
            url,
            method,
            headers,
            body,
            call_timeout_ms,
            true,
            session,
        )
    }

    pub fn request_text_with_timeout_and_redirects(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
        call_timeout_ms: Option<u64>,
        follow_redirects: bool,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        let parsed = LegadoRequest {
            url: url.to_string(),
            options_json: None,
            method: method.to_ascii_uppercase(),
            headers,
            body,
            body_base64: None,
            charset: None,
            dns_ip: None,
            origin: None,
            call_timeout_ms,
            proxy: None,
            follow_redirects,
            retry_attempts: 0,
        };
        self.execute_parsed_text(parsed, session)
    }

    pub fn request_raw(
        &self,
        url: &str,
        method: &str,
        headers: Vec<(String, String)>,
        body: Option<String>,
        session: &mut AnalyzerSession,
    ) -> Result<RawRequestOutput> {
        let parsed = LegadoRequest {
            url: url.to_string(),
            options_json: None,
            method: method.to_ascii_uppercase(),
            headers,
            body,
            body_base64: None,
            charset: None,
            dns_ip: None,
            origin: None,
            call_timeout_ms: None,
            proxy: None,
            follow_redirects: true,
            retry_attempts: 0,
        };
        self.execute_parsed_raw(parsed, session)
    }

    fn wait_for_rate_limit(&self, skip_rate_limit: bool) {
        if skip_rate_limit {
            return;
        }
        let Some(config) = self.rate_limit.lock().expect("rate limit poisoned").clone() else {
            return;
        };
        loop {
            let wait = {
                let mut records = concurrent_records()
                    .lock()
                    .expect("concurrent records poisoned");
                let now = Instant::now();
                let record = records
                    .entry(config.key.clone())
                    .or_insert(RateLimitRecord {
                        window_start: now,
                        frequency: 0,
                        access_limit: config.access_limit,
                        interval_ms: config.interval_ms,
                    });
                record.access_limit = config.access_limit;
                record.interval_ms = config.interval_ms;
                let elapsed_ms = now
                    .saturating_duration_since(record.window_start)
                    .as_millis() as u64;
                if elapsed_ms >= record.interval_ms {
                    record.window_start = now;
                    record.frequency = 1;
                    0
                } else if record.frequency < record.access_limit {
                    record.frequency += 1;
                    0
                } else {
                    record.interval_ms.saturating_sub(elapsed_ms)
                }
            };
            if wait == 0 {
                return;
            }
            thread::sleep(Duration::from_millis(wait));
        }
    }

    pub fn upload_multipart_text(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        fields: Vec<(String, String)>,
        file: MultipartFilePart,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        let raw = self.upload_multipart_raw(url, headers, fields, file, session)?;
        Ok(RequestOutput {
            url: raw.url,
            status: raw.status,
            headers: raw.headers,
            content_type: raw.content_type,
            body: String::from_utf8_lossy(&raw.body).into_owned(),
        })
    }

    pub fn upload_multipart_raw(
        &self,
        url: &str,
        headers: Vec<(String, String)>,
        fields: Vec<(String, String)>,
        file: MultipartFilePart,
        session: &mut AnalyzerSession,
    ) -> Result<RawRequestOutput> {
        let parsed = LegadoRequest {
            url: url.to_string(),
            options_json: None,
            method: "POST".to_string(),
            headers,
            body: None,
            body_base64: None,
            charset: None,
            dns_ip: None,
            origin: None,
            call_timeout_ms: None,
            proxy: None,
            follow_redirects: true,
            retry_attempts: 0,
        };
        self.upload_multipart_raw_with_request(parsed, fields, file, session)
    }

    pub fn upload_multipart_text_with_request(
        &self,
        parsed: LegadoRequest,
        fields: Vec<(String, String)>,
        file: MultipartFilePart,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        let raw = self.upload_multipart_raw_with_request(parsed, fields, file, session)?;
        Ok(RequestOutput {
            url: raw.url,
            status: raw.status,
            headers: raw.headers,
            content_type: raw.content_type,
            body: String::from_utf8_lossy(&raw.body).into_owned(),
        })
    }

    pub fn upload_multipart_raw_with_request(
        &self,
        mut parsed: LegadoRequest,
        fields: Vec<(String, String)>,
        file: MultipartFilePart,
        session: &mut AnalyzerSession,
    ) -> Result<RawRequestOutput> {
        parsed.url = strip_query(&parsed.url)?;
        parsed.method = "POST".to_string();
        parsed.body = None;
        parsed.body_base64 = None;
        parsed.charset = None;

        if let Ok(parsed_url) = Url::parse(&parsed.url) {
            let host = parsed_url.host_str().unwrap_or_default();
            let cookie = session.get_cookie(host);
            if !cookie.is_empty()
                && !parsed
                    .headers
                    .iter()
                    .any(|(key, _)| key.eq_ignore_ascii_case("cookie"))
            {
                parsed.headers.push(("Cookie".to_string(), cookie));
            }
        }
        let mut header_pairs = self.default_headers.clone();
        for (key, value) in &parsed.headers {
            if let Some((_, existing)) = header_pairs
                .iter_mut()
                .find(|(existing_key, _)| existing_key.eq_ignore_ascii_case(key))
            {
                *existing = value.clone();
            } else {
                header_pairs.push((key.clone(), value.clone()));
            }
        }
        if let Ok(parsed_url) = Url::parse(&parsed.url) {
            let host = parsed_url.host_str().unwrap_or_default();
            merge_session_cookie_header(&mut header_pairs, &session.get_cookie(host));
        }
        if parsed.proxy.is_none() {
            parsed.proxy = take_proxy_header(&mut header_pairs);
        } else {
            let _ = take_proxy_header(&mut header_pairs);
        }
        let mut header_map = header_map_from_pairs(&header_pairs)?;
        if !header_map.contains_key(USER_AGENT) {
            header_map.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        }
        parsed.headers = header_pairs;
        let override_client = build_override_client(&parsed)?;
        let default_client = if parsed.follow_redirects {
            &self.client
        } else {
            &self.no_redirect_client
        };
        let client = override_client.as_ref().unwrap_or(default_client);
        let mut output_result = None;
        let retry_attempts = effective_retry_attempts(&parsed);
        for attempt in 0..=retry_attempts {
            let form = build_multipart_form(&fields, &file)?;
            match client
                .post(&parsed.url)
                .headers(header_map.clone())
                .multipart(form)
                .send()
            {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let final_url = response.url().to_string();
                    let response_headers = response_headers_to_pairs(response.headers());
                    let content_type = response_content_type(response.headers());
                    match response.bytes() {
                        Ok(bytes) => {
                            output_result = Some(Ok(RawRequestOutput {
                                url: final_url,
                                status: Some(status),
                                headers: response_headers,
                                content_type,
                                body: bytes.to_vec(),
                            }));
                            break;
                        }
                        Err(err) if attempt < retry_attempts => {
                            output_result = Some(Err(request_diag(
                                "error reading multipart upload response",
                                err,
                                &parsed,
                                Some(status),
                            )
                            .with_request(final_url.clone(), Some(status))));
                        }
                        Err(err) => {
                            output_result = Some(Err(request_diag(
                                "error reading multipart upload response",
                                err,
                                &parsed,
                                Some(status),
                            )
                            .with_request(final_url.clone(), Some(status))));
                            break;
                        }
                    }
                }
                Err(err) if attempt < retry_attempts => {
                    output_result = Some(Err(request_diag(
                        "error sending multipart upload",
                        err,
                        &parsed,
                        None,
                    )));
                }
                Err(err) => {
                    output_result = Some(Err(request_diag(
                        "error sending multipart upload",
                        err,
                        &parsed,
                        None,
                    )));
                    break;
                }
            }
        }
        let output = output_result.expect("multipart request loop always runs")?;
        store_response_cookies_from_pairs(session, &output.url, &output.headers);
        Ok(output)
    }

    fn execute_parsed_text(
        &self,
        parsed: LegadoRequest,
        session: &mut AnalyzerSession,
    ) -> Result<RequestOutput> {
        self.execute_parsed_text_with_rate_limit(parsed, session, false)
    }

    fn execute_parsed_text_with_rate_limit(
        &self,
        parsed: LegadoRequest,
        session: &mut AnalyzerSession,
        skip_rate_limit: bool,
    ) -> Result<RequestOutput> {
        let hex_body = request_has_type_option(&parsed);
        if let Some(data) = decode_data_url_for_request(&parsed)? {
            let content_type = data_url_content_type(&parsed.url);
            return Ok(RequestOutput {
                url: parsed.url,
                status: None,
                headers: Vec::new(),
                content_type,
                body: data,
            });
        }
        let raw = self.execute_parsed_raw_with_rate_limit(parsed, session, skip_rate_limit)?;
        Ok(RequestOutput {
            url: raw.url,
            status: raw.status,
            headers: raw.headers,
            content_type: raw.content_type,
            body: if hex_body {
                hex::encode(raw.body)
            } else {
                String::from_utf8_lossy(&raw.body).into_owned()
            },
        })
    }

    fn execute_parsed_raw(
        &self,
        parsed: LegadoRequest,
        session: &mut AnalyzerSession,
    ) -> Result<RawRequestOutput> {
        self.execute_parsed_raw_with_rate_limit(parsed, session, false)
    }

    fn execute_parsed_raw_with_rate_limit(
        &self,
        mut parsed: LegadoRequest,
        session: &mut AnalyzerSession,
        skip_rate_limit: bool,
    ) -> Result<RawRequestOutput> {
        apply_charset_encoding(&mut parsed)?;
        if legado_request_wants_webview(&parsed)? {
            return Err(Diagnostic::new(
                DiagnosticKind::UnsupportedPlatformApi,
                format!(
                    "request option `webView` requires WebView platform boundary; rawUrl={}",
                    excerpt(
                        &parsed
                            .options_json
                            .as_ref()
                            .map(|options| format!("{},{}", parsed.url, options))
                            .unwrap_or_else(|| parsed.url.clone()),
                        500,
                    )
                ),
            )
            .with_request(parsed.url.clone(), None));
        }
        if let Some(bytes) = decode_data_url_bytes(&parsed.url)? {
            let content_type = data_url_content_type(&parsed.url);
            return Ok(RawRequestOutput {
                url: parsed.url,
                status: None,
                headers: Vec::new(),
                content_type,
                body: bytes,
            });
        }
        self.wait_for_rate_limit(skip_rate_limit);

        if let Ok(url) = Url::parse(&parsed.url) {
            let host = url.host_str().unwrap_or_default();
            let cookie = session.get_cookie(host);
            if !cookie.is_empty()
                && !parsed
                    .headers
                    .iter()
                    .any(|(key, _)| key.eq_ignore_ascii_case("cookie"))
            {
                parsed.headers.push(("Cookie".to_string(), cookie));
            }
        }

        if let Some(cached) = try_read_http_cache(&parsed)? {
            return Ok(cached);
        }

        let mut header_pairs = self.default_headers.clone();
        for (key, value) in &parsed.headers {
            if let Some((_, existing)) = header_pairs
                .iter_mut()
                .find(|(existing_key, _)| existing_key.eq_ignore_ascii_case(key))
            {
                *existing = value.clone();
            } else {
                header_pairs.push((key.clone(), value.clone()));
            }
        }
        if let Ok(url) = Url::parse(&parsed.url) {
            let host = url.host_str().unwrap_or_default();
            merge_session_cookie_header(&mut header_pairs, &session.get_cookie(host));
        }
        parsed.proxy = take_proxy_header(&mut header_pairs);
        let mut headers = header_map_from_pairs(&header_pairs)?;
        if !headers.contains_key(USER_AGENT) {
            headers.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        }
        let method = Method::from_bytes(parsed.method.as_bytes())
            .map_err(|err| request_diag("invalid HTTP method", err, &parsed, None))?;
        let default_client = if parsed.follow_redirects {
            &self.client
        } else {
            &self.no_redirect_client
        };
        let override_client = build_override_client(&parsed)?;
        let client = override_client.as_ref().unwrap_or(default_client);
        let body_bytes = if let Some(body_base64) = parsed.body_base64.as_deref() {
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(body_base64.as_bytes())
                    .map_err(|err| request_diag("invalid bodyBase64", err, &parsed, None))?,
            )
        } else {
            parsed.body.clone().map(String::into_bytes)
        };
        let mut output_result = None;
        let retry_attempts = effective_retry_attempts(&parsed);
        for attempt in 0..=retry_attempts {
            let mut builder = client
                .request(method.clone(), &parsed.url)
                .headers(headers.clone());
            if let Some(body) = body_bytes.clone() {
                builder = builder.body(body);
            }
            match builder.send() {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let final_url = response.url().to_string();
                    let response_headers = response_headers_to_pairs(response.headers());
                    let content_type = response_content_type(response.headers());
                    match response.bytes() {
                        Ok(bytes) => {
                            cache_http_response(
                                &parsed,
                                &final_url,
                                Some(status),
                                &response_headers,
                                content_type.as_deref(),
                                &bytes,
                            );
                            output_result = Some(Ok(RawRequestOutput {
                                url: final_url,
                                status: Some(status),
                                headers: response_headers,
                                content_type,
                                body: bytes.to_vec(),
                            }));
                            break;
                        }
                        Err(err) if attempt < retry_attempts => {
                            output_result = Some(Err(request_diag(
                                "error reading response body",
                                err,
                                &parsed,
                                Some(status),
                            )
                            .with_request(final_url.clone(), Some(status))));
                        }
                        Err(err) => {
                            output_result = Some(Err(request_diag(
                                "error reading response body",
                                err,
                                &parsed,
                                Some(status),
                            )
                            .with_request(final_url.clone(), Some(status))));
                            break;
                        }
                    }
                }
                Err(err) if attempt < retry_attempts => {
                    output_result = Some(Err(request_diag(
                        "error sending request",
                        err,
                        &parsed,
                        None,
                    )));
                }
                Err(err) => {
                    output_result = Some(Err(request_diag(
                        "error sending request",
                        err,
                        &parsed,
                        None,
                    )));
                    break;
                }
            }
        }
        let output = output_result.expect("request loop always runs")?;
        if let Some(status) = output.status {
            if status > 0 {
                store_response_cookies_from_pairs(session, &output.url, &output.headers);
            }
        }
        Ok(output)
    }
}

fn build_override_client(request: &LegadoRequest) -> Result<Option<Client>> {
    let has_dns_override = request
        .dns_ip
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_proxy = request
        .proxy
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_dns_override && !has_proxy && request.call_timeout_ms.is_none() {
        return Ok(None);
    };

    let redirect = if request.follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let mut builder = Client::builder()
        .cookie_store(true)
        .redirect(redirect)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .timeout(request_timeout_duration(request.call_timeout_ms));

    if let Some(proxy) = request
        .proxy
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        builder = builder.proxy(parse_proxy_option(proxy, request)?);
    }

    if let Some(dns_ip) = request
        .dns_ip
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let url = Url::parse(&request.url)
            .map_err(|err| request_diag("invalid URL for dnsIp", err, request, None))?;
        if let Some(host) = url.host_str() {
            let Some(port) = url.port_or_known_default() else {
                return Err(request_diag_msg(
                    "unsupported URL scheme for dnsIp",
                    "missing default port",
                    request,
                    None,
                ));
            };
            let addrs = resolve_dns_ip_option(dns_ip, port);
            if !addrs.is_empty() {
                builder = builder.resolve_to_addrs(host, &addrs);
            }
        }
    }

    builder
        .build()
        .map(Some)
        .map_err(|err| request_diag("error building request override client", err, request, None))
}

fn request_timeout_duration(call_timeout_ms: Option<u64>) -> Option<Duration> {
    match call_timeout_ms {
        None => Some(DEFAULT_CALL_TIMEOUT),
        Some(0) => None,
        Some(ms) => Some(Duration::from_millis(ms)),
    }
}

fn effective_retry_attempts(request: &LegadoRequest) -> u32 {
    request.retry_attempts.max(1)
}

fn take_proxy_header(headers: &mut Vec<(String, String)>) -> Option<String> {
    let position = headers
        .iter()
        .rposition(|(key, _)| key.eq_ignore_ascii_case("proxy"))?;
    let (_, value) = headers.remove(position);
    (!value.trim().is_empty()).then_some(value)
}

fn parse_proxy_option(raw_proxy: &str, request: &LegadoRequest) -> Result<Proxy> {
    let proxy_url = normalize_legacy_proxy_url(raw_proxy).ok_or_else(|| {
        request_diag_msg(
            "invalid proxy header",
            "expected http|socks4|socks5://host:port[@user@pass]",
            request,
            None,
        )
    })?;
    Proxy::all(&proxy_url).map_err(|err| request_diag("invalid proxy header", err, request, None))
}

fn build_multipart_form(fields: &[(String, String)], file: &MultipartFilePart) -> Result<Form> {
    let mut form = Form::new();
    for (key, value) in fields {
        form = form.text(key.clone(), value.clone());
    }
    let part = Part::bytes(file.body.clone())
        .file_name(file.file_name.clone())
        .mime_str(&file.content_type)
        .map_err(|err| Diagnostic::new(DiagnosticKind::Request, err.to_string()))?;
    Ok(form.part(file.field_name.clone(), part))
}

fn normalize_legacy_proxy_url(raw_proxy: &str) -> Option<String> {
    let raw_proxy = raw_proxy.trim();
    let (scheme, rest) = raw_proxy.split_once("://")?;
    if !matches!(scheme, "http" | "socks4" | "socks5") {
        return None;
    }
    let (host_port, auth) = match rest.rsplit_once('@') {
        Some((before_pass, password)) => match before_pass.rsplit_once('@') {
            Some((host_port, username)) => (host_port, Some((username, password))),
            None => (rest, None),
        },
        None => (rest, None),
    };
    let (host, port) = host_port.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().is_err() {
        return None;
    }
    Some(match auth {
        Some((username, password)) if !username.is_empty() && !password.is_empty() => {
            format!("{scheme}://{username}:{password}@{host}:{port}")
        }
        _ => format!("{scheme}://{host}:{port}"),
    })
}

fn merge_header_pairs(
    mut base: Vec<(String, String)>,
    overrides: Vec<(String, String)>,
) -> Vec<(String, String)> {
    for (key, value) in overrides {
        if let Some((_, existing)) = base
            .iter_mut()
            .find(|(existing_key, _)| existing_key.eq_ignore_ascii_case(&key))
        {
            *existing = value;
        } else {
            base.push((key, value));
        }
    }
    base
}

fn resolve_dns_ip_option(dns_ip: &str, port: u16) -> Vec<SocketAddr> {
    dns_ip
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .flat_map(|value| {
            if let Ok(ip) = value.parse::<IpAddr>() {
                return vec![SocketAddr::new(ip, port)];
            }
            (value, port)
                .to_socket_addrs()
                .map(|addrs| addrs.collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect()
}

fn store_response_cookies_from_pairs(
    session: &mut AnalyzerSession,
    final_url: &str,
    headers: &[(String, String)],
) {
    let Ok(url) = Url::parse(final_url) else {
        return;
    };
    let Some(host) = url.host_str() else {
        return;
    };
    let mut pairs = parse_cookie_pairs(&session.get_cookie(host));
    for (_, value) in headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
    {
        let Some((name, cookie_value)) = value
            .split(';')
            .next()
            .and_then(|part| part.trim().split_once('='))
        else {
            continue;
        };
        if !name.trim().is_empty() {
            pairs.insert(name.trim().to_string(), cookie_value.trim().to_string());
        }
    }
    if !pairs.is_empty() {
        let cookie = pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        session.set_cookie(host, cookie);
    }
}

fn parse_cookie_pairs(cookie: &str) -> std::collections::BTreeMap<String, String> {
    cookie
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            (!name.trim().is_empty()).then(|| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn merge_session_cookie_header(headers: &mut Vec<(String, String)>, session_cookie: &str) {
    if session_cookie.trim().is_empty() {
        return;
    }
    let mut merged = parse_cookie_pairs(session_cookie);
    let mut first_cookie_index = None;
    let existing_cookies = headers
        .iter()
        .enumerate()
        .filter_map(|(index, (key, value))| {
            if key.eq_ignore_ascii_case("cookie") {
                if first_cookie_index.is_none() {
                    first_cookie_index = Some(index);
                }
                Some(value.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for cookie in existing_cookies {
        merged.extend(parse_cookie_pairs(&cookie));
    }
    let cookie = merged
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    headers.retain(|(key, _)| !key.eq_ignore_ascii_case("cookie"));
    if let Some(index) = first_cookie_index {
        headers.insert(index.min(headers.len()), ("Cookie".to_string(), cookie));
    } else {
        headers.push(("Cookie".to_string(), cookie));
    }
}

fn strip_query(raw_url: &str) -> Result<String> {
    let mut url = Url::parse(raw_url)
        .map_err(|err| Diagnostic::new(DiagnosticKind::Request, err.to_string()))?;
    url.set_query(None);
    Ok(url.to_string())
}

pub fn parse_legado_request(raw_url: &str) -> Result<LegadoRequest> {
    let (url, options_json) = split_legado_url_options(raw_url);
    let mut parsed = LegadoRequest {
        url,
        options_json,
        method: "GET".to_string(),
        headers: Vec::new(),
        body: None,
        body_base64: None,
        charset: None,
        dns_ip: None,
        origin: None,
        call_timeout_ms: None,
        proxy: None,
        follow_redirects: true,
        retry_attempts: 0,
    };
    let Some(options_json) = parsed.options_json.as_ref() else {
        return Ok(parsed);
    };
    let value: Value = serde_json::from_str(options_json).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "invalid request options JSON: {err}; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        )
    })?;
    if !value.is_object() {
        return Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "request options JSON must be an object; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        ));
    }
    if let Some(method) = value.get("method") {
        parsed.method = parse_request_option_method(method, raw_url)?;
    }
    if let Some(headers) = value.get("headers") {
        parsed.headers = parse_request_option_headers(headers, raw_url)?;
    }
    reject_unsupported_request_option_script(&value, "js", raw_url)?;
    reject_unsupported_request_option_script(&value, "bodyJs", raw_url)?;
    reject_unsupported_request_option_script(&value, "body_js", raw_url)?;
    reject_unsupported_request_option_script(&value, "webJs", raw_url)?;
    reject_unsupported_request_option_script(&value, "web_js", raw_url)?;
    reject_unsupported_request_option_webview_delay(&value, "webViewDelayTime", raw_url)?;
    reject_unsupported_request_option_webview_delay(&value, "web_view_delay_time", raw_url)?;
    if let Some(type_value) = value.get("type") {
        let _ = parse_request_option_optional_string(type_value, "type", raw_url)?;
    }
    if let Some(body) = value.get("body") {
        parsed.body = parse_request_option_body(body, raw_url)?;
        if parsed.body.is_some() && value.get("method").is_none() {
            parsed.method = "POST".to_string();
        }
    }
    if let Some(body_base64) = value.get("bodyBase64").or_else(|| value.get("body_base64")) {
        parsed.body_base64 =
            parse_request_option_optional_string(body_base64, "bodyBase64", raw_url)?;
        if parsed.body_base64.is_some() && value.get("method").is_none() {
            parsed.method = "POST".to_string();
        }
    }
    if let Some(charset) = value.get("charset") {
        parsed.charset = parse_request_option_optional_string(charset, "charset", raw_url)?;
    }
    if let Some(dns_ip) = value.get("dnsIp").or_else(|| value.get("dns_ip")) {
        parsed.dns_ip = parse_request_option_optional_string(dns_ip, "dnsIp", raw_url)?;
    }
    if let Some(origin) = value.get("origin") {
        parsed.origin = parse_request_option_optional_string(origin, "origin", raw_url)?;
    }
    if let Some(redirect) = value
        .get("redirect")
        .or_else(|| value.get("followRedirects"))
        .or_else(|| value.get("follow_redirects"))
    {
        parsed.follow_redirects = parse_request_option_bool(redirect, "redirect", raw_url)?;
    }
    if let Some(retry) = value.get("retry") {
        parsed.retry_attempts = parse_request_option_retry(retry, raw_url)?;
    }
    Ok(parsed)
}

pub fn legado_request_wants_webview(request: &LegadoRequest) -> Result<bool> {
    let Some(options_json) = request.options_json.as_deref() else {
        return Ok(false);
    };
    let options: Value = serde_json::from_str(options_json).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "invalid request options JSON: {err}; rawUrl={}",
                excerpt(&format!("{},{}", request.url, options_json), 500)
            ),
        )
    })?;
    let Some(value) = options
        .get("webView")
        .or_else(|| options.get("webview"))
        .or_else(|| options.get("useWebView"))
        .or_else(|| options.get("use_web_view"))
    else {
        return Ok(false);
    };
    parse_request_option_bool(
        value,
        "webView",
        &format!("{},{}", request.url, options_json),
    )
}

fn reject_unsupported_request_option_script(
    options: &Value,
    key: &str,
    raw_url: &str,
) -> Result<()> {
    let Some(value) = options.get(key) else {
        return Ok(());
    };
    let has_script = match value {
        Value::Null => false,
        Value::String(value) => !value.trim().is_empty(),
        _ => true,
    };
    if has_script {
        return Err(Diagnostic::new(
            DiagnosticKind::UnsupportedRule,
            format!(
                "unsupported request option `{key}` requires Rust analyzer JS/WebView handling; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        ));
    }
    Ok(())
}

fn reject_unsupported_request_option_webview_delay(
    options: &Value,
    key: &str,
    raw_url: &str,
) -> Result<()> {
    let Some(value) = options.get(key) else {
        return Ok(());
    };
    let delay = match value {
        Value::Null => 0,
        Value::String(value) if value.trim().is_empty() => 0,
        Value::String(value) => value.trim().parse::<i64>().map_err(|_| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `{key}` must be an integer milliseconds value; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            )
        })?,
        Value::Number(value) => value.as_i64().ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `{key}` must be an integer milliseconds value; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            )
        })?,
        _ => {
            return Err(Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `{key}` must be an integer milliseconds value; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            ));
        }
    };
    if delay > 0 {
        return Err(Diagnostic::new(
            DiagnosticKind::UnsupportedPlatformApi,
            format!(
                "request option `{key}` requires WebView platform boundary; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        ));
    }
    Ok(())
}

fn parse_request_option_string<'a>(value: &'a Value, key: &str, raw_url: &str) -> Result<&'a str> {
    match value {
        Value::String(value) => Ok(value),
        Value::Null => Ok(""),
        _ => Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "request option `{key}` must be a string; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        )),
    }
}

fn parse_request_option_optional_string(
    value: &Value,
    key: &str,
    raw_url: &str,
) -> Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) if value.trim().is_empty() => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "request option `{key}` must be a string; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        )),
    }
}

fn parse_request_option_method(value: &Value, raw_url: &str) -> Result<String> {
    let method = parse_request_option_string(value, "method", raw_url)?
        .trim()
        .to_ascii_uppercase();
    if method.is_empty() {
        return Ok("GET".to_string());
    }
    Method::from_bytes(method.as_bytes())
        .map(|_| method)
        .map_err(|_| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `method` must be a valid HTTP method token; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            )
        })
}

fn parse_request_option_body(value: &Value, raw_url: &str) -> Result<Option<String>> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) if value.trim().is_empty() => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        other => serde_json::to_string(other).map(Some).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `body` could not be serialized: {err}; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            )
        }),
    }
}

fn parse_request_option_bool(value: &Value, key: &str, raw_url: &str) -> Result<bool> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::Number(value) => value.as_i64().map(|value| value != 0).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `{key}` must be a boolean; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            )
        }),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "" | "false" | "0" | "no" => Ok(false),
            "true" | "1" | "yes" => Ok(true),
            _ => Err(Diagnostic::new(
                DiagnosticKind::Request,
                format!(
                    "request option `{key}` must be a boolean; rawUrl={}",
                    excerpt(raw_url, 500)
                ),
            )),
        },
        Value::Null => Ok(false),
        _ => Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "request option `{key}` must be a boolean; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        )),
    }
}

fn parse_request_option_retry(value: &Value, raw_url: &str) -> Result<u32> {
    match value {
        Value::Null => Ok(0),
        Value::Number(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!(
                        "request option `retry` must be a non-negative integer; rawUrl={}",
                        excerpt(raw_url, 500)
                    ),
                )
            }),
        Value::String(value) => {
            if value.trim().is_empty() {
                return Ok(0);
            }
            value.trim().parse::<u32>().map_err(|_| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!(
                        "request option `retry` must be a non-negative integer; rawUrl={}",
                        excerpt(raw_url, 500)
                    ),
                )
            })
        }
        _ => Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "request option `retry` must be a non-negative integer; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        )),
    }
}

fn parse_request_option_headers(headers: &Value, raw_url: &str) -> Result<Vec<(String, String)>> {
    match headers {
        Value::Null => Ok(Vec::new()),
        Value::Object(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (key, value) in map {
                let Some(value) = scalar_to_string(value) else {
                    return Err(Diagnostic::new(
                        DiagnosticKind::Request,
                        format!(
                            "request option header `{key}` must be a scalar value; rawUrl={}",
                            excerpt(raw_url, 500)
                        ),
                    ));
                };
                out.push((key.clone(), value));
            }
            Ok(out)
        }
        Value::String(raw) => {
            if raw.trim().is_empty() {
                return Ok(Vec::new());
            }
            let headers = parse_header_map(raw);
            if headers.is_empty() {
                return Err(Diagnostic::new(
                    DiagnosticKind::Request,
                    format!(
                        "request option headers string did not contain any header pairs; rawUrl={}",
                        excerpt(raw_url, 500)
                    ),
                ));
            }
            Ok(headers)
        }
        _ => Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "request option headers must be an object or string; rawUrl={}",
                excerpt(raw_url, 500)
            ),
        )),
    }
}

pub fn parse_header_map(input: &str) -> Vec<(String, String)> {
    let input = input.trim();
    if input.is_empty() {
        return Vec::new();
    }
    if let Ok(value) = serde_json::from_str::<Value>(input) {
        if let Some(map) = value.as_object() {
            return map
                .iter()
                .filter_map(|(key, value)| {
                    scalar_to_string(value).map(|value| (key.clone(), value))
                })
                .collect();
        }
    }
    parse_lenient_header_map(input)
}

fn parse_rate_limit(source_key: &str, concurrent_rate: &str) -> Option<RateLimitConfig> {
    let concurrent_rate = concurrent_rate.trim();
    if source_key.trim().is_empty() || concurrent_rate.is_empty() || concurrent_rate == "0" {
        return None;
    }
    if let Some((access, interval)) = concurrent_rate.split_once('/') {
        let access_limit = access.trim().parse::<u32>().ok()?;
        let interval_ms = interval.trim().parse::<u64>().ok()?;
        if access_limit == 0 || interval_ms == 0 {
            return None;
        }
        return Some(RateLimitConfig {
            key: source_key.to_string(),
            access_limit,
            interval_ms,
        });
    }
    let interval_ms = concurrent_rate.parse::<u64>().ok()?;
    if interval_ms == 0 {
        return None;
    }
    Some(RateLimitConfig {
        key: source_key.to_string(),
        access_limit: 1,
        interval_ms,
    })
}

fn parse_lenient_header_map(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut body = input.trim();
    if let Some(stripped) = body.strip_prefix('{') {
        body = stripped;
    }
    if let Some(stripped) = body.strip_suffix('}') {
        body = stripped;
    }
    let bytes = body.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        while index < bytes.len() && matches!(bytes[index], b',' | b' ' | b'\n' | b'\r' | b'\t') {
            index += 1;
        }
        let Some((key, next)) = read_quoted_or_bare(body, index) else {
            break;
        };
        index = next;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b':' {
            break;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let Some((value, next)) = read_quoted_or_bare(body, index) else {
            break;
        };
        out.push((key, value));
        index = next;
        while index < bytes.len() && bytes[index] != b',' {
            index += 1;
        }
    }
    out
}

fn read_quoted_or_bare(input: &str, start: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    if start >= bytes.len() {
        return None;
    }
    if matches!(bytes[start], b'\'' | b'"') {
        let quote = bytes[start];
        let mut out = String::new();
        let mut index = start + 1;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\\' && index + 1 < bytes.len() {
                out.push(bytes[index + 1] as char);
                index += 2;
                continue;
            }
            if byte == quote {
                return Some((out, index + 1));
            }
            out.push(byte as char);
            index += 1;
        }
        return Some((out, index));
    }
    let mut index = start;
    while index < bytes.len() && !matches!(bytes[index], b',' | b'\n' | b'\r') {
        index += 1;
    }
    Some((input[start..index].trim().to_string(), index))
}

pub(crate) fn split_legado_url_options(raw_url: &str) -> (String, Option<String>) {
    let mut malformed_candidate: Option<(String, String)> = None;
    for (idx, _) in raw_url.match_indices(',').rev() {
        let candidate = raw_url[idx + 1..].trim();
        if !candidate.starts_with('{') {
            continue;
        }
        match serde_json::from_str::<Value>(candidate) {
            Ok(value) if value.is_object() => {
                return (
                    raw_url[..idx].trim().to_string(),
                    Some(candidate.to_string()),
                );
            }
            _ => {
                malformed_candidate.get_or_insert_with(|| {
                    (raw_url[..idx].trim().to_string(), candidate.to_string())
                });
            }
        }
    }
    if let Some((url, candidate)) = malformed_candidate {
        return (url, Some(candidate));
    }
    (raw_url.trim().to_string(), None)
}
fn header_map_from_pairs(headers: &[(String, String)]) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (key, value) in headers {
        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!("invalid header name {key}: {err}"),
            )
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|err| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!("invalid header value for {key}: {err}"),
            )
        })?;
        map.insert(name, header_value);
    }
    Ok(map)
}

fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

fn request_diag(
    context: &str,
    err: impl std::fmt::Display + Error,
    request: &LegadoRequest,
    status: Option<u16>,
) -> Diagnostic {
    let error = format_error_chain(&err);
    Diagnostic::new(
        DiagnosticKind::Request,
        format!(
            "{context}: {error}; url={}; method={}; headers={}; body={}; options={}",
            request.url,
            request.method,
            format_header_pairs(&request.headers),
            request
                .body
                .as_ref()
                .map(|body| excerpt(body, 240))
                .unwrap_or_else(|| "<none>".to_string()),
            request
                .options_json
                .as_ref()
                .map(|options| excerpt(options, 500))
                .unwrap_or_else(|| "<none>".to_string()),
        ),
    )
    .with_request(request.url.clone(), status)
}

fn request_diag_msg(
    context: &str,
    err: impl std::fmt::Display,
    request: &LegadoRequest,
    status: Option<u16>,
) -> Diagnostic {
    Diagnostic::new(
        DiagnosticKind::Request,
        format!(
            "{context}: {err}; url={}; method={}; headers={}; body={}; options={}",
            request.url,
            request.method,
            format_header_pairs(&request.headers),
            request
                .body
                .as_ref()
                .map(|body| excerpt(body, 240))
                .unwrap_or_else(|| "<none>".to_string()),
            request
                .options_json
                .as_ref()
                .map(|options| excerpt(options, 500))
                .unwrap_or_else(|| "<none>".to_string()),
        ),
    )
    .with_request(request.url.clone(), status)
}

fn format_error_chain(err: &(impl Error + ?Sized)) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        let part = err.to_string();
        if !message.contains(&part) {
            message.push_str(": ");
            message.push_str(&part);
        }
        source = err.source();
    }
    message
}

fn format_header_pairs(headers: &[(String, String)]) -> String {
    if headers.is_empty() {
        return "<none>".to_string();
    }
    headers
        .iter()
        .map(|(key, value)| format!("{key}={}", excerpt(value, 80)))
        .collect::<Vec<_>>()
        .join(";")
}

fn excerpt(value: &str, limit: usize) -> String {
    let mut out = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        out.push_str("...");
    }
    out
}

fn try_read_http_cache(request: &LegadoRequest) -> Result<Option<RawRequestOutput>> {
    if !is_http_url(&request.url) || is_loopback_http_url(&request.url) {
        return Ok(None);
    }
    let root = http_cache_root();
    let key = http_cache_key(request);
    let meta_path = root.join(format!("{key}.json"));
    let body_path = root.join(format!("{key}.body"));
    if !meta_path.exists() || !body_path.exists() {
        return Ok(None);
    }
    let meta = fs::read_to_string(&meta_path)
        .ok()
        .and_then(|text| serde_json::from_str::<CachedResponseMeta>(&text).ok());
    let Some(meta) = meta else {
        return Ok(None);
    };
    let body = fs::read(&body_path).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "failed to read HTTP cache body: {err}; cache={}",
                body_path.display()
            ),
        )
    })?;
    let body_text = String::from_utf8_lossy(&body);
    if is_business_error_response(&body_text) {
        return Err(Diagnostic::new(
            DiagnosticKind::Request,
            format!(
                "cached HTTP response is a business error and cannot be replayed as success; cache={}; requestUrl={}",
                body_path.display(),
                meta.request_url
            ),
        )
        .with_request(meta.final_url, meta.status));
    }
    Ok(Some(RawRequestOutput {
        url: meta.final_url,
        status: meta.status,
        headers: meta.headers,
        content_type: meta.content_type,
        body,
    }))
}

fn cache_http_response(
    request: &LegadoRequest,
    final_url: &str,
    status: Option<u16>,
    headers: &[(String, String)],
    content_type: Option<&str>,
    body: &[u8],
) {
    if !is_http_url(&request.url) || is_loopback_http_url(&request.url) {
        return;
    }
    if is_business_error_response(&String::from_utf8_lossy(body)) {
        return;
    }
    let root = http_cache_root();
    if fs::create_dir_all(&root).is_err() {
        return;
    }
    let key = http_cache_key(request);
    let body_file = format!("{key}.body");
    let meta_file = format!("{key}.json");
    let body_path = root.join(&body_file);
    let meta_path = root.join(meta_file);
    if fs::write(&body_path, body).is_err() {
        return;
    }
    let meta = CachedResponseMeta {
        cache_version: 1,
        request_url: request.url.clone(),
        final_url: final_url.to_string(),
        method: request.method.clone(),
        status,
        body_file,
        headers: headers.to_vec(),
        content_type: content_type.map(ToString::to_string),
    };
    if let Ok(text) = serde_json::to_string_pretty(&meta) {
        let _ = fs::write(meta_path, text);
    }
}

pub fn is_business_error_response(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("errors").is_some_and(|value| !value.is_null()) {
        return true;
    }
    object
        .get("error")
        .is_some_and(|value| value.is_object() || value.as_bool() == Some(true))
}

fn is_http_url(url: &str) -> bool {
    Url::parse(url)
        .map(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or(false)
}

fn is_loopback_http_url(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn http_cache_root() -> PathBuf {
    std::env::var_os("LEGADO_HTTP_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            for dir in cwd.ancestors() {
                let cache = dir.join(".legado-cli").join("http-cache");
                if cache.exists() {
                    return cache;
                }
            }
            cwd.join(".legado-cli").join("http-cache")
        })
}

pub fn http_cache_key(request: &LegadoRequest) -> String {
    let mut source = format!(
        "{}\n{}\n{}\n{}",
        request.method,
        request.url,
        request.body.as_deref().unwrap_or_default(),
        request.options_json.as_deref().unwrap_or_default()
    );
    let mut cookie_headers = request
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    cookie_headers.sort_unstable();
    if !cookie_headers.is_empty() {
        source.push_str("\ncookie:");
        source.push_str(&cookie_headers.join("; "));
    }
    format!("{:x}", md5::compute(source))
}

pub fn decode_data_url(raw_url: &str) -> Result<Option<String>> {
    decode_data_url_text(raw_url)
}

fn decode_data_url_for_request(request: &LegadoRequest) -> Result<Option<String>> {
    let Some(bytes) = decode_data_url_bytes(&request.url)? else {
        return Ok(None);
    };
    if request_has_type_option(request) {
        Ok(Some(hex::encode(bytes)))
    } else {
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

fn decode_data_url_text(raw_url: &str) -> Result<Option<String>> {
    decode_data_url_bytes(raw_url)
        .map(|bytes| bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
}

fn decode_data_url_bytes(raw_url: &str) -> Result<Option<Vec<u8>>> {
    if !raw_url.starts_with("data:") {
        return Ok(None);
    }
    let Some(comma) = raw_url.find(',') else {
        return Err(Diagnostic::new(
            DiagnosticKind::Request,
            "invalid data URL: missing comma",
        ));
    };
    let metadata = &raw_url[..comma];
    let payload = &raw_url[comma + 1..];
    let payload = payload.split(",{").next().unwrap_or(payload);
    if metadata.ends_with(";base64") || metadata.contains(";base64") {
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|err| {
                Diagnostic::new(
                    DiagnosticKind::Request,
                    format!("invalid base64 data URL: {err}"),
                )
            })
            .map(Some)
    } else {
        let decoded = percent_encoding::percent_decode_str(payload).collect::<Vec<_>>();
        Ok(Some(decoded))
    }
}

fn data_url_content_type(raw_url: &str) -> Option<String> {
    if !raw_url.starts_with("data:") {
        return None;
    }
    let comma = raw_url.find(',')?;
    let metadata = &raw_url[5..comma];
    let media_type = metadata.split(';').next().unwrap_or_default();
    (!media_type.is_empty()).then(|| media_type.to_string())
}

fn response_headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_string(), value.to_string()))
        })
        .collect()
}

fn response_content_type(headers: &HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

fn apply_charset_encoding(request: &mut LegadoRequest) -> Result<()> {
    let charset = request.charset.as_deref();
    if let Some((base, query)) = request.url.split_once('?') {
        if !query.is_empty() && !looks_percent_encoded(query) {
            request.url = format!("{base}?{}", encode_params_with_charset(query, charset)?);
        }
    }
    if request.method.eq_ignore_ascii_case("POST")
        && request.body_base64.is_none()
        && !request
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("content-type"))
    {
        match request.body.as_ref().cloned() {
            Some(body) if !body_is_json_or_xml(&body) => {
                request.body = Some(encode_params_with_charset(&body, charset)?);
                request.headers.push((
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ));
            }
            None => {
                request.body = Some(String::new());
                request.headers.push((
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn body_is_json_or_xml(body: &str) -> bool {
    let body = body.trim_start();
    body.starts_with('{') || body.starts_with('[') || body.starts_with('<')
}

fn looks_percent_encoded(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

fn encode_params_with_charset(params: &str, charset: Option<&str>) -> Result<String> {
    let mut out = String::new();
    let mut first = true;
    for segment in params.split('&') {
        if !first {
            out.push('&');
        }
        first = false;
        let (key, value) = segment.split_once('=').unwrap_or((segment, ""));
        out.push_str(&encode_component_with_charset(key, charset)?);
        if segment.contains('=') {
            out.push('=');
            out.push_str(&encode_component_with_charset(value, charset)?);
        }
    }
    Ok(out)
}

fn encode_component_with_charset(input: &str, charset: Option<&str>) -> Result<String> {
    if charset.is_none() && looks_percent_encoded(input) {
        return Ok(input.to_string());
    }
    let charset = charset.unwrap_or("UTF-8");
    if charset.eq_ignore_ascii_case("escape") {
        return Ok(js_escape(input));
    }
    let encoding =
        encoding_rs::Encoding::for_label(charset.trim().as_bytes()).ok_or_else(|| {
            Diagnostic::new(
                DiagnosticKind::Request,
                format!("unsupported request option `charset`: {charset}"),
            )
        })?;
    let (encoded, _, _) = encoding.encode(input);
    let mut out = String::new();
    for byte in encoded.as_ref() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    Ok(out)
}

fn js_escape(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '*' | '+' | '-' | '.' | '/' | '@' | '_') {
            out.push(ch);
        } else if ch.is_ascii() {
            out.push_str(&format!("%{:02X}", ch as u32));
        } else {
            out.push_str(&format!("%u{:04X}", ch as u32));
        }
    }
    out
}

fn request_has_type_option(request: &LegadoRequest) -> bool {
    request
        .options_json
        .as_deref()
        .and_then(|options| serde_json::from_str::<Value>(options).ok())
        .and_then(|value| value.get("type").cloned())
        .is_some_and(|value| match value {
            Value::String(value) => !value.is_empty(),
            Value::Null => false,
            _ => true,
        })
}

pub fn parse_session_cookie_json(input: &str) -> HashMap<String, String> {
    let Ok(value) = serde_json::from_str::<Value>(input) else {
        return HashMap::new();
    };
    value
        .get("cookies")
        .and_then(Value::as_object)
        .map(|cookies| {
            cookies
                .iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
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
    fn legado_request_options_fail_fast_on_malformed_json() {
        let err = parse_legado_request("https://example.test/path,{\"headers\":")
            .unwrap_err()
            .to_string();

        assert!(err.contains("invalid request options JSON"), "{err}");
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_parse_string_headers() {
        let request = parse_legado_request(
            "https://example.test/path,{\"headers\":\"{'User-Agent':'UA','cookie':'a=b,c=d'}\"}",
        )
        .unwrap();

        assert!(request
            .headers
            .contains(&("User-Agent".to_string(), "UA".to_string())));
        assert!(request
            .headers
            .contains(&("cookie".to_string(), "a=b,c=d".to_string())));
    }

    #[test]
    fn legado_request_options_ignore_json_like_body_fragments_when_splitting() {
        let body = serde_json::json!({
            "model": "rust-model",
            "messages": [
                {"role": "system", "content": "use tools"},
                {"role": "user", "content": "hello"}
            ]
        })
        .to_string();
        let raw_url = format!(
            "https://example.test/chat,{}",
            serde_json::json!({
                "method": "POST",
                "body": body
            })
        );

        let request = parse_legado_request(&raw_url).unwrap();

        assert_eq!(request.url, "https://example.test/chat");
        assert_eq!(request.method, "POST");
        assert_eq!(request.body.as_deref(), Some(body.as_str()));
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_headers_shape() {
        let err = parse_legado_request("https://example.test/path,{\"headers\":[[\"A\",\"B\"]]}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option headers must be an object or string"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_fail_fast_on_non_scalar_header_value() {
        let err = parse_legado_request("https://example.test/path,{\"headers\":{\"A\":[\"B\"]}}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option header `A` must be a scalar value"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_parse_string_redirect_bool() {
        let request =
            parse_legado_request("https://example.test/path,{\"redirect\":\"false\"}").unwrap();

        assert!(!request.follow_redirects);
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_method_type() {
        let err = parse_legado_request("https://example.test/path,{\"method\":1}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `method` must be a string"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_accepts_valid_http_method_tokens() {
        let request =
            parse_legado_request("https://example.test/path,{\"method\":\"PUT\"}").unwrap();

        assert_eq!(request.method, "PUT");
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_method_token() {
        let err = parse_legado_request("https://example.test/path,{\"method\":\"BAD METHOD\"}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `method` must be a valid HTTP method token"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_blank_method_defaults_to_get() {
        let request =
            parse_legado_request("https://example.test/path,{\"method\":\"  \"}").unwrap();

        assert_eq!(request.method, "GET");
    }

    #[test]
    fn legado_request_options_null_body_does_not_force_post() {
        let request = parse_legado_request("https://example.test/path,{\"body\":null}").unwrap();

        assert_eq!(request.method, "GET");
        assert!(request.body.is_none());
    }

    #[test]
    fn legado_request_options_blank_body_does_not_force_post() {
        let request = parse_legado_request("https://example.test/path,{\"body\":\"  \"}").unwrap();

        assert_eq!(request.method, "GET");
        assert!(request.body.is_none());
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_body_base64_type() {
        let err = parse_legado_request("https://example.test/path,{\"bodyBase64\":true}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `bodyBase64` must be a string"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_null_body_base64_does_not_force_post() {
        let request =
            parse_legado_request("https://example.test/path,{\"bodyBase64\":null}").unwrap();

        assert_eq!(request.method, "GET");
        assert!(request.body_base64.is_none());
    }

    #[test]
    fn legado_request_options_blank_body_base64_does_not_force_post() {
        let request =
            parse_legado_request("https://example.test/path,{\"bodyBase64\":\"  \"}").unwrap();

        assert_eq!(request.method, "GET");
        assert!(request.body_base64.is_none());
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_type_option() {
        let err = parse_legado_request("https://example.test/path,{\"type\":123}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `type` must be a string"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_fail_fast_on_webview_delay_boundary() {
        let err = parse_legado_request("https://example.test/path,{\"webViewDelayTime\":250}")
            .unwrap_err();

        assert_eq!(err.kind, DiagnosticKind::UnsupportedPlatformApi);
        let message = err.to_string();
        assert!(
            message.contains("request option `webViewDelayTime`"),
            "{message}"
        );
        assert!(message.contains("WebView platform boundary"), "{message}");
        assert!(message.contains("https://example.test/path"), "{message}");
    }

    #[test]
    fn legado_request_options_allows_non_positive_webview_delay() {
        for raw in [
            "https://example.test/path,{\"webViewDelayTime\":0}",
            "https://example.test/path,{\"webViewDelayTime\":-5}",
            "https://example.test/path,{\"webViewDelayTime\":\"\"}",
        ] {
            let request = parse_legado_request(raw).unwrap();
            assert_eq!(request.url, "https://example.test/path");
        }
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_redirect_bool() {
        let err = parse_legado_request("https://example.test/path,{\"redirect\":\"sometimes\"}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `redirect` must be a boolean"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_fail_fast_on_fractional_redirect_bool() {
        let err = parse_legado_request("https://example.test/path,{\"redirect\":0.5}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `redirect` must be a boolean"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_fail_fast_on_fractional_webview_bool() {
        let request = parse_legado_request("https://example.test/path,{\"webView\":0.5}").unwrap();
        let err = legado_request_wants_webview(&request)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `webView` must be a boolean"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_parse_retry() {
        let request = parse_legado_request("https://example.test/path,{\"retry\":\"2\"}").unwrap();

        assert_eq!(request.retry_attempts, 2);
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_retry() {
        let err = parse_legado_request("https://example.test/path,{\"retry\":\"again\"}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `retry` must be a non-negative integer"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_fail_fast_on_retry_overflow() {
        let err = parse_legado_request("https://example.test/path,{\"retry\":4294967296}")
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `retry` must be a non-negative integer"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_fail_fast_on_js_hooks() {
        for option in [
            r#"{"js":"url + '?signed=1'"}"#,
            r#"{"bodyJs":"result.replace('a','b')" }"#,
            r#"{"webJs":"document.body.innerText"}"#,
        ] {
            let raw = format!("https://example.test/path,{option}");
            let err = parse_legado_request(&raw).unwrap_err().to_string();

            assert!(
                err.contains("unsupported request option"),
                "{option}: {err}"
            );
            assert!(
                err.contains("requires Rust analyzer JS/WebView handling"),
                "{err}"
            );
            assert!(err.contains("https://example.test/path"), "{err}");
        }
    }

    #[test]
    fn legado_request_options_parse_dns_ip() {
        let request = parse_legado_request(r#"https://example.test/path,{"dnsIp":"127.0.0.1"}"#)
            .expect("dnsIp option");
        let snake_case =
            parse_legado_request(r#"https://example.test/path,{"dns_ip":"127.0.0.2"}"#)
                .expect("dns_ip option");

        assert_eq!(request.dns_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(snake_case.dns_ip.as_deref(), Some("127.0.0.2"));
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_dns_ip_type() {
        let err = parse_legado_request(r#"https://example.test/path,{"dnsIp":["127.0.0.1"]}"#)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `dnsIp` must be a string"),
            "{err}"
        );
        assert!(err.contains("https://example.test/path"), "{err}");
    }

    #[test]
    fn legado_request_options_parse_charset() {
        let request = parse_legado_request(r#"https://example.test/path,{"charset":"GBK"}"#)
            .expect("charset option");

        assert_eq!(request.charset.as_deref(), Some("GBK"));
    }

    #[test]
    fn legado_request_options_parse_origin_metadata() {
        let request =
            parse_legado_request(r#"https://example.test/book,{"origin":"https://source.test"}"#)
                .expect("origin option");
        let blank = parse_legado_request(r#"https://example.test/book,{"origin":" "}"#)
            .expect("blank origin option");

        assert_eq!(request.origin.as_deref(), Some("https://source.test"));
        assert_eq!(blank.origin, None);
    }

    #[test]
    fn http_cache_skips_loopback_test_servers() {
        let request = parse_legado_request("http://127.0.0.1:34657/script.js").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("LEGADO_HTTP_CACHE_DIR");
        std::env::set_var("LEGADO_HTTP_CACHE_DIR", dir.path());

        cache_http_response(
            &request,
            &request.url,
            Some(200),
            &[],
            Some("text/javascript"),
            b"var cached = true;",
        );

        assert!(try_read_http_cache(&request).unwrap().is_none());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());

        if let Some(value) = previous {
            std::env::set_var("LEGADO_HTTP_CACHE_DIR", value);
        } else {
            std::env::remove_var("LEGADO_HTTP_CACHE_DIR");
        }
    }

    #[test]
    fn legado_request_options_fail_fast_on_invalid_origin_type() {
        let err = parse_legado_request(r#"https://example.test/book,{"origin":42}"#)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("request option `origin` must be a string"),
            "{err}"
        );
        assert!(err.contains("https://example.test/book"), "{err}");
    }

    #[test]
    fn legado_request_options_allow_blank_js_hooks() {
        let request =
            parse_legado_request(r#"https://example.test/path,{"js":"","bodyJs":null,"webJs":""}"#)
                .unwrap();

        assert_eq!(request.url, "https://example.test/path");
    }

    #[test]
    fn request_option_type_returns_http_body_as_hex() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /bin "));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x00a\n\xff",
                )
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://{addr}/bin,{{\"type\":\"bytes\"}}");
        let response = engine.get_text(&raw, &mut session).expect("hex response");

        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, "00610aff");
    }

    #[test]
    fn request_merges_session_cookie_with_url_option_cookie_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("cookie: a=1; b=2; c=3"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        session.set_cookie(addr.ip().to_string(), "a=1; b=session");
        let raw = format!("http://{addr}/cookie,{{\"headers\":{{\"Cookie\":\"b=2; c=3\"}}}}");
        let response = engine
            .get_text(&raw, &mut session)
            .expect("cookie response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_retry_retries_send_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept first request");
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept retry request");
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read retry request");
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /retry "));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://{addr}/retry,{{\"retry\":1}}");
        let response = engine.get_raw(&raw, &mut session).expect("retry response");

        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, b"OK");
    }

    #[test]
    fn get_retries_one_transient_send_failure_like_okhttp() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept first request");
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept retry request");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /default-retry "), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let response = engine
            .get_raw(&format!("http://{addr}/default-retry"), &mut session)
            .expect("retry response");

        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, b"OK");
    }

    #[test]
    fn post_retries_one_transient_send_failure_by_default() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept first request");
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept retry request");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with("POST /default-post-retry "),
                "{request}"
            );
            assert!(request.contains("body=1"), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw =
            format!("http://{addr}/default-post-retry,{{\"method\":\"POST\",\"body\":\"body=1\"}}");
        let response = engine.get_raw(&raw, &mut session).expect("retry response");

        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, b"OK");
    }

    #[test]
    fn retries_one_transient_body_read_failure_by_default() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept first request");
            let _ = read_http_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nO")
                .expect("write partial response");
            drop(stream);

            let (mut stream, _) = listener.accept().expect("accept retry request");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /body-retry "), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let response = engine
            .get_raw(&format!("http://{addr}/body-retry"), &mut session)
            .expect("retry response");

        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, b"OK");
    }

    #[test]
    fn request_option_charset_encodes_get_query_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(
                request.starts_with("GET /search?wd=%D6%D0%CE%C4 HTTP/1.1"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://{addr}/search?wd=中文,{{\"charset\":\"GBK\"}}");
        let response = engine
            .get_text(&raw, &mut session)
            .expect("charset response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_query_defaults_to_utf8_encoding_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with("GET /search?wd=%E4%B8%AD%E6%96%87&ok=a%20b HTTP/1.1"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://{addr}/search?wd=中文&ok=a b");
        let response = engine.get_text(&raw, &mut session).expect("query response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_charset_encodes_post_form_body_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /submit HTTP/1.1"), "{request}");
            assert!(request.ends_with("wd=%D6%D0%CE%C4"), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!(
            "http://{addr}/submit,{{\"method\":\"POST\",\"body\":\"wd=中文\",\"charset\":\"GBK\"}}"
        );
        let response = engine
            .get_text(&raw, &mut session)
            .expect("charset response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_post_form_body_defaults_to_utf8_form_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /submit HTTP/1.1"), "{request}");
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("content-type: application/x-www-form-urlencoded"),
                "{request}"
            );
            assert!(
                request.ends_with("wd=%E4%B8%AD%E6%96%87&ok=a%20b"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw =
            format!("http://{addr}/submit,{{\"method\":\"POST\",\"body\":\"wd=中文&ok=a b\"}}");
        let response = engine.get_text(&raw, &mut session).expect("form response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_post_form_body_preserves_encoded_components_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(
                request.ends_with("wd=%E4%B8%AD%E6%96%87&plain=a%20b"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!(
            "http://{addr}/submit,{{\"method\":\"POST\",\"body\":\"wd=%E4%B8%AD%E6%96%87&plain=a b\"}}"
        );
        let response = engine.get_text(&raw, &mut session).expect("form response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_charset_escape_encodes_query_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with("GET /search?wd=%u4E2D%u6587&space=a%20b HTTP/1.1"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://{addr}/search?wd=中文&space=a b,{{\"charset\":\"escape\"}}");
        let response = engine
            .get_text(&raw, &mut session)
            .expect("escape charset response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_charset_escape_encodes_post_form_body_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("POST /submit HTTP/1.1"), "{request}");
            assert!(
                request.ends_with("wd=%u4E2D%u6587&space=a%20b"),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!(
            "http://{addr}/submit,{{\"method\":\"POST\",\"body\":\"wd=中文&space=a b\",\"charset\":\"escape\"}}"
        );
        let response = engine
            .get_text(&raw, &mut session)
            .expect("escape charset response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_option_dns_ip_overrides_host_resolution_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let port = addr.port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            assert!(request.starts_with("GET /dns HTTP/1.1"), "{request}");
            assert!(
                request.contains(&format!("host: legado-dns.test:{port}"))
                    || request.contains(&format!("Host: legado-dns.test:{port}")),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://legado-dns.test:{port}/dns,{{\"dnsIp\":\"127.0.0.1\"}}");
        let response = engine.get_text(&raw, &mut session).expect("dnsIp response");

        assert_eq!(response.status, Some(200));
        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_call_timeout_overrides_default_timeout_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let _ = read_http_request(&mut stream);
            thread::sleep(Duration::from_millis(250));
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nSLOW",
            );
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let err = engine
            .request_text_with_timeout(
                &format!("http://{addr}/slow"),
                "GET",
                Vec::new(),
                None,
                Some(20),
                &mut session,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("error sending request"), "{err}");
        assert!(err.contains("/slow"), "{err}");
    }

    #[test]
    fn request_proxy_header_uses_proxy_client_and_removes_proxy_header_like_analyze_url() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy request");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with("GET http://origin.test/proxied HTTP/1.1"),
                "{request}"
            );
            assert!(
                request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz")
                    || request.contains("proxy-authorization: Basic dXNlcjpwYXNz"),
                "{request}"
            );
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("proxy:")),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write proxy response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!(
            "http://origin.test/proxied,{{\"headers\":{{\"proxy\":\"http://{addr}@user@pass\"}}}}"
        );
        let response = engine.get_text(&raw, &mut session).expect("proxy response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_proxy_header_fails_fast_on_invalid_proxy_shape() {
        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let err = engine
            .get_text(
                r#"http://origin.test/proxied,{"headers":{"proxy":"ftp://127.0.0.1:8080"}}"#,
                &mut session,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("invalid proxy header"), "{err}");
        assert!(err.contains("origin.test"), "{err}");
    }

    #[test]
    fn multipart_upload_proxy_header_uses_proxy_client_like_analyze_url_upload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept proxy upload");
            let request = read_http_request(&mut stream);
            assert!(
                request.starts_with("POST http://origin.test/upload HTTP/1.1"),
                "{request}"
            );
            assert!(request.contains("multipart/form-data"), "{request}");
            assert!(request.contains("name=\"file\""), "{request}");
            assert!(request.contains("upload body"), "{request}");
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("proxy:")),
                "{request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .expect("write proxy upload response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let response = engine
            .upload_multipart_text(
                "http://origin.test/upload",
                vec![("proxy".to_string(), format!("http://{addr}"))],
                vec![("kind".to_string(), "rule".to_string())],
                MultipartFilePart {
                    field_name: "file".to_string(),
                    file_name: "rule.txt".to_string(),
                    content_type: "text/plain".to_string(),
                    body: b"upload body".to_vec(),
                },
                &mut session,
            )
            .expect("proxy upload response");

        assert_eq!(response.body, "OK");
    }

    #[test]
    fn request_fails_fast_on_webview_option_without_platform_boundary() {
        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let err = engine
            .get_raw("data:text/plain,ok,{\"webView\":true}", &mut session)
            .unwrap_err()
            .to_string();

        assert!(err.contains("request option `webView`"), "{err}");
        assert!(err.contains("WebView platform boundary"), "{err}");
    }

    #[test]
    fn request_option_redirect_false_keeps_head_location_response() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("HEAD /download.php "));
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /files/final-name.txt\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let raw = format!("http://{addr}/download.php,{{\"method\":\"HEAD\",\"redirect\":false}}");
        let response = engine.get_raw(&raw, &mut session).expect("head response");

        assert_eq!(response.status, Some(302));
        assert_eq!(response.url, format!("http://{addr}/download.php"));
        assert!(response
            .headers
            .iter()
            .any(|(key, value)| key.eq_ignore_ascii_case("location")
                && value == "/files/final-name.txt"));
    }

    #[test]
    fn request_option_body_base64_sends_binary_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|index| index + 4)
                {
                    let request_head = String::from_utf8_lossy(&bytes[..header_end]);
                    let has_content_length = request_head
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case("content-length: 4"));
                    if has_content_length && bytes.len() >= header_end + 4 {
                        break;
                    }
                }
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") && bytes.len() > 4096 {
                    break;
                }
            }
            let header_end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("headers end")
                + 4;
            let request_head = String::from_utf8_lossy(&bytes[..header_end]);
            assert!(request_head.starts_with("PUT /remote.bin "));
            assert!(request_head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("content-length: 4")));
            assert_eq!(&bytes[header_end..header_end + 4], &[0, b'a', b'\n', 0xff]);
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                )
                .expect("write response");
        });

        let engine = RequestEngine::new().expect("request engine");
        let mut session = AnalyzerSession::default();
        let body = base64::engine::general_purpose::STANDARD.encode([0, b'a', b'\n', 0xff]);
        let raw =
            format!("http://{addr}/remote.bin,{{\"method\":\"PUT\",\"bodyBase64\":\"{body}\"}}");
        let response = engine.get_raw(&raw, &mut session).expect("put response");

        assert_eq!(response.status, Some(201));
        assert_eq!(response.body, b"OK");
    }
}
