use legado_runtime::request::{
    decode_data_url, http_cache_key, is_business_error_response, parse_header_map,
    parse_legado_request, parse_session_cookie_json,
};

#[test]
fn replays_base64_data_url_without_network() {
    let out = decode_data_url("data:;base64,eyJvayI6dHJ1ZX0=,{\"type\":\"fixture\"}")
        .unwrap()
        .unwrap();
    assert_eq!(out, "{\"ok\":true}");
}

#[test]
fn data_url_with_type_option_returns_hex_like_analyze_url() {
    let request =
        parse_legado_request("data:;base64,eyJvayI6dHJ1ZX0=,{\"type\":\"fixture\"}").unwrap();
    let mut session = legado_runtime::AnalyzerSession::default();
    let out = legado_runtime::request::RequestEngine::new()
        .unwrap()
        .get_text(
            &format!("{},{}", request.url, request.options_json.unwrap()),
            &mut session,
        )
        .unwrap();
    assert_eq!(out.body, "7b226f6b223a747275657d");
}

#[test]
fn raw_data_url_preserves_binary_bytes() {
    let mut session = legado_runtime::AnalyzerSession::default();
    let out = legado_runtime::request::RequestEngine::new()
        .unwrap()
        .get_raw("data:application/octet-stream;base64,AP8Q", &mut session)
        .unwrap();
    assert_eq!(
        out.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(out.body, vec![0, 255, 16]);
}

#[test]
fn http_cache_replays_raw_bytes_and_metadata() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("LEGADO_HTTP_CACHE_DIR", dir.path());
    let request = parse_legado_request("https://example.com/binary").unwrap();
    let key = http_cache_key(&request);
    std::fs::write(dir.path().join(format!("{key}.body")), [0u8, 159, 146, 150]).unwrap();
    std::fs::write(
        dir.path().join(format!("{key}.json")),
        serde_json::json!({
            "cache_version": 1,
            "request_url": request.url,
            "final_url": "https://example.com/binary",
            "method": "GET",
            "status": 200,
            "body_file": format!("{key}.body"),
            "headers": [["content-type", "application/octet-stream"]],
            "content_type": "application/octet-stream"
        })
        .to_string(),
    )
    .unwrap();

    let mut session = legado_runtime::AnalyzerSession::default();
    let out = legado_runtime::request::RequestEngine::new()
        .unwrap()
        .get_raw("https://example.com/binary", &mut session)
        .unwrap();
    assert_eq!(out.body, vec![0, 159, 146, 150]);
    assert_eq!(
        out.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert!(out.headers.contains(&(
        "content-type".to_string(),
        "application/octet-stream".to_string()
    )));
    std::env::remove_var("LEGADO_HTTP_CACHE_DIR");
}

#[test]
fn imports_legado_cli_session_cookies() {
    let cookies = parse_session_cookie_json(r#"{"cookies":{"v1.gyks.cf":"qttoken=abc"}}"#);
    assert_eq!(cookies.get("v1.gyks.cf").unwrap(), "qttoken=abc");
}

#[test]
fn parses_legado_url_options_like_analyze_url() {
    let parsed = parse_legado_request(
        r#"https://example.com/a?x=1,{"method":"POST","headers":{"A":"b","N":1},"body":{"ok":true}}"#,
    )
    .unwrap();
    assert_eq!(parsed.url, "https://example.com/a?x=1");
    assert_eq!(parsed.method, "POST");
    assert!(parsed.headers.contains(&("A".to_string(), "b".to_string())));
    assert!(parsed.headers.contains(&("N".to_string(), "1".to_string())));
    assert_eq!(parsed.body.unwrap(), r#"{"ok":true}"#);
}

#[test]
fn http_cache_key_uses_request_semantics() {
    let a = parse_legado_request(r#"https://example.com/a,{"method":"POST","body":"x"}"#).unwrap();
    let b = parse_legado_request(r#"https://example.com/a,{"method":"POST","body":"y"}"#).unwrap();
    assert_ne!(http_cache_key(&a), http_cache_key(&b));
}

#[test]
fn parses_lenient_source_header_like_base_source() {
    let headers =
        parse_header_map("{\n 'User-Agent': 'Mozilla/5.0',\n 'cookie': 'jieqiUserInfo=abc,def'\n}");
    assert!(headers.contains(&("User-Agent".to_string(), "Mozilla/5.0".to_string())));
    assert!(headers.contains(&("cookie".to_string(), "jieqiUserInfo=abc,def".to_string())));
}

#[test]
fn detects_business_error_response_bodies() {
    assert!(is_business_error_response(
        r#"{"errors":{"code":"44010120","title":"验签失败"}}"#
    ));
    assert!(!is_business_error_response(r#"{"data":{"content":"ok"}}"#));
}
