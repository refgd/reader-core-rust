use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use aes::Aes128;
use base64::Engine;
use cbc::cipher::{
    block_padding::Pkcs7, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
    KeyIvInit,
};
use chrono::{Datelike, FixedOffset, Local, TimeZone, Timelike};
use des::{Des, TdesEde3};
use hmac::{Hmac, Mac};
use regex::Regex;
use rquickjs::function::{Func, Rest};
use rquickjs::{CatchResultExt, CaughtError, Coerced, Context, FromJs, Runtime};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{Pkcs1v15Encrypt, SigningKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest as ShaDigest, Sha256, Sha384, Sha512};
use uuid::Uuid;

use crate::diagnostics::{Diagnostic, DiagnosticKind, Result};
use crate::platform::PlatformHostRef;
use crate::request::{parse_header_map, parse_legado_request, RequestEngine, DEFAULT_USER_AGENT};
use crate::rule_engine::extract_html_rule_from_str;
use crate::session::{
    persistent_delete_cache, persistent_delete_login_header, persistent_delete_login_info,
    persistent_get_cache, persistent_get_login_header, persistent_get_source_store,
    persistent_set_cache, persistent_set_login_header, persistent_set_source_store,
    AnalyzerSession,
};
use crate::source::BookSource;

pub(crate) const FORCED_STRING_RESULT_PREFIX: &str = "__LEGADO_FORCE_STRING_RESULT__";

pub struct JsRuntime {
    _runtime: Runtime,
    context: Context,
    session: Arc<Mutex<AnalyzerSession>>,
    request: RequestEngine,
    source_name: String,
    source_key: String,
    platform_host: Option<PlatformHostRef>,
    normalized_scripts: HashMap<String, String>,
}

impl JsRuntime {
    pub fn new(source: &BookSource, session: AnalyzerSession) -> Result<Self> {
        Self::new_with_platform(source, session, None)
    }

    pub fn new_with_platform(
        source: &BookSource,
        session: AnalyzerSession,
        platform_host: Option<PlatformHostRef>,
    ) -> Result<Self> {
        let runtime = Runtime::new()
            .map_err(|err| Diagnostic::new(DiagnosticKind::JavaScript, err.to_string()))?;
        let context = Context::full(&runtime)
            .map_err(|err| Diagnostic::new(DiagnosticKind::JavaScript, err.to_string()))?;
        let session = Arc::new(Mutex::new(session));
        let request = RequestEngine::new_with_default_headers_and_rate_limit(
            parse_header_map(&source.header),
            &source.book_source_url,
            &source.concurrent_rate,
        )?;
        let mut this = Self {
            _runtime: runtime,
            context,
            session,
            request,
            source_name: source.book_source_name.clone(),
            source_key: source.book_source_url.clone(),
            platform_host,
            normalized_scripts: HashMap::new(),
        };
        this.install_host(source)?;
        this.eval_string(RHINO_COMPAT_PRELUDE, "runtime.rhinoCompat")?;
        this.eval_string(RHINO_COMPAT_POSTLUDE, "runtime.rhinoCompat.postlude")?;
        this.load_js_lib(source)?;
        Ok(this)
    }

    fn load_js_lib(&mut self, source: &BookSource) -> Result<()> {
        let js_lib = source.js_lib.trim();
        if js_lib.is_empty() {
            return Ok(());
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(js_lib) {
            if let Some(object) = value.as_object() {
                for (name, value) in object {
                    let Some(url) = value.as_str() else {
                        return Err(Diagnostic::new(
                            DiagnosticKind::SourceParse,
                            format!("source jsLib entry `{name}` must be a URL string"),
                        )
                        .with_source(self.source_name.clone())
                        .with_rule_path("source.jsLib")
                        .with_script(js_lib));
                    };
                    let script = self.fetch_text_for_js(url, "source.jsLib")?;
                    self.eval_string(
                        &preprocess_imported_eval_script(&script),
                        &format!("source.jsLib.{name}"),
                    )?;
                }
                return Ok(());
            }
        }
        self.eval_string(&preprocess_imported_eval_script(js_lib), "source.jsLib")?;
        Ok(())
    }

    fn fetch_text_for_js(&self, url: &str, rule_path: &str) -> Result<String> {
        let mut session = self.session.lock().expect("session poisoned");
        self.request
            .get_text(url, &mut session)
            .map(|out| out.body)
            .map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_rule_path(rule_path)
                    .with_request(url.to_string(), None)
            })
    }

    pub fn eval_rule_script_with_response(
        &mut self,
        script: &str,
        rule_path: &str,
        response: &crate::request::RequestOutput,
        base_url: &str,
        key: &str,
        page: i32,
    ) -> Result<String> {
        let wrapped = self.normalized_script(script);
        let body = response.body.clone();
        self.session
            .lock()
            .expect("session poisoned")
            .java_store
            .insert("__result_json".to_string(), body.clone());
        self.context.with(|ctx| {
            let globals = ctx.globals();
            globals.set("baseUrl", base_url).map_err(to_js_diag)?;
            globals.set("key", key).map_err(to_js_diag)?;
            globals.set("page", page).map_err(to_js_diag)?;
            let headers = response
                .headers
                .iter()
                .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
                .collect::<serde_json::Map<_, _>>();
            let response_json = serde_json::json!({
                "url": response.url,
                "body": response.body,
                "code": response.status.unwrap_or(200),
                "message": "OK",
                "headers": headers,
                "contentType": response.content_type,
                "raw": ""
            });
            let script_set_result = format!(
                "globalThis.result = java.__strResponse({}); if (globalThis.java) java.ruleUrl = {};",
                response_json,
                serde_json::to_string(&response.url).unwrap_or_else(|_| "\"\"".to_string())
            );
            ctx.eval::<(), _>(script_set_result).catch(&ctx).map_err(js_caught_to_diag)?;
            let value: rquickjs::Value = ctx.eval(wrapped.as_str()).catch(&ctx).map_err(|err| {
                js_caught_to_diag(err)
                    .with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            let output = value_to_string(ctx.clone(), value).map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            sync_global_state(ctx.clone(), &self.session).map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            Ok(output)
        })
    }

    pub fn session(&self) -> AnalyzerSession {
        self.session.lock().expect("session poisoned").clone()
    }

    pub fn put_java_store(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        let _ = persistent_set_source_store(&self.source_key, &key, &value);
        self.session
            .lock()
            .expect("session poisoned")
            .java_store
            .insert(key.clone(), value.clone());
        self.session
            .lock()
            .expect("session poisoned")
            .source_store
            .insert(key, value);
    }

    pub fn eval_string(&mut self, script: &str, rule_path: &str) -> Result<String> {
        self.context.with(|ctx| {
            ctx.globals()
                .set(
                    "result",
                    rquickjs::String::from_str(ctx.clone(), "").map_err(to_js_diag)?,
                )
                .map_err(to_js_diag)?;
            let value: rquickjs::Value = ctx.eval(script).catch(&ctx).map_err(|err| {
                js_caught_to_diag(err)
                    .with_source(self.source_name.clone())
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            value_to_string(ctx, value).map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_rule_path(rule_path)
                    .with_script(script)
            })
        })
    }

    pub fn eval_rule_script(
        &mut self,
        script: &str,
        rule_path: &str,
        result: &str,
        base_url: &str,
        key: &str,
        page: i32,
    ) -> Result<String> {
        self.eval_rule_script_with_bindings(script, rule_path, result, base_url, key, page, "")
    }

    pub fn eval_rule_script_with_bindings(
        &mut self,
        script: &str,
        rule_path: &str,
        result: &str,
        base_url: &str,
        key: &str,
        page: i32,
        bindings_json: &str,
    ) -> Result<String> {
        let wrapped = self.normalized_script(script);
        self.session
            .lock()
            .expect("session poisoned")
            .java_store
            .insert("__result_json".to_string(), result.to_string());
        self.context.with(|ctx| {
            let globals = ctx.globals();
            set_result_global(ctx.clone(), &globals, result)?;
            globals.set("baseUrl", base_url).map_err(to_js_diag)?;
            globals.set("key", key).map_err(to_js_diag)?;
            globals.set("page", page).map_err(to_js_diag)?;
            apply_eval_bindings(ctx.clone(), bindings_json).map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(bindings_json)
            })?;
            let value: rquickjs::Value = ctx.eval(wrapped.as_str()).catch(&ctx).map_err(|err| {
                js_caught_to_diag(err)
                    .with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            let output = value_to_string(ctx.clone(), value).map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            sync_global_state(ctx.clone(), &self.session).map_err(|err| {
                err.with_source(self.source_name.clone())
                    .with_base_url(base_url)
                    .with_rule_path(rule_path)
                    .with_script(script)
            })?;
            Ok(output)
        })
    }

    fn install_host(&mut self, source: &BookSource) -> Result<()> {
        let session = self.session.clone();
        let request_session = self.session.clone();
        let ajax_all_session = self.session.clone();
        let request_global_session = self.session.clone();
        let request = self.request.clone();
        let source_name = source.book_source_name.clone();
        let source_key = source.book_source_url.clone();
        self.context.with(|ctx| {
            let globals = ctx.globals();

            let java = rquickjs::Object::new(ctx.clone()).map_err(to_js_diag)?;
            java.set(
                "base64Encode",
                Func::from(|args: Rest<Coerced<String>>| {
                    let input = args
                        .0
                        .first()
                        .map(|value| value.0.as_str())
                        .unwrap_or_default();
                    let flags = args
                        .0
                        .get(1)
                        .and_then(|value| value.0.parse::<i32>().ok())
                        .unwrap_or(ANDROID_BASE64_NO_WRAP);
                    android_base64_encode(input.as_bytes(), flags)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "base64Decode",
                Func::from(|args: Rest<Coerced<String>>| {
                    let input = args
                        .0
                        .first()
                        .map(|value| value.0.as_str())
                        .unwrap_or_default();
                    let charset = args
                        .0
                        .get(1)
                        .map(|value| value.0.as_str())
                        .filter(|value| !value.chars().all(|ch| ch.is_ascii_digit()));
                    let flags = args
                        .0
                        .get(1)
                        .filter(|value| value.0.chars().all(|ch| ch.is_ascii_digit()))
                        .and_then(|value| value.0.parse::<i32>().ok())
                        .unwrap_or(ANDROID_BASE64_DEFAULT);
                    decode_base64_string(input, charset, flags)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "hexDecodeToString",
                Func::from(|input: Coerced<String>| decode_hex_to_string(&input.0, "UTF-8")),
            )
            .map_err(to_js_diag)?;
            java.set(
                "hexEncodeToString",
                Func::from(|input: Coerced<String>| hex::encode(input.0.as_bytes())),
            )
            .map_err(to_js_diag)?;
            java.set(
                "encodeURI",
                Func::from(|args: Rest<Coerced<String>>| {
                    let input = args
                        .0
                        .first()
                        .map(|value| value.0.as_str())
                        .unwrap_or_default();
                    let charset = args
                        .0
                        .get(1)
                        .map(|value| value.0.as_str())
                        .unwrap_or("UTF-8");
                    java_url_encode(input, charset)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "htmlFormat",
                Func::from(|input: Coerced<String>| {
                    crate::html_formatter::format_content(&input.0)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "t2s",
                Func::from(|input: Coerced<String>| hanconv::t2s(input.0)),
            )
            .map_err(to_js_diag)?;
            java.set(
                "s2t",
                Func::from(|input: Coerced<String>| hanconv::s2t(input.0)),
            )
            .map_err(to_js_diag)?;
            java.set(
                "toNumChapter",
                Func::from(|input: Coerced<String>| to_num_chapter(&input.0)),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__toUrlJson",
                Func::from(|url: Coerced<String>, base_url: Coerced<String>| {
                    js_url_json(&url.0, &base_url.0)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__base64DecodeToHex",
                Func::from(|args: Rest<Coerced<String>>| {
                    let input = args
                        .0
                        .first()
                        .map(|value| value.0.as_str())
                        .unwrap_or_default();
                    let flags = args
                        .0
                        .get(1)
                        .and_then(|value| value.0.parse::<i32>().ok())
                        .unwrap_or(ANDROID_BASE64_DEFAULT);
                    match android_base64_decode(input, flags) {
                        Ok(bytes) => hex::encode(bytes),
                        Err(err) => format!("__LEGADO_BASE64_ERROR__:{input}:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__base64EncodeHex",
                Func::from(|hex_input: Coerced<String>, flags: i32| {
                    let bytes = match hex::decode(hex_input.0.trim()) {
                        Ok(bytes) => bytes,
                        Err(err) => return format!("__LEGADO_BASE64_ERROR__:{err}"),
                    };
                    android_base64_encode(&bytes, flags)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__utf8ToHex",
                Func::from(|input: Coerced<String>| hex::encode(input.0.as_bytes())),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__strToHex",
                Func::from(|input: Coerced<String>, charset: Coerced<String>| {
                    encode_string_to_hex(&input.0, &charset.0)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__hexToString",
                Func::from(|hex: Coerced<String>, charset: Coerced<String>| {
                    decode_hex_to_string(&hex.0, &charset.0)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__hexToAutoString",
                Func::from(|hex: Coerced<String>| {
                    let bytes = match hex::decode(hex.0.trim()) {
                        Ok(bytes) => bytes,
                        Err(err) => return format!("__LEGADO_HEX_ERROR__:{}:{err}", hex.0),
                    };
                    decode_bytes_auto_string(&bytes)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__preprocessImportedScript",
                Func::from(|input: Coerced<String>| preprocess_imported_eval_script(&input.0)),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__aesCbcPkcs5DecryptHex",
                Func::from(
                    |data_hex: Coerced<String>,
                     key_hex: Coerced<String>,
                     iv_hex: Coerced<String>| {
                        crypto_result_marker(aes_cbc_pkcs5_decrypt_hex(
                            &data_hex.0,
                            &key_hex.0,
                            &iv_hex.0,
                        ))
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "aesBase64DecodeToString",
                Func::from(
                    |data: Coerced<String>,
                     key: Coerced<String>,
                     algorithm: Coerced<String>,
                     iv: Coerced<String>| {
                        crypto_result_marker(aes_base64_decode_to_string(
                            &data.0,
                            &key.0,
                            &algorithm.0,
                            &iv.0,
                        ))
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "aesEncodeToBase64String",
                Func::from(
                    |data: Coerced<String>,
                     key: Coerced<String>,
                     algorithm: Coerced<String>,
                     iv: Coerced<String>| {
                        crypto_result_marker(aes_encode_to_base64_string(
                            &data.0,
                            &key.0,
                            &algorithm.0,
                            &iv.0,
                        ))
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__symmetricEncryptBase64",
                Func::from(
                    |algorithm: Coerced<String>,
                     key: Coerced<String>,
                     key_is_hex: bool,
                     iv: Coerced<String>,
                     iv_is_hex: bool,
                     data: Coerced<String>,
                     data_is_hex: bool| {
                        crypto_result_marker(
                            symmetric_encrypt_bytes(
                                &algorithm.0,
                                &key.0,
                                key_is_hex,
                                &iv.0,
                                iv_is_hex,
                                &data.0,
                                data_is_hex,
                            )
                            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__symmetricEncryptHex",
                Func::from(
                    |algorithm: Coerced<String>,
                     key: Coerced<String>,
                     key_is_hex: bool,
                     iv: Coerced<String>,
                     iv_is_hex: bool,
                     data: Coerced<String>,
                     data_is_hex: bool| {
                        crypto_result_marker(
                            symmetric_encrypt_bytes(
                                &algorithm.0,
                                &key.0,
                                key_is_hex,
                                &iv.0,
                                iv_is_hex,
                                &data.0,
                                data_is_hex,
                            )
                            .map(hex::encode),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__symmetricEncryptLossyString",
                Func::from(
                    |algorithm: Coerced<String>,
                     key: Coerced<String>,
                     key_is_hex: bool,
                     iv: Coerced<String>,
                     iv_is_hex: bool,
                     data: Coerced<String>,
                     data_is_hex: bool| {
                        crypto_result_marker(
                            symmetric_encrypt_bytes(
                                &algorithm.0,
                                &key.0,
                                key_is_hex,
                                &iv.0,
                                iv_is_hex,
                                &data.0,
                                data_is_hex,
                            )
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__symmetricDecryptStr",
                Func::from(
                    |algorithm: Coerced<String>,
                     key: Coerced<String>,
                     key_is_hex: bool,
                     iv: Coerced<String>,
                     iv_is_hex: bool,
                     data: Coerced<String>,
                     data_is_hex: bool| {
                        crypto_result_marker(
                            symmetric_decrypt_bytes(
                                &algorithm.0,
                                &key.0,
                                key_is_hex,
                                &iv.0,
                                iv_is_hex,
                                &data.0,
                                data_is_hex,
                            )
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__symmetricDecryptHex",
                Func::from(
                    |algorithm: Coerced<String>,
                     key: Coerced<String>,
                     key_is_hex: bool,
                     iv: Coerced<String>,
                     iv_is_hex: bool,
                     data: Coerced<String>,
                     data_is_hex: bool| {
                        crypto_result_marker(
                            symmetric_decrypt_bytes(
                                &algorithm.0,
                                &key.0,
                                key_is_hex,
                                &iv.0,
                                iv_is_hex,
                                &data.0,
                                data_is_hex,
                            )
                            .map(hex::encode),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "digestHex",
                Func::from(|data: Coerced<String>, algorithm: Coerced<String>| {
                    crypto_result_marker(
                        digest_bytes(&data.0, &algorithm.0)
                            .map(hex::encode)
                            .ok_or_else(|| {
                                format!("unsupported digest algorithm `{}`", algorithm.0)
                            }),
                    )
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "digestBase64Str",
                Func::from(|data: Coerced<String>, algorithm: Coerced<String>| {
                    crypto_result_marker(
                        digest_bytes(&data.0, &algorithm.0)
                            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
                            .ok_or_else(|| {
                                format!("unsupported digest algorithm `{}`", algorithm.0)
                            }),
                    )
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "HMacHex",
                Func::from(
                    |data: Coerced<String>, algorithm: Coerced<String>, key: Coerced<String>| {
                        crypto_result_marker(
                            hmac_bytes(&data.0, &algorithm.0, &key.0)
                                .map(hex::encode)
                                .ok_or_else(|| {
                                    format!("unsupported HMAC algorithm `{}`", algorithm.0)
                                }),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "HMacBase64",
                Func::from(
                    |data: Coerced<String>, algorithm: Coerced<String>, key: Coerced<String>| {
                        crypto_result_marker(
                            hmac_bytes(&data.0, &algorithm.0, &key.0)
                                .map(|bytes| {
                                    base64::engine::general_purpose::STANDARD.encode(bytes)
                                })
                                .ok_or_else(|| {
                                    format!("unsupported HMAC algorithm `{}`", algorithm.0)
                                }),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__asymmetricEncryptBase64",
                Func::from(
                    |algorithm: Coerced<String>,
                     public_key: Coerced<String>,
                     private_key: Coerced<String>,
                     data: Coerced<String>,
                     use_public_key: bool| {
                        crypto_result_marker(asymmetric_encrypt_base64(
                            &algorithm.0,
                            &public_key.0,
                            &private_key.0,
                            &data.0,
                            use_public_key,
                        ))
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__asymmetricEncryptHex",
                Func::from(
                    |algorithm: Coerced<String>,
                     public_key: Coerced<String>,
                     private_key: Coerced<String>,
                     data: Coerced<String>,
                     use_public_key: bool| {
                        crypto_result_marker(
                            asymmetric_encrypt_bytes(
                                &algorithm.0,
                                &public_key.0,
                                &private_key.0,
                                &data.0,
                                use_public_key,
                            )
                            .map(hex::encode),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__asymmetricDecryptStr",
                Func::from(
                    |algorithm: Coerced<String>,
                     public_key: Coerced<String>,
                     private_key: Coerced<String>,
                     data: Coerced<String>,
                     use_public_key: bool| {
                        crypto_result_marker(
                            asymmetric_decrypt_bytes(
                                &algorithm.0,
                                &public_key.0,
                                &private_key.0,
                                &data.0,
                                use_public_key,
                            )
                            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__signHex",
                Func::from(
                    |algorithm: Coerced<String>,
                     private_key: Coerced<String>,
                     data: Coerced<String>| {
                        crypto_result_marker(
                            sign_bytes(&algorithm.0, &private_key.0, &data.0).map(hex::encode),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__signBase64",
                Func::from(
                    |algorithm: Coerced<String>,
                     private_key: Coerced<String>,
                     data: Coerced<String>| {
                        crypto_result_marker(
                            sign_bytes(&algorithm.0, &private_key.0, &data.0).map(|bytes| {
                                base64::engine::general_purpose::STANDARD.encode(bytes)
                            }),
                        )
                    },
                ),
            )
            .map_err(to_js_diag)?;
            java.set(
                "md5Encode",
                Func::from(|input: Coerced<String>| format!("{:x}", md5::compute(input.0))),
            )
            .map_err(to_js_diag)?;
            java.set(
                "md5Encode16",
                Func::from(|input: Coerced<String>| {
                    let full = format!("{:x}", md5::compute(input.0));
                    full.chars().skip(8).take(16).collect::<String>()
                }),
            )
            .map_err(to_js_diag)?;
            java.set("randomUUID", Func::from(|| Uuid::new_v4().to_string()))
                .map_err(to_js_diag)?;
            java.set(
                "__timeFormatMillis",
                Func::from(|time: f64| {
                    let millis = time as i64;
                    Local
                        .timestamp_millis_opt(millis)
                        .single()
                        .map(|time| time.format("%Y/%m/%d %H:%M").to_string())
                        .unwrap_or_default()
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__timeFormatUtcMillis",
                Func::from(|time: f64, format: Coerced<String>, offset_millis: i32| {
                    java_time_format_utc(time as i64, &format.0, offset_millis)
                }),
            )
            .map_err(to_js_diag)?;
            let s_get_string = session.clone();
            java.set(
                "getString",
                Func::from(move |path: Coerced<String>| {
                    let result = s_get_string
                        .lock()
                        .expect("session poisoned")
                        .java_store
                        .get("__result_json")
                        .cloned()
                        .unwrap_or_default();
                    get_string_from_rule(&result, &path.0)
                }),
            )
            .map_err(to_js_diag)?;
            let s_set_content = session.clone();
            java.set(
                "__setContentRaw",
                Func::from(move |content: Coerced<String>| {
                    let content = content.0;
                    s_set_content
                        .lock()
                        .expect("session poisoned")
                        .java_store
                        .insert("__result_json".to_string(), content);
                    true
                }),
            )
            .map_err(to_js_diag)?;
            let s_get_content = session.clone();
            java.set(
                "__getContentRaw",
                Func::from(move || {
                    s_get_content
                        .lock()
                        .expect("session poisoned")
                        .java_store
                        .get("__result_json")
                        .cloned()
                        .unwrap_or_default()
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__selectElementsJson",
                Func::from(|content: Coerced<String>, rule: Coerced<String>| {
                    match crate::rule_engine::select_html_nodes_from_str(&content.0, &rule.0) {
                        Ok(nodes) => {
                            serde_json::to_string(&nodes).unwrap_or_else(|_| "[]".to_string())
                        }
                        Err(err) => format!("__LEGADO_RULE_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__extractHtmlRule",
                Func::from(|content: Coerced<String>, rule: Coerced<String>| {
                    match crate::rule_engine::extract_html_rule_from_str(&content.0, &rule.0) {
                        Ok(value) => value,
                        Err(err) => format!("__LEGADO_RULE_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;

            let s_get = session.clone();
            let java_get_source_key = source_key.clone();
            java.set(
                "get",
                Func::from(move |key: Coerced<String>| {
                    let session = s_get.lock().expect("session poisoned");
                    session
                        .source_store
                        .get(&key.0)
                        .cloned()
                        .or_else(|| {
                            persistent_get_source_store(&java_get_source_key, &key.0)
                                .ok()
                                .flatten()
                        })
                        .or_else(|| session.java_store.get(&key.0).cloned())
                        .unwrap_or_default()
                }),
            )
            .map_err(to_js_diag)?;
            let s_put = session.clone();
            let java_put_source_key = source_key.clone();
            java.set(
                "put",
                Func::from(move |key: Coerced<String>, value: Coerced<String>| {
                    let key = key.0;
                    let value = value.0;
                    let _ = persistent_set_source_store(&java_put_source_key, &key, &value);
                    let mut session = s_put.lock().expect("session poisoned");
                    session.source_store.insert(key.clone(), value.clone());
                    session.java_store.insert(key, value.clone());
                    value
                }),
            )
            .map_err(to_js_diag)?;
            let s_cookie = session.clone();
            java.set(
                "getCookie",
                Func::from(move |args: Rest<Coerced<String>>| {
                    let host = args
                        .0
                        .first()
                        .map(|value| value.0.clone())
                        .unwrap_or_default();
                    let key = args.0.get(1).map(|value| value.0.clone());
                    let cookie = s_cookie.lock().expect("session poisoned").get_cookie(&host);
                    if let Some(key) = key {
                        cookie
                            .split(';')
                            .find_map(|part| {
                                let (name, value) = part.trim().split_once('=')?;
                                (name == key).then(|| value.to_string())
                            })
                            .unwrap_or_default()
                    } else {
                        cookie
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let s_log = session.clone();
            java.set(
                "log",
                Func::from(move |message: Rest<Coerced<String>>| {
                    let message = message
                        .0
                        .first()
                        .map(|value| value.0.clone())
                        .unwrap_or_default();
                    s_log
                        .lock()
                        .expect("session poisoned")
                        .logs
                        .push(message.clone());
                    message
                }),
            )
            .map_err(to_js_diag)?;
            let s_log_type = session.clone();
            java.set(
                "logType",
                Func::from(move |message: Rest<Coerced<String>>| {
                    let ty = if message.0.is_empty() {
                        "undefined"
                    } else {
                        "string"
                    };
                    s_log_type
                        .lock()
                        .expect("session poisoned")
                        .logs
                        .push(ty.to_string());
                }),
            )
            .map_err(to_js_diag)?;
            let s_toast = session.clone();
            java.set(
                "toast",
                Func::from(move |message: Coerced<String>| {
                    let message = message.0;
                    s_toast
                        .lock()
                        .expect("session poisoned")
                        .toasts
                        .push(message);
                }),
            )
            .map_err(to_js_diag)?;
            let s_long_toast = session.clone();
            java.set(
                "longToast",
                Func::from(move |message: Coerced<String>| {
                    let message = message.0;
                    s_long_toast
                        .lock()
                        .expect("session poisoned")
                        .toasts
                        .push(message);
                }),
            )
            .map_err(to_js_diag)?;
            let pre_update_action_session = session.clone();
            java.set(
                "__preUpdateAction",
                Func::from(move |api: Coerced<String>| {
                    let mut session = pre_update_action_session.lock().expect("session poisoned");
                    let actions = session
                        .java_store
                        .entry("__pre_update_actions".to_string())
                        .or_default();
                    if !actions.is_empty() {
                        actions.push('\n');
                    }
                    actions.push_str(&api.0);
                    format!("__LEGADO_PRE_UPDATE_ACTION__:{}", api.0)
                }),
            )
            .map_err(to_js_diag)?;

            let import_request = request.clone();
            let import_session = session.clone();
            java.set(
                "__fetchText",
                Func::from(move |url: Coerced<String>| {
                    let url = url.0;
                    let mut session = import_session.lock().expect("session poisoned");
                    import_request
                        .get_text(&url, &mut session)
                        .map(|out| out.body)
                        .unwrap_or_else(|err| format!("__LEGADO_REQUEST_ERROR__:{err}"))
                }),
            )
            .map_err(to_js_diag)?;
            let cache_request = request.clone();
            let cache_session = session.clone();
            java.set(
                "__cacheTextFile",
                Func::from(move |url: Coerced<String>, _save_time: i32| {
                    let url = url.0;
                    let key = format!("cacheFile:{:x}", md5::compute(&url));
                    let mut session = cache_session.lock().expect("session poisoned");
                    if let Some(value) = session
                        .cache
                        .get(&key)
                        .cloned()
                        .or_else(|| persistent_get_cache(&key).ok().flatten())
                    {
                        return value;
                    }
                    match cache_request.get_text(&url, &mut session) {
                        Ok(out) => {
                            let text = out.body;
                            session.cache.insert(key.clone(), text.clone());
                            let _ = persistent_set_cache(&key, &text);
                            text
                        }
                        Err(err) => format!("__LEGADO_REQUEST_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let zip_request = request.clone();
            let zip_session = session.clone();
            java.set(
                "__zipEntryHex",
                Func::from(move |url_or_hex: Coerced<String>, path: Coerced<String>| {
                    let input = url_or_hex.0;
                    let bytes = if input.starts_with("http://")
                        || input.starts_with("https://")
                        || input.starts_with("data:")
                    {
                        let mut session = zip_session.lock().expect("session poisoned");
                        zip_request
                            .get_raw(&input, &mut session)
                            .map(|out| out.body)
                            .map_err(|err| err.to_string())
                    } else {
                        let session = zip_session.lock().expect("session poisoned");
                        session_file_bytes(&session, &input)
                            .ok_or_else(|| "not a Rust-managed file path".to_string())
                            .or_else(|_| hex::decode(input.trim()).map_err(|err| err.to_string()))
                    };
                    match bytes.and_then(|bytes| zip_entry_hex(&bytes, &path.0)) {
                        Ok(hex) => hex,
                        Err(err) if err == "specified file not found in archive" => String::new(),
                        Err(err) => format!("__LEGADO_ZIP_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let sevenz_request = request.clone();
            let sevenz_session = session.clone();
            java.set(
                "__7zEntryHex",
                Func::from(move |url_or_hex: Coerced<String>, path: Coerced<String>| {
                    let input = url_or_hex.0;
                    let bytes = if input.starts_with("http://")
                        || input.starts_with("https://")
                        || input.starts_with("data:")
                    {
                        let mut session = sevenz_session.lock().expect("session poisoned");
                        sevenz_request
                            .get_raw(&input, &mut session)
                            .map(|out| out.body)
                            .map_err(|err| err.to_string())
                    } else {
                        let session = sevenz_session.lock().expect("session poisoned");
                        session_file_bytes(&session, &input)
                            .ok_or_else(|| "not a Rust-managed file path".to_string())
                            .or_else(|_| hex::decode(input.trim()).map_err(|err| err.to_string()))
                    };
                    match bytes.and_then(|bytes| sevenz_entry_hex(&bytes, &path.0)) {
                        Ok(hex) => hex,
                        Err(err) if err == "specified file not found in archive" => String::new(),
                        Err(err) => format!("__LEGADO_7Z_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let rar_request = request.clone();
            let rar_session = session.clone();
            java.set(
                "__rarEntryHex",
                Func::from(move |url_or_hex: Coerced<String>, path: Coerced<String>| {
                    let input = url_or_hex.0;
                    let bytes = if input.starts_with("http://")
                        || input.starts_with("https://")
                        || input.starts_with("data:")
                    {
                        let mut session = rar_session.lock().expect("session poisoned");
                        rar_request
                            .get_raw(&input, &mut session)
                            .map(|out| out.body)
                            .map_err(|err| err.to_string())
                    } else {
                        let session = rar_session.lock().expect("session poisoned");
                        session_file_bytes(&session, &input)
                            .ok_or_else(|| "not a Rust-managed file path".to_string())
                            .or_else(|_| hex::decode(input.trim()).map_err(|err| err.to_string()))
                    };
                    match bytes.and_then(|bytes| rar_entry_hex(&bytes, &path.0)) {
                        Ok(hex) => hex,
                        Err(err) if err == "specified file not found in archive" => String::new(),
                        Err(err) => format!("__LEGADO_RAR_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let ttf_input_request = request.clone();
            let ttf_input_session = session.clone();
            java.set(
                "__queryTTFJsonFromInput",
                Func::from(move |input: Coerced<String>| {
                    let input = input.0;
                    let bytes = if input.starts_with("http://")
                        || input.starts_with("https://")
                        || input.starts_with("data:")
                    {
                        let mut session = ttf_input_session.lock().expect("session poisoned");
                        ttf_input_request
                            .get_raw(&input, &mut session)
                            .map(|out| out.body)
                            .map_err(|err| err.to_string())
                    } else {
                        let session = ttf_input_session.lock().expect("session poisoned");
                        session_file_bytes(&session, &input)
                            .ok_or_else(|| "not a Rust-managed file path".to_string())
                            .or_else(|_| {
                                base64::engine::general_purpose::STANDARD
                                    .decode(input.trim())
                                    .map_err(|err| err.to_string())
                            })
                    };
                    match bytes.and_then(|bytes| query_ttf_json(&bytes)) {
                        Ok(json) => json,
                        Err(err) => format!("__LEGADO_TTF_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__queryTTFJsonFromHex",
                Func::from(move |bytes_hex: Coerced<String>| {
                    match hex::decode(bytes_hex.0.trim())
                        .map_err(|err| err.to_string())
                        .and_then(|bytes| query_ttf_json(&bytes))
                    {
                        Ok(json) => json,
                        Err(err) => format!("__LEGADO_TTF_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let download_request = request.clone();
            let download_session = session.clone();
            java.set(
                "__downloadFile",
                Func::from(move |url: Coerced<String>, path: Coerced<String>| {
                    let mut session = download_session.lock().expect("session poisoned");
                    match download_request.get_raw(&url.0, &mut session) {
                        Ok(out) => {
                            let key = format!("file-bytes:{}", path.0);
                            let bytes_hex = hex::encode(out.body);
                            session.cache.insert(key.clone(), bytes_hex.clone());
                            let _ = persistent_set_cache(&key, &bytes_hex);
                            "true".to_string()
                        }
                        Err(err) => format!("__LEGADO_REQUEST_ERROR__:{err}"),
                    }
                }),
            )
            .map_err(to_js_diag)?;
            let read_file_session = session.clone();
            java.set(
                "__readTextFile",
                Func::from(move |args: Rest<Coerced<String>>| {
                    let path = args
                        .0
                        .first()
                        .map(|value| value.0.as_str())
                        .unwrap_or_default();
                    let charset = args
                        .0
                        .get(1)
                        .map(|value| value.0.as_str())
                        .filter(|value| !value.trim().is_empty());
                    let key = format!("file:{path}");
                    let session = read_file_session.lock().expect("session poisoned");
                    if let Some(text) = session
                        .cache
                        .get(&key)
                        .cloned()
                        .or_else(|| persistent_get_cache(&key).ok().flatten())
                    {
                        return text;
                    }
                    session_file_bytes(&session, path)
                        .map(|bytes| {
                            charset
                                .map(|charset| decode_bytes_to_string(&bytes, charset))
                                .unwrap_or_else(|| decode_bytes_auto_string(&bytes))
                        })
                        .unwrap_or_default()
                }),
            )
            .map_err(to_js_diag)?;
            let read_bytes_session = session.clone();
            java.set(
                "__readBytesFileHex",
                Func::from(move |path: Coerced<String>| {
                    let session = read_bytes_session.lock().expect("session poisoned");
                    session_file_bytes(&session, &path.0)
                        .map(hex::encode)
                        .unwrap_or_default()
                }),
            )
            .map_err(to_js_diag)?;
            let file_exists_session = session.clone();
            java.set(
                "__fileExists",
                Func::from(move |path: Coerced<String>| {
                    let session = file_exists_session.lock().expect("session poisoned");
                    session_file_exists(&session, &path.0)
                }),
            )
            .map_err(to_js_diag)?;
            let write_file_session = session.clone();
            java.set(
                "__writeTextFile",
                Func::from(move |path: Coerced<String>, text: Coerced<String>| {
                    let key = format!("file:{}", path.0);
                    let text = text.0;
                    write_file_session
                        .lock()
                        .expect("session poisoned")
                        .cache
                        .insert(key.clone(), text.clone());
                    let _ = persistent_set_cache(&key, &text);
                    true
                }),
            )
            .map_err(to_js_diag)?;
            let write_bytes_session = session.clone();
            java.set(
                "__writeBytesFileHex",
                Func::from(move |path: Coerced<String>, bytes_hex: Coerced<String>| {
                    let bytes_hex = bytes_hex.0.trim().to_string();
                    if hex::decode(&bytes_hex).is_err() {
                        return false;
                    }
                    let key = format!("file-bytes:{}", path.0);
                    write_bytes_session
                        .lock()
                        .expect("session poisoned")
                        .cache
                        .insert(key.clone(), bytes_hex.clone());
                    let _ = persistent_set_cache(&key, &bytes_hex);
                    true
                }),
            )
            .map_err(to_js_diag)?;
            let delete_file_session = session.clone();
            java.set(
                "__deleteTextFile",
                Func::from(move |path: Coerced<String>| {
                    let mut session = delete_file_session.lock().expect("session poisoned");
                    for prefix in ["file:", "file-bytes:", "folder:"] {
                        let key = format!("{prefix}{}", path.0);
                        session.cache.remove(&key);
                        let _ = persistent_delete_cache(&key);
                    }
                    true
                }),
            )
            .map_err(to_js_diag)?;
            let unzip_session = session.clone();
            java.set(
                "__unzipTextFolder",
                Func::from(
                    move |zip_path: Coerced<String>, folder_path: Coerced<String>| {
                        let mut session = unzip_session.lock().expect("session poisoned");
                        let Some(bytes) = session_file_bytes(&session, &zip_path.0) else {
                            return "__LEGADO_ZIP_ERROR__:Rust-managed archive file not found"
                                .to_string();
                        };
                        match zip_all_text(&bytes) {
                            Ok(text) => {
                                let key = format!("folder:{}", folder_path.0);
                                session.cache.insert(key.clone(), text.clone());
                                let _ = persistent_set_cache(&key, &text);
                                "true".to_string()
                            }
                            Err(err) => format!("__LEGADO_ZIP_ERROR__:{err}"),
                        }
                    },
                ),
            )
            .map_err(to_js_diag)?;
            let un7z_session = session.clone();
            java.set(
                "__un7zTextFolder",
                Func::from(
                    move |zip_path: Coerced<String>, folder_path: Coerced<String>| {
                        let mut session = un7z_session.lock().expect("session poisoned");
                        let Some(bytes) = session_file_bytes(&session, &zip_path.0) else {
                            return "__LEGADO_7Z_ERROR__:Rust-managed archive file not found"
                                .to_string();
                        };
                        match sevenz_all_text(&bytes) {
                            Ok(text) => {
                                let key = format!("folder:{}", folder_path.0);
                                session.cache.insert(key.clone(), text.clone());
                                let _ = persistent_set_cache(&key, &text);
                                "true".to_string()
                            }
                            Err(err) => format!("__LEGADO_7Z_ERROR__:{err}"),
                        }
                    },
                ),
            )
            .map_err(to_js_diag)?;
            let unrar_session = session.clone();
            java.set(
                "__unrarTextFolder",
                Func::from(
                    move |zip_path: Coerced<String>, folder_path: Coerced<String>| {
                        let mut session = unrar_session.lock().expect("session poisoned");
                        let Some(bytes) = session_file_bytes(&session, &zip_path.0) else {
                            return "__LEGADO_RAR_ERROR__:Rust-managed archive file not found"
                                .to_string();
                        };
                        match rar_all_text(&bytes) {
                            Ok(text) => {
                                let key = format!("folder:{}", folder_path.0);
                                session.cache.insert(key.clone(), text.clone());
                                let _ = persistent_set_cache(&key, &text);
                                "true".to_string()
                            }
                            Err(err) => format!("__LEGADO_RAR_ERROR__:{err}"),
                        }
                    },
                ),
            )
            .map_err(to_js_diag)?;
            let read_folder_session = session.clone();
            java.set(
                "__readTextFolder",
                Func::from(move |folder_path: Coerced<String>| {
                    let key = format!("folder:{}", folder_path.0);
                    let mut session = read_folder_session.lock().expect("session poisoned");
                    let text = session
                        .cache
                        .remove(&key)
                        .or_else(|| persistent_get_cache(&key).ok().flatten())
                        .unwrap_or_default();
                    let _ = persistent_delete_cache(&key);
                    text
                }),
            )
            .map_err(to_js_diag)?;

            let ajax_request = request.clone();
            java.set(
                "ajax",
                Func::from(move |args: Rest<Coerced<String>>| {
                    let url = args
                        .first()
                        .map(|value| value.0.clone())
                        .unwrap_or_default();
                    let call_timeout_ms = js_timeout_arg(args.get(1).map(|value| value.0.as_str()));
                    let mut session = request_session.lock().expect("session poisoned");
                    ajax_request
                        .get_text_with_timeout(&url, Vec::new(), call_timeout_ms, &mut session)
                        .map(|out| out.body)
                        .unwrap_or_else(|err| format!("__LEGADO_REQUEST_ERROR__:{err}"))
                }),
            )
            .map_err(to_js_diag)?;
            let ajax_all_request = request.clone();
            java.set(
                "ajaxAll",
                Func::from(move |args: Rest<Coerced<String>>| {
                    let urls_json = args
                        .first()
                        .map(|value| value.0.clone())
                        .unwrap_or_default();
                    let call_timeout_ms = js_timeout_arg(args.get(1).map(|value| value.0.as_str()));
                    let skip_rate_limit = js_bool_arg(args.get(2).map(|value| value.0.as_str()));
                    let urls = match serde_json::from_str::<Vec<String>>(&urls_json) {
                        Ok(urls) => urls,
                        Err(err) => {
                            return format!(
                                "__LEGADO_AJAX_ALL_ERROR__:invalid URL list JSON: {err}"
                            );
                        }
                    };
                    let mut session = ajax_all_session.lock().expect("session poisoned");
                    let responses = urls
                        .iter()
                        .map(|url| {
                            let start = Instant::now();
                            match ajax_all_request.get_text_with_timeout_and_rate_limit(
                                url,
                                Vec::new(),
                                call_timeout_ms,
                                skip_rate_limit,
                                &mut session,
                            ) {
                                Ok(out) => {
                                    response_json_with_call_time(out, elapsed_millis_i32(start))
                                }
                                Err(err) => {
                                    let message = err.to_string();
                                    let call_time = if call_timeout_ms.is_some() {
                                        ajax_test_error_call_time(&message)
                                    } else {
                                        0
                                    };
                                    request_error_json_with_call_time(url, message, call_time)
                                }
                            }
                        })
                        .collect::<Vec<_>>();
                    serde_json::to_string(&responses)
                        .unwrap_or_else(|err| format!("__LEGADO_AJAX_ALL_ERROR__:{err}"))
                }),
            )
            .map_err(to_js_diag)?;
            let connect_request = request.clone();
            let connect_session = session.clone();
            java.set(
                "connect",
                Func::from(move |args: Rest<Coerced<String>>| {
                    let url = args
                        .first()
                        .map(|value| value.0.clone())
                        .unwrap_or_default();
                    let headers = args
                        .get(1)
                        .map(|value| parse_header_map(&value.0))
                        .unwrap_or_default();
                    let call_timeout_ms = js_timeout_arg(args.get(2).map(|value| value.0.as_str()));
                    let mut session = connect_session.lock().expect("session poisoned");
                    match connect_request.get_text_with_timeout(
                        &url,
                        headers,
                        call_timeout_ms,
                        &mut session,
                    ) {
                        Ok(out) => response_json(out).to_string(),
                        Err(err) => request_error_json(&url, err.to_string()).to_string(),
                    }
                }),
            )
            .map_err(to_js_diag)?;

            let http_request = request.clone();
            let http_session = session.clone();
            java.set(
                "__httpRequestRaw",
                Func::from(
                    move |method: Coerced<String>,
                          url: Coerced<String>,
                          body: Coerced<String>,
                          headers_json: Coerced<String>,
                          timeout: i32| {
                        let method = method.0;
                        let url = url.0;
                        let headers = parse_header_map(&headers_json.0);
                        let body = if body.0.is_empty() {
                            None
                        } else {
                            Some(body.0)
                        };
                        let call_timeout_ms = if timeout < 0 {
                            None
                        } else {
                            Some(timeout as u64)
                        };
                        let mut session = http_session.lock().expect("session poisoned");
                        match http_request.request_text_with_timeout_and_redirects(
                            &url,
                            &method,
                            headers,
                            body,
                            call_timeout_ms,
                            false,
                            &mut session,
                        ) {
                            Ok(out) => response_json(out).to_string(),
                            Err(err) => request_error_json(&url, err.to_string()).to_string(),
                        }
                    },
                ),
            )
            .map_err(to_js_diag)?;
            let bytes_request = request.clone();
            let bytes_session = session.clone();
            java.set(
                "__requestBytesHex",
                Func::from(
                    move |url: Coerced<String>, headers_json: Coerced<String>, timeout: i32| {
                        let headers = parse_header_map(&headers_json.0);
                        let call_timeout_ms = if timeout < 0 {
                            None
                        } else {
                            Some(timeout as u64)
                        };
                        let mut session = bytes_session.lock().expect("session poisoned");
                        match bytes_request.get_raw_with_timeout_and_rate_limit(
                            &url.0,
                            headers,
                            call_timeout_ms,
                            false,
                            &mut session,
                        ) {
                            Ok(out) => hex::encode(out.body),
                            Err(err) => format!("__LEGADO_REQUEST_ERROR__:{err}"),
                        }
                    },
                ),
            )
            .map_err(to_js_diag)?;

            let user_agent_session = session.clone();
            let user_agent_source_header = source.header.clone();
            let user_agent_source_key = source_key.clone();
            java.set(
                "__getUserAgentRaw",
                Func::from(move |rule_url: Coerced<String>| {
                    let login_header = {
                        let session = user_agent_session.lock().expect("session poisoned");
                        if session.login_header.is_empty() {
                            persistent_get_login_header(&user_agent_source_key)
                                .ok()
                                .flatten()
                                .unwrap_or_default()
                        } else {
                            session.login_header.clone()
                        }
                    };
                    user_agent_for_rule_url(&rule_url.0, &user_agent_source_header, &login_header)
                }),
            )
            .map_err(to_js_diag)?;
            java.set(
                "__threadSleepRaw",
                Func::from(|millis: Coerced<String>| {
                    let millis = millis.0.parse::<f64>().unwrap_or(0.0).max(0.0) as u64;
                    std::thread::sleep(Duration::from_millis(millis));
                    true
                }),
            )
            .map_err(to_js_diag)?;

            install_platform_action_handler(
                &java,
                &source_name,
                session.clone(),
                self.platform_host.clone(),
            )?;
            globals.set("java", java).map_err(to_js_diag)?;

            install_store_object(
                ctx.clone(),
                &globals,
                "cache",
                session.clone(),
                StoreKind::Cache,
            )?;
            install_cookie_object(ctx.clone(), &globals, session.clone())?;
            install_source_object(
                ctx.clone(),
                &globals,
                session.clone(),
                source,
                request.clone(),
            )?;
            install_store_object(
                ctx.clone(),
                &globals,
                "book",
                session.clone(),
                StoreKind::Book,
            )?;
            install_store_object(
                ctx.clone(),
                &globals,
                "chapter",
                session,
                StoreKind::Chapter,
            )?;
            globals
                .set(
                    "request",
                    Func::from(move |args: Rest<Coerced<String>>| {
                        let url = args
                            .first()
                            .map(|value| value.0.clone())
                            .unwrap_or_default();
                        let method = args
                            .get(1)
                            .map(|value| value.0.clone())
                            .unwrap_or_else(|| "GET".to_string());
                        let body = args
                            .get(2)
                            .map(|value| value.0.clone())
                            .filter(|value| !value.is_empty());
                        let headers = args
                            .get(3)
                            .map(|value| parse_header_map(&value.0))
                            .unwrap_or_default();
                        let call_timeout_ms =
                            js_timeout_arg(args.get(4).map(|value| value.0.as_str()));
                        let mut session = request_global_session.lock().expect("session poisoned");
                        let result = if args.len() <= 1 {
                            request.get_text(&url, &mut session)
                        } else {
                            request.request_text_with_timeout(
                                &url,
                                &method,
                                headers,
                                body,
                                call_timeout_ms,
                                &mut session,
                            )
                        };
                        result
                            .map(|out| out.body)
                            .unwrap_or_else(|err| format!("__LEGADO_REQUEST_ERROR__:{url}:{err}"))
                    }),
                )
                .map_err(to_js_diag)?;
            Ok(())
        })
    }

    fn normalized_script(&mut self, script: &str) -> String {
        if let Some(wrapped) = self.normalized_scripts.get(script) {
            return wrapped.clone();
        }
        let wrapped = normalize_script(script);
        self.normalized_scripts
            .insert(script.to_string(), wrapped.clone());
        wrapped
    }
}

#[derive(Clone, Copy)]
enum StoreKind {
    Cache,
    Book,
    Chapter,
}

fn install_store_object<'js>(
    ctx: rquickjs::Ctx<'js>,
    globals: &rquickjs::Object<'js>,
    name: &str,
    session: Arc<Mutex<AnalyzerSession>>,
    kind: StoreKind,
) -> Result<()> {
    let obj = rquickjs::Object::new(ctx).map_err(to_js_diag)?;
    let get_session = session.clone();
    obj.set(
        "get",
        Func::from(move |key: Coerced<String>| get_store(&get_session, kind, &key.0)),
    )
    .map_err(to_js_diag)?;
    let put_session = session.clone();
    obj.set(
        "put",
        Func::from(move |args: Rest<Coerced<String>>| {
            let key = coerced_arg(&args.0, 0);
            let value = coerced_arg(&args.0, 1);
            put_store(&put_session, kind, key, value.clone());
            value
        }),
    )
    .map_err(to_js_diag)?;
    let put_var_session = session.clone();
    obj.set(
        "putVariable",
        Func::from(move |args: Rest<Coerced<String>>| {
            let key = coerced_arg(&args.0, 0);
            let value = coerced_arg(&args.0, 1);
            put_store(&put_var_session, kind, key, value);
            true
        }),
    )
    .map_err(to_js_diag)?;
    let set_session = session.clone();
    obj.set(
        "setVariable",
        Func::from(move |args: Rest<Coerced<String>>| {
            let key = coerced_arg(&args.0, 0);
            let value = coerced_arg(&args.0, 1);
            put_store(&set_session, kind, key, value);
        }),
    )
    .map_err(to_js_diag)?;
    let getv_session = session.clone();
    obj.set(
        "getVariable",
        Func::from(move |key: Coerced<String>| get_store(&getv_session, kind, &key.0)),
    )
    .map_err(to_js_diag)?;
    let del_session = session.clone();
    obj.set(
        "delete",
        Func::from(move |key: Coerced<String>| {
            let key = key.0;
            let mut session = del_session.lock().expect("session poisoned");
            match kind {
                StoreKind::Cache => {
                    session.cache.remove(&key);
                    session.cache.remove(&file_cache_key(&key));
                    session.java_store.remove(&memory_cache_key(&key));
                    let _ = persistent_delete_cache(&key);
                    let _ = persistent_delete_cache(&file_cache_key(&key));
                }
                StoreKind::Book => {
                    session.book_variables.remove(&key);
                }
                StoreKind::Chapter => {
                    session.chapter_variables.remove(&key);
                }
            };
            ()
        }),
    )
    .map_err(to_js_diag)?;
    if matches!(kind, StoreKind::Cache) {
        let put_file_session = session.clone();
        obj.set(
            "putFile",
            Func::from(move |args: Rest<Coerced<String>>| {
                let key = coerced_arg(&args.0, 0);
                let value = coerced_arg(&args.0, 1);
                put_file_cache(&put_file_session, key, value.clone());
                value
            }),
        )
        .map_err(to_js_diag)?;
        let get_file_session = session.clone();
        obj.set(
            "getFile",
            Func::from(move |key: Coerced<String>| get_file_cache(&get_file_session, &key.0)),
        )
        .map_err(to_js_diag)?;
        let put_memory_session = session.clone();
        obj.set(
            "putMemory",
            Func::from(move |args: Rest<Coerced<String>>| {
                let key = coerced_arg(&args.0, 0);
                let value = coerced_arg(&args.0, 1);
                put_memory_cache(&put_memory_session, key, value.clone());
                value
            }),
        )
        .map_err(to_js_diag)?;
        let get_memory_session = session.clone();
        obj.set(
            "getFromMemory",
            Func::from(move |key: Coerced<String>| get_memory_cache(&get_memory_session, &key.0)),
        )
        .map_err(to_js_diag)?;
        let delete_memory_session = session.clone();
        obj.set(
            "deleteMemory",
            Func::from(move |key: Coerced<String>| {
                delete_memory_cache(&delete_memory_session, &key.0);
            }),
        )
        .map_err(to_js_diag)?;
    }
    if matches!(kind, StoreKind::Book) {
        obj.set("durChapterTitle", "").map_err(to_js_diag)?;
        obj.set("durChapterIndex", 0).map_err(to_js_diag)?;
        let replace_session = session.clone();
        obj.set(
            "setUseReplaceRule",
            Func::from(move |use_replace_rule: bool| {
                put_store(
                    &replace_session,
                    StoreKind::Book,
                    "readConfig.useReplaceRule".to_string(),
                    use_replace_rule.to_string(),
                );
            }),
        )
        .map_err(to_js_diag)?;
        let get_replace_session = session.clone();
        obj.set(
            "getUseReplaceRule",
            Func::from(move || {
                get_store(
                    &get_replace_session,
                    StoreKind::Book,
                    "readConfig.useReplaceRule",
                ) == "true"
            }),
        )
        .map_err(to_js_diag)?;
    }
    if matches!(kind, StoreKind::Chapter) {
        obj.set("index", 0).map_err(to_js_diag)?;
        let put_lyric_session = session.clone();
        obj.set(
            "putLyric",
            Func::from(move |value: Coerced<String>| {
                put_store(
                    &put_lyric_session,
                    StoreKind::Chapter,
                    "lyric".to_string(),
                    value.0,
                );
            }),
        )
        .map_err(to_js_diag)?;
        let put_img_url_session = session.clone();
        obj.set(
            "putImgUrl",
            Func::from(move |value: Coerced<String>| {
                put_store(
                    &put_img_url_session,
                    StoreKind::Chapter,
                    "imgUrl".to_string(),
                    value.0,
                );
            }),
        )
        .map_err(to_js_diag)?;
    }
    globals.set(name, obj).map_err(to_js_diag)?;
    Ok(())
}

fn install_cookie_object<'js>(
    ctx: rquickjs::Ctx<'js>,
    globals: &rquickjs::Object<'js>,
    session: Arc<Mutex<AnalyzerSession>>,
) -> Result<()> {
    let obj = rquickjs::Object::new(ctx).map_err(to_js_diag)?;
    let get_session = session.clone();
    obj.set(
        "getCookie",
        Func::from(move |host: Coerced<String>| {
            get_session
                .lock()
                .expect("session poisoned")
                .get_cookie(&host.0)
        }),
    )
    .map_err(to_js_diag)?;
    let get_key_session = session.clone();
    obj.set(
        "getKey",
        Func::from(move |host: Coerced<String>, key: Coerced<String>| {
            get_key_session
                .lock()
                .expect("session poisoned")
                .get_cookie(&host.0)
                .split(';')
                .find_map(|part| {
                    let (name, value) = part.trim().split_once('=')?;
                    (name == key.0).then(|| value.to_string())
                })
                .unwrap_or_default()
        }),
    )
    .map_err(to_js_diag)?;
    let set_session = session.clone();
    obj.set(
        "setCookie",
        Func::from(move |host: Coerced<String>, value: Coerced<String>| {
            set_session
                .lock()
                .expect("session poisoned")
                .set_cookie(host.0, value.0);
        }),
    )
    .map_err(to_js_diag)?;
    obj.set(
        "replaceCookie",
        obj.get::<_, rquickjs::Value>("setCookie")
            .map_err(to_js_diag)?,
    )
    .map_err(to_js_diag)?;
    obj.set(
        "setWebCookie",
        obj.get::<_, rquickjs::Value>("setCookie")
            .map_err(to_js_diag)?,
    )
    .map_err(to_js_diag)?;
    let remove_session = session;
    obj.set(
        "removeCookie",
        Func::from(move |host: Coerced<String>| {
            remove_session
                .lock()
                .expect("session poisoned")
                .remove_cookie(host.0);
        }),
    )
    .map_err(to_js_diag)?;
    globals.set("cookie", obj).map_err(to_js_diag)?;
    Ok(())
}

fn install_source_object<'js>(
    ctx: rquickjs::Ctx<'js>,
    globals: &rquickjs::Object<'js>,
    session: Arc<Mutex<AnalyzerSession>>,
    source: &BookSource,
    request: RequestEngine,
) -> Result<()> {
    let obj = rquickjs::Object::new(ctx.clone()).map_err(to_js_diag)?;
    obj.set("bookSourceUrl", source.book_source_url.clone())
        .map_err(to_js_diag)?;
    obj.set("bookSourceName", source.book_source_name.clone())
        .map_err(to_js_diag)?;
    obj.set("sourceUrl", source.book_source_url.clone())
        .map_err(to_js_diag)?;
    obj.set("sourceName", source.book_source_name.clone())
        .map_err(to_js_diag)?;
    obj.set("jsLib", source.js_lib.clone())
        .map_err(to_js_diag)?;
    obj.set("loginUrl", source.login_url.clone())
        .map_err(to_js_diag)?;
    obj.set("header", source.header.clone())
        .map_err(to_js_diag)?;
    if let Some(value) = source
        .extra
        .get("variableComment")
        .and_then(serde_json::Value::as_str)
    {
        obj.set("variableComment", value.to_string())
            .map_err(to_js_diag)?;
    }
    if let Some(value) = source
        .extra
        .get("loginUi")
        .and_then(serde_json::Value::as_str)
    {
        obj.set("__loginUiText", value.to_string())
            .map_err(to_js_diag)?;
    }
    if let Some(extra) = source.extra.as_object() {
        for (key, value) in extra {
            if key == "loginUi" {
                continue;
            }
            if obj.contains_key(key.as_str()).map_err(to_js_diag)? {
                continue;
            }
            match value {
                serde_json::Value::String(value) => {
                    obj.set(key.as_str(), value.clone()).map_err(to_js_diag)?;
                }
                serde_json::Value::Number(value) => {
                    if let Some(value) = value.as_i64() {
                        obj.set(key.as_str(), value).map_err(to_js_diag)?;
                    } else if let Some(value) = value.as_f64() {
                        obj.set(key.as_str(), value).map_err(to_js_diag)?;
                    }
                }
                serde_json::Value::Bool(value) => {
                    obj.set(key.as_str(), *value).map_err(to_js_diag)?;
                }
                _ => {}
            }
        }
    }
    let key = source.book_source_url.clone();
    obj.set("getKey", Func::from(move || key.clone()))
        .map_err(to_js_diag)?;
    let concurrent_key = source.book_source_url.clone();
    obj.set(
        "putConcurrent",
        Func::from(move |value: Coerced<String>| {
            request.update_concurrent_rate(&concurrent_key, &value.0);
        }),
    )
    .map_err(to_js_diag)?;
    let get_session = session.clone();
    obj.set(
        "getVariable",
        Func::from(move |args: Rest<Coerced<String>>| {
            let session = get_session.lock().expect("session poisoned");
            if let Some(key) = args.0.first() {
                source_variable_get(&session, &key.0)
            } else {
                source_variable_json(&session)
            }
        }),
    )
    .map_err(to_js_diag)?;
    let set_session = session.clone();
    obj.set(
        "setVariable",
        Func::from(move |args: Rest<Coerced<String>>| {
            let mut session = set_session.lock().expect("session poisoned");
            match args.0.len() {
                len if len >= 2 => {
                    let key = coerced_arg(&args.0, 0);
                    let value = coerced_arg(&args.0, 1);
                    source_variable_set_key(&mut session, &key, &value);
                }
                1 => {
                    let json = coerced_arg(&args.0, 0);
                    source_variable_set_raw(&mut session, &json);
                }
                _ => {}
            }
        }),
    )
    .map_err(to_js_diag)?;
    let put_variable = obj
        .get::<_, rquickjs::Value>("setVariable")
        .map_err(to_js_diag)?;
    obj.set("putVariable", put_variable).map_err(to_js_diag)?;
    let put_cache_session = session.clone();
    let put_source_key = source.book_source_url.clone();
    obj.set(
        "put",
        Func::from(move |args: Rest<Coerced<String>>| {
            let key = coerced_arg(&args.0, 0);
            let value = coerced_arg(&args.0, 1);
            put_cache_session
                .lock()
                .expect("session poisoned")
                .source_store
                .insert(key.clone(), value.clone());
            let _ = persistent_set_source_store(&put_source_key, &key, &value);
            value
        }),
    )
    .map_err(to_js_diag)?;
    let get_cache_session = session.clone();
    let get_source_key = source.book_source_url.clone();
    obj.set(
        "get",
        Func::from(move |key: Coerced<String>| {
            get_cache_session
                .lock()
                .expect("session poisoned")
                .source_store
                .get(&key.0)
                .cloned()
                .or_else(|| {
                    persistent_get_source_store(&get_source_key, &key.0)
                        .ok()
                        .flatten()
                })
                .unwrap_or_default()
        }),
    )
    .map_err(to_js_diag)?;
    let login_get = session.clone();
    obj.set(
        "__getLoginInfoMapJson",
        Func::from(move || {
            serde_json::to_string(&login_get.lock().expect("session poisoned").login_info)
                .unwrap_or_default()
        }),
    )
    .map_err(to_js_diag)?;
    let login_info_get = session.clone();
    obj.set(
        "getLoginInfo",
        Func::from(move || {
            let session = login_info_get.lock().expect("session poisoned");
            if !session.login_info_raw.is_empty() {
                session.login_info_raw.clone()
            } else {
                serde_json::to_string(&session.login_info).unwrap_or_default()
            }
        }),
    )
    .map_err(to_js_diag)?;
    let login_put = session.clone();
    obj.set(
        "putLoginInfo",
        Func::from(move |args: Rest<Coerced<String>>| {
            let mut session = login_put.lock().expect("session poisoned");
            match args.0.len() {
                1 => {
                    let json = coerced_arg(&args.0, 0);
                    session.login_info_raw = json.clone();
                    session.login_info.clear();
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) {
                        if let Some(object) = value.as_object() {
                            for (key, value) in object {
                                session
                                    .login_info
                                    .insert(key.clone(), js_variable_value_to_string(value));
                            }
                        }
                    }
                }
                len if len >= 2 => {
                    let key = coerced_arg(&args.0, 0);
                    let value = coerced_arg(&args.0, 1);
                    session.login_info.insert(key, value);
                    session.login_info_raw =
                        serde_json::to_string(&session.login_info).unwrap_or_default();
                }
                _ => {}
            }
            true
        }),
    )
    .map_err(to_js_diag)?;
    let login_remove_session = session.clone();
    let login_remove_key = source.book_source_url.clone();
    obj.set(
        "removeLoginInfo",
        Func::from(move || {
            let _ = persistent_delete_login_info(&login_remove_key);
            let mut session = login_remove_session.lock().expect("session poisoned");
            session.login_info.clear();
            session.login_info_raw.clear();
        }),
    )
    .map_err(to_js_diag)?;
    let login_header_get = session.clone();
    let login_header_get_key = source.book_source_url.clone();
    obj.set(
        "getLoginHeader",
        Func::from(move || {
            login_header_get
                .lock()
                .expect("session poisoned")
                .login_header
                .clone()
                .or_else_nonempty(|| {
                    persistent_get_login_header(&login_header_get_key)
                        .ok()
                        .flatten()
                })
                .unwrap_or_default()
        }),
    )
    .map_err(to_js_diag)?;
    let login_header_map_get = session.clone();
    let login_header_map_key = source.book_source_url.clone();
    obj.set(
        "__getLoginHeaderMapJson",
        Func::from(move || {
            let header = login_header_map_get
                .lock()
                .expect("session poisoned")
                .login_header
                .clone()
                .or_else_nonempty(|| {
                    persistent_get_login_header(&login_header_map_key)
                        .ok()
                        .flatten()
                })
                .unwrap_or_default();
            header_map_json(&header)
        }),
    )
    .map_err(to_js_diag)?;
    let source_header_map_get = session.clone();
    let source_header_map_key = source.book_source_url.clone();
    let source_header_map_header = source.header.clone();
    obj.set(
        "__getHeaderMapJson",
        Func::from(move |args: Rest<Coerced<String>>| {
            let has_login_header = args
                .0
                .first()
                .map(|value| js_bool_arg(Some(&value.0)))
                .unwrap_or(false);
            let login_header = if has_login_header {
                source_header_map_get
                    .lock()
                    .expect("session poisoned")
                    .login_header
                    .clone()
                    .or_else_nonempty(|| {
                        persistent_get_login_header(&source_header_map_key)
                            .ok()
                            .flatten()
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            };
            source_header_map_json(&source_header_map_header, &login_header, has_login_header)
        }),
    )
    .map_err(to_js_diag)?;
    let login_header_put = session.clone();
    let login_header_put_key = source.book_source_url.clone();
    obj.set(
        "putLoginHeader",
        Func::from(move |header: Coerced<String>| {
            let header = header.0;
            let _ = persistent_set_login_header(&login_header_put_key, &header);
            let mut session = login_header_put.lock().expect("session poisoned");
            if let Some(cookie) = login_header_cookie(&header) {
                session.set_cookie(login_header_put_key.clone(), cookie);
            }
            session.login_header = header;
            true
        }),
    )
    .map_err(to_js_diag)?;
    let login_header_remove = session.clone();
    let login_header_remove_key = source.book_source_url.clone();
    obj.set(
        "removeLoginHeader",
        Func::from(move || {
            let _ = persistent_delete_login_header(&login_header_remove_key);
            let mut session = login_header_remove.lock().expect("session poisoned");
            session.login_header.clear();
            session.remove_cookie(login_header_remove_key.clone());
        }),
    )
    .map_err(to_js_diag)?;
    obj.set("refreshExplore", Func::from(|| {}))
        .map_err(to_js_diag)?;
    let refresh_js_lib_session = session.clone();
    let refresh_js_lib = source.js_lib.clone();
    obj.set(
        "refreshJSLib",
        Func::from(move || {
            let mut session = refresh_js_lib_session.lock().expect("session poisoned");
            refresh_js_lib_cache(&mut session, &refresh_js_lib);
            true
        }),
    )
    .map_err(to_js_diag)?;
    obj.set("loginUi", Func::from(|| true))
        .map_err(to_js_diag)?;
    globals.set("source", obj).map_err(to_js_diag)?;
    if source.extra.is_object() {
        let raw = serde_json::to_string(&source.extra).unwrap_or_else(|_| "{}".to_string());
        let raw = serde_json::to_string(&raw).unwrap_or_else(|_| "\"{}\"".to_string());
        let script = format!(
            r#"(function(raw) {{
  var extra = JSON.parse(raw || "{{}}");
  if (!extra || typeof extra !== "object") return;
  Object.keys(extra).forEach(function(key) {{
    if (key === "loginUi") return;
    if (Object.prototype.hasOwnProperty.call(source, key)) return;
    source[key] = extra[key];
  }});
}})({raw});"#
        );
        ctx.eval::<(), _>(script)
            .catch(&ctx)
            .map_err(js_caught_to_diag)?;
    }
    Ok(())
}

fn source_variable_json(session: &AnalyzerSession) -> String {
    session.source_variable.clone()
}

fn source_variable_get(session: &AnalyzerSession, key: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&session.source_variable) {
        if let Some(value) = value.get(key) {
            return js_variable_value_to_string(value);
        }
    }
    session.variables.get(key).cloned().unwrap_or_default()
}

fn source_variable_set_key(session: &mut AnalyzerSession, key: &str, value: &str) {
    session.variables.insert(key.to_string(), value.to_string());
    let mut root = serde_json::from_str::<serde_json::Value>(&session.source_variable)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    root.insert(
        key.to_string(),
        serde_json::Value::String(value.to_string()),
    );
    session.source_variable = serde_json::Value::Object(root).to_string();
}

fn source_variable_set_raw(session: &mut AnalyzerSession, raw: &str) {
    session.source_variable = raw.to_string();
    session.variables.clear();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(object) = value.as_object() {
            for (key, value) in object {
                session
                    .variables
                    .insert(key.clone(), js_variable_value_to_string(value));
            }
        }
    }
}

fn js_variable_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        value => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn refresh_js_lib_cache(session: &mut AnalyzerSession, js_lib: &str) {
    let js_lib = js_lib.trim();
    if js_lib.is_empty() {
        return;
    }
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(js_lib) {
        for value in map.values().filter_map(serde_json::Value::as_str) {
            if value.starts_with("http://") || value.starts_with("https://") {
                let key = format!("cacheFile:{:x}", md5::compute(value));
                session.cache.remove(&key);
                let _ = persistent_delete_cache(&key);
            }
        }
    }
}

fn install_platform_action_handler(
    java: &rquickjs::Object<'_>,
    source_name: &str,
    session: Arc<Mutex<AnalyzerSession>>,
    platform_host: Option<PlatformHostRef>,
) -> Result<()> {
    let source_name = source_name.to_string();
    java.set(
        "__platformAction",
        Func::from(move |api: String, args_json: String| -> String {
            if let Some(host) = platform_host.as_ref() {
                let response = host.handle_platform_action(&api, &source_name, &args_json);
                session
                    .lock()
                    .expect("session poisoned")
                    .java_store
                    .insert("__platform_actions".to_string(), response.clone());
                response
            } else {
                let marker =
                    format!("__LEGADO_UNSUPPORTED_PLATFORM_API__:{source_name}:{api}:{args_json}");
                session
                    .lock()
                    .expect("session poisoned")
                    .java_store
                    .insert("__platform_actions".to_string(), marker.clone());
                serde_json::json!({
                    "unsupported": true,
                    "marker": marker,
                    "url": "",
                    "body": "",
                    "code": 500,
                    "message": "Unsupported platform API"
                })
                .to_string()
            }
        }),
    )
    .map_err(to_js_diag)?;
    Ok(())
}

fn apply_eval_bindings(ctx: rquickjs::Ctx<'_>, bindings_json: &str) -> Result<()> {
    if bindings_json.trim().is_empty() {
        return Ok(());
    }
    serde_json::from_str::<serde_json::Value>(bindings_json).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::JavaScript,
            format!("invalid eval bindings JSON: {err}"),
        )
    })?;
    let raw = serde_json::to_string(bindings_json).unwrap_or_else(|_| "\"{}\"".to_string());
    let script = format!(
        r#"(function(raw) {{
  var bindings = JSON.parse(raw || "{{}}");
  function merge(target, value) {{
    if (!target || !value || typeof value !== "object") return;
    Object.keys(value).forEach(function(key) {{ target[key] = value[key]; }});
  }}
  function mapLike(value) {{
    var actual = value && typeof value === "object" ? value : {{}};
    return {{
      get: function(key) {{
        if (arguments.length === 0) return actual;
        var out = actual[String(key)];
        return out === undefined ? null : String(out);
      }},
      set: function(next) {{
        actual = next && typeof next === "object" ? next : {{}};
      }},
      put: function(key, next) {{
        actual[String(key)] = String(next);
        return String(next);
      }},
      remove: function(key) {{
        var old = actual[String(key)];
        delete actual[String(key)];
        return old === undefined ? null : String(old);
      }},
      putAll: function(next) {{
        if (next && typeof next === "object") {{
          Object.keys(next).forEach(function(key) {{ actual[String(key)] = String(next[key]); }});
        }}
      }},
      containsKey: function(key) {{
        return Object.prototype.hasOwnProperty.call(actual, String(key));
      }}
    }};
  }}
  Object.keys(bindings).forEach(function(key) {{
    if (key === "java" || key === "source" || key === "cache" || key === "cookie") return;
    if (bindings[key] && typeof bindings[key] === "object" && bindings[key].__javaBytesHex !== undefined) {{
      globalThis[key] = __javaBytes(String(bindings[key].__javaBytesHex || ""));
      return;
    }}
    if (key === "infoMap" && typeof bindings[key] === "object") {{
      globalThis.infoMap = mapLike(bindings[key]);
      return;
    }}
    if (key === "book" && typeof globalThis.book === "object") {{
      merge(globalThis.book, bindings[key]);
      return;
    }}
    if (key === "chapter" && typeof globalThis.chapter === "object") {{
      merge(globalThis.chapter, bindings[key]);
      return;
    }}
    globalThis[key] = bindings[key];
  }});
}})({raw});"#
    );
    ctx.eval::<(), _>(script)
        .catch(&ctx)
        .map_err(js_caught_to_diag)
}

fn sync_global_state(ctx: rquickjs::Ctx<'_>, session: &Arc<Mutex<AnalyzerSession>>) -> Result<()> {
    sync_global_object(ctx.clone(), session, "book", StoreKind::Book)?;
    sync_global_object(ctx, session, "chapter", StoreKind::Chapter)?;
    Ok(())
}

fn sync_global_object(
    ctx: rquickjs::Ctx<'_>,
    session: &Arc<Mutex<AnalyzerSession>>,
    name: &str,
    kind: StoreKind,
) -> Result<()> {
    let script = format!(
        r#"JSON.stringify((function(o) {{
  var out = {{}};
  if (!o || typeof o !== "object") return out;
  Object.keys(o).forEach(function(key) {{
    var value = o[key];
    if (typeof value !== "function") out[key] = value;
  }});
  return out;
}})(globalThis.{name}))"#
    );
    let json: String = ctx.eval(script).catch(&ctx).map_err(js_caught_to_diag)?;
    let value: serde_json::Value = serde_json::from_str(&json).map_err(|err| {
        Diagnostic::new(
            DiagnosticKind::JavaScript,
            format!("failed to sync JS {name} object: {err}"),
        )
    })?;
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    let mut session = session.lock().expect("session poisoned");
    for (key, value) in object {
        let value = js_variable_value_to_string(value);
        match kind {
            StoreKind::Book => {
                session.book_variables.insert(key.clone(), value);
            }
            StoreKind::Chapter => {
                session.chapter_variables.insert(key.clone(), value);
            }
            StoreKind::Cache => {}
        }
    }
    Ok(())
}

fn get_store(session: &Arc<Mutex<AnalyzerSession>>, kind: StoreKind, key: &str) -> String {
    let session = session.lock().expect("session poisoned");
    match kind {
        StoreKind::Cache => {
            return session
                .java_store
                .get(&memory_cache_key(key))
                .cloned()
                .or_else(|| session.cache.get(key).cloned())
                .or_else(|| persistent_get_cache(key).ok().flatten())
                .unwrap_or_default();
        }
        StoreKind::Book => session.book_variables.get(key),
        StoreKind::Chapter => session.chapter_variables.get(key),
    }
    .cloned()
    .unwrap_or_default()
}

fn get_memory_cache(session: &Arc<Mutex<AnalyzerSession>>, key: &str) -> String {
    let session = session.lock().expect("session poisoned");
    session
        .java_store
        .get(&memory_cache_key(key))
        .cloned()
        .or_else(|| session.cache.get(key).cloned())
        .unwrap_or_default()
}

fn get_file_cache(session: &Arc<Mutex<AnalyzerSession>>, key: &str) -> String {
    let storage_key = file_cache_key(key);
    let session = session.lock().expect("session poisoned");
    session
        .cache
        .get(&storage_key)
        .cloned()
        .or_else(|| persistent_get_cache(&storage_key).ok().flatten())
        .unwrap_or_default()
}

fn put_file_cache(session: &Arc<Mutex<AnalyzerSession>>, key: String, value: String) {
    let storage_key = file_cache_key(&key);
    let _ = persistent_set_cache(&storage_key, &value);
    let mut session = session.lock().expect("session poisoned");
    session.cache.insert(storage_key, value);
}

fn put_memory_cache(session: &Arc<Mutex<AnalyzerSession>>, key: String, value: String) {
    let mut session = session.lock().expect("session poisoned");
    session.java_store.insert(memory_cache_key(&key), value);
}

fn delete_memory_cache(session: &Arc<Mutex<AnalyzerSession>>, key: &str) {
    let mut session = session.lock().expect("session poisoned");
    session.java_store.remove(&memory_cache_key(key));
    session.cache.remove(key);
}

fn memory_cache_key(key: &str) -> String {
    format!("__cache_memory:{key}")
}

fn file_cache_key(key: &str) -> String {
    format!("__cache_file:{key}")
}

fn put_store(session: &Arc<Mutex<AnalyzerSession>>, kind: StoreKind, key: String, value: String) {
    let mut session = session.lock().expect("session poisoned");
    match kind {
        StoreKind::Cache => {
            let _ = persistent_set_cache(&key, &value);
            session.cache.insert(key, value)
        }
        StoreKind::Book => session.book_variables.insert(key, value),
        StoreKind::Chapter => session.chapter_variables.insert(key, value),
    };
}

fn normalize_script(script: &str) -> String {
    let trimmed = script.trim();
    let mut body = trimmed;
    if let Some(stripped) = body.strip_prefix("@js:") {
        body = stripped;
    }
    if let Some(stripped) = body.strip_prefix("<js>") {
        body = stripped;
    }
    if let Some(stripped) = body.strip_suffix("</js>") {
        body = stripped;
    }
    let body = preprocess_js(body);
    let trimmed_start = body.trim_start();
    if trimmed_start.starts_with("return ") || body.contains("; return ") {
        format!("(function() {{\n{body}\n}})()")
    } else {
        body
    }
}

fn lexical_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:let|const)\b").expect("valid lexical declaration regex"))
}

fn get_bytes_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"String\(([^()]+)\)\.getBytes\(\)"#).expect("valid getBytes regex")
    })
}

fn assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(?:^|[;\n{])\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=")
            .expect("valid assignment regex")
    })
}

fn for_loop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bfor\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s+(?:in|of)\b")
            .expect("valid for loop regex")
    })
}

fn eval_literal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"eval\(\s*"((?:\\.|[^"\\])*)"\s*\)"#).expect("valid eval literal regex")
    })
}

fn imported_assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[;\n{}])(\s*)([A-Za-z_$][A-Za-z0-9_$]*)\s*=")
            .expect("valid imported assignment regex")
    })
}

fn imported_for_loop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bfor\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s+(in|of)\b")
            .expect("valid imported for regex")
    })
}

fn imported_var_assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[;\n])(\s*)var\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=")
            .expect("valid imported var declaration regex")
    })
}

fn this_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bthis\b").expect("valid this regex"))
}

fn top_level_var_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[;\n])(\s*)var\s+([^;=\n]+);")
            .expect("valid top-level var declaration regex")
    })
}

fn js_var_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z_$][A-Za-z0-9_$]*$").expect("valid var name regex"))
}

fn terminal_if_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bif\s*\(").expect("valid terminal if regex"))
}

fn top_level_function_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)(^|[;\n])(\s*)function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
            .expect("valid top-level function regex")
    })
}

fn function_body_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bfunction(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(")
            .expect("valid function body regex")
    })
}

fn keyword_declaration_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:var|let|const|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)")
            .expect("valid keyword declaration regex")
    })
}

fn var_declaration_list_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bvar\s+([^;\n]*)").expect("valid var declaration list regex"))
}

fn declared_js_names(script: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    names.extend(
        keyword_declaration_re()
            .captures_iter(script)
            .filter_map(|caps| caps.get(1).map(|name| name.as_str().to_string())),
    );
    for caps in var_declaration_list_re().captures_iter(script) {
        let Some(list) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for item in list.split(',') {
            let name = item
                .trim()
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '$')
                .next()
                .unwrap_or_default();
            if js_var_name_re().is_match(name) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

fn preprocess_js(script: &str) -> String {
    let script = preprocess_direct_eval_literals(script);
    let script = preprocess_eval_string_arguments(&script);
    let script = replace_this_outside_literals(&script);
    let script = remove_with_blocks(&script);
    let script = lexical_decl_re().replace_all(&script, "var").into_owned();
    let script = get_bytes_re()
        .replace_all(&script, "__javaStringBytes(String($1))")
        .into_owned();
    let declared_names = declared_js_names(&script);
    let re = assignment_re();
    let mut names = Vec::new();
    for caps in re.captures_iter(&script) {
        let whole = caps.get(0).expect("assignment match");
        if assignment_match_is_arrow(&script, whole.end()) {
            continue;
        }
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if matches!(
            name,
            "if" | "for" | "while" | "switch" | "return" | "let" | "const" | "var"
        ) {
            continue;
        }
        let declared = declared_names.contains(name);
        if !declared && !names.iter().any(|existing: &&str| *existing == name) {
            names.push(name);
        }
    }
    for caps in for_loop_re().captures_iter(&script) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let declared = declared_names.contains(name);
        if !declared && !names.iter().any(|existing: &&str| *existing == name) {
            names.push(name);
        }
    }
    if names.is_empty() {
        script
    } else {
        format!("var {};\n{}", names.join(","), script)
    }
}

fn preprocess_direct_eval_literals(script: &str) -> String {
    eval_literal_re()
        .replace_all(script, |caps: &regex::Captures<'_>| {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let quoted = format!("\"{raw}\"");
            let Ok(decoded) = serde_json::from_str::<String>(&quoted) else {
                return caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
            };
            if decoded.contains("globalThis.") {
                return caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
            }
            let processed = preprocess_imported_eval_script(&decoded);
            format!(
                "eval({})",
                serde_json::to_string(&processed).unwrap_or_else(|_| "\"\"".to_string())
            )
        })
        .into_owned()
}

fn preprocess_eval_string_arguments(script: &str) -> String {
    let mut out = String::new();
    let mut index = 0usize;
    while let Some(relative) = script[index..].find("eval") {
        let eval_start = index + relative;
        if !is_identifier_boundary(script, eval_start, 4) {
            out.push_str(&script[index..eval_start + 4]);
            index = eval_start + 4;
            continue;
        }
        let Some(eval_open) =
            skip_ws(script, eval_start + 4).filter(|pos| byte_at(script, *pos) == Some(b'('))
        else {
            out.push_str(&script[index..eval_start + 4]);
            index = eval_start + 4;
            continue;
        };
        let string_start = skip_ws(script, eval_open + 1).unwrap_or(eval_open + 1);
        if !script[string_start..].starts_with("String")
            || !is_identifier_boundary(script, string_start, 6)
        {
            out.push_str(&script[index..eval_start + 4]);
            index = eval_start + 4;
            continue;
        }
        let Some(string_open) =
            skip_ws(script, string_start + 6).filter(|pos| byte_at(script, *pos) == Some(b'('))
        else {
            out.push_str(&script[index..eval_start + 4]);
            index = eval_start + 4;
            continue;
        };
        let Some(string_close) = find_matching_delimiter(script, string_open, b'(', b')') else {
            out.push_str(&script[index..eval_start + 4]);
            index = eval_start + 4;
            continue;
        };
        let Some(eval_close) =
            skip_ws(script, string_close + 1).filter(|pos| byte_at(script, *pos) == Some(b')'))
        else {
            out.push_str(&script[index..eval_start + 4]);
            index = eval_start + 4;
            continue;
        };
        out.push_str(&script[index..eval_start]);
        out.push_str("eval((typeof java !== \"undefined\" && typeof java.__preprocessImportedScript === \"function\") ? java.__preprocessImportedScript(");
        out.push_str(&script[string_start..=string_close]);
        out.push_str(") : ");
        out.push_str(&script[string_start..=string_close]);
        out.push(')');
        index = eval_close + 1;
    }
    out.push_str(&script[index..]);
    out
}

fn is_identifier_boundary(script: &str, start: usize, len: usize) -> bool {
    let bytes = script.as_bytes();
    let before = start
        .checked_sub(1)
        .and_then(|pos| bytes.get(pos).copied())
        .is_none_or(|byte| !is_js_identifier_byte(byte) && byte != b'.');
    let after = bytes
        .get(start + len)
        .copied()
        .is_none_or(|byte| !is_js_identifier_byte(byte));
    before && after
}

fn is_js_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn byte_at(script: &str, index: usize) -> Option<u8> {
    script.as_bytes().get(index).copied()
}

fn skip_ws(script: &str, mut index: usize) -> Option<usize> {
    let bytes = script.as_bytes();
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_whitespace() {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn preprocess_imported_eval_script(script: &str) -> String {
    let script = preprocess_direct_eval_literals(script);
    let script = preprocess_eval_string_arguments(&script);
    let script = replace_this_outside_literals(&script);
    let script = remove_with_blocks(&script);
    let script = lexical_decl_re().replace_all(&script, "var").into_owned();
    let script = get_bytes_re()
        .replace_all(&script, "__javaStringBytes(String($1))")
        .into_owned();
    let script = rewrite_top_level_var_declarations(&script);
    let assign_re = imported_assignment_re();
    let declared_names = declared_js_names(&script);
    let mut implicit_globals: Vec<String> = Vec::new();
    for caps in assign_re.captures_iter(&script) {
        let whole = caps.get(0).expect("assignment match");
        if is_in_js_literal(&script, whole.start()) {
            continue;
        }
        if assignment_match_is_arrow(&script, whole.end()) {
            continue;
        }
        let name = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
        if matches!(
            name,
            "if" | "for" | "while" | "switch" | "return" | "let" | "const" | "var"
        ) || declared_names.contains(name)
        {
            continue;
        }
        if !implicit_globals.iter().any(|existing| existing == name) {
            implicit_globals.push(name.to_string());
        }
    }
    let for_re = imported_for_loop_re();
    for caps in for_re.captures_iter(&script) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if declared_names.contains(name) {
            continue;
        }
        if !implicit_globals.iter().any(|existing| existing == name) {
            implicit_globals.push(name.to_string());
        }
    }
    let mut script = assign_re
        .replace_all(&script, |caps: &regex::Captures<'_>| {
            let Some(whole) = caps.get(0) else {
                return String::new();
            };
            if is_in_js_literal(&script, whole.start()) {
                return whole.as_str().to_string();
            }
            if assignment_match_is_arrow(&script, whole.end()) {
                return whole.as_str().to_string();
            }
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let spaces = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let name = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if matches!(
                name,
                "if" | "for" | "while" | "switch" | "return" | "let" | "const" | "var"
            ) {
                return caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
            }
            let declared = declared_names.contains(name);
            let assignment_start = whole.start() + prefix.len() + spaces.len();
            if declared && is_global_js_position(&script, assignment_start) {
                format!("{prefix}{spaces}{name} = globalThis.{name} =")
            } else if declared {
                whole.as_str().to_string()
            } else {
                format!("{prefix}{spaces}{name} = globalThis.{name} =")
            }
        })
        .into_owned();
    script = for_re
        .replace_all(&script, |caps: &regex::Captures<'_>| {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let keyword = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let declared = declared_names.contains(name);
            if declared {
                caps.get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                format!("for ({name} {keyword}")
            }
        })
        .into_owned();
    if !implicit_globals.is_empty() {
        let prefix = implicit_globals
            .iter()
            .map(|name| format!("globalThis.{name} = globalThis.{name};"))
            .collect::<Vec<_>>()
            .join("\n");
        script = format!("{prefix}\n{script}");
    }
    script = export_top_level_function_declarations(&script);
    script = rewrite_terminal_if_completion(&script);
    imported_var_assignment_re()
        .replace_all(&script, |caps: &regex::Captures<'_>| {
            let Some(whole) = caps.get(0) else {
                return String::new();
            };
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let spaces = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let name = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            let var_start = whole.start() + prefix.len() + spaces.len();
            if !is_global_js_position(&script, var_start) {
                return whole.as_str().to_string();
            }
            format!("{prefix}{spaces}globalThis.{name} =")
        })
        .into_owned()
}

fn assignment_match_is_arrow(script: &str, match_end: usize) -> bool {
    script[match_end..].trim_start().starts_with('>')
}

fn replace_this_outside_literals(script: &str) -> String {
    this_re()
        .replace_all(script, |caps: &regex::Captures<'_>| {
            let Some(whole) = caps.get(0) else {
                return String::new();
            };
            if is_in_js_literal(script, whole.start()) {
                whole.as_str().to_string()
            } else {
                "globalThis".to_string()
            }
        })
        .into_owned()
}

fn is_in_js_literal(script: &str, pos: usize) -> bool {
    #[derive(Clone, Copy)]
    enum Mode {
        Normal,
        SingleQuote,
        DoubleQuote,
        Template,
        TemplateExpr(usize),
    }

    let bytes = script.as_bytes();
    let mut stack = vec![Mode::Normal];
    let mut index = 0usize;
    while index < pos && index < bytes.len() {
        let byte = bytes[index];
        match *stack.last().unwrap_or(&Mode::Normal) {
            Mode::SingleQuote => {
                if byte == b'\\' {
                    index += 2;
                } else {
                    if byte == b'\'' {
                        stack.pop();
                    }
                    index += 1;
                }
            }
            Mode::DoubleQuote => {
                if byte == b'\\' {
                    index += 2;
                } else {
                    if byte == b'"' {
                        stack.pop();
                    }
                    index += 1;
                }
            }
            Mode::Template => {
                if byte == b'\\' {
                    index += 2;
                } else if byte == b'`' {
                    stack.pop();
                    index += 1;
                } else if byte == b'$' && bytes.get(index + 1) == Some(&b'{') {
                    stack.push(Mode::TemplateExpr(1));
                    index += 2;
                } else {
                    index += 1;
                }
            }
            Mode::TemplateExpr(depth) => match byte {
                b'\'' => {
                    stack.push(Mode::SingleQuote);
                    index += 1;
                }
                b'"' => {
                    stack.push(Mode::DoubleQuote);
                    index += 1;
                }
                b'`' => {
                    stack.push(Mode::Template);
                    index += 1;
                }
                b'{' => {
                    if let Some(slot) = stack.last_mut() {
                        *slot = Mode::TemplateExpr(depth + 1);
                    }
                    index += 1;
                }
                b'}' => {
                    if depth <= 1 {
                        stack.pop();
                    } else if let Some(slot) = stack.last_mut() {
                        *slot = Mode::TemplateExpr(depth - 1);
                    }
                    index += 1;
                }
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    index += 2;
                    while index < pos && index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < pos && index + 1 < bytes.len() {
                        if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                            index += 2;
                            break;
                        }
                        index += 1;
                    }
                }
                _ => index += 1,
            },
            Mode::Normal => match byte {
                b'\'' => {
                    stack.push(Mode::SingleQuote);
                    index += 1;
                }
                b'"' => {
                    stack.push(Mode::DoubleQuote);
                    index += 1;
                }
                b'`' => {
                    stack.push(Mode::Template);
                    index += 1;
                }
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    index += 2;
                    while index < pos && index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    index += 2;
                    while index + 1 < pos && index + 1 < bytes.len() {
                        if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                            index += 2;
                            break;
                        }
                        index += 1;
                    }
                }
                _ => index += 1,
            },
        }
    }
    matches!(
        stack.last(),
        Some(Mode::SingleQuote | Mode::DoubleQuote | Mode::Template)
    )
}

fn rewrite_top_level_var_declarations(script: &str) -> String {
    top_level_var_decl_re()
        .replace_all(script, |caps: &regex::Captures<'_>| {
            let Some(whole) = caps.get(0) else {
                return String::new();
            };
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let spaces = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let names = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            let var_start = whole.start() + prefix.len() + spaces.len();
            if !is_global_js_position(script, var_start) {
                return whole.as_str().to_string();
            }
            let exports = names
                .split(',')
                .filter_map(|name| {
                    let name = name.trim();
                    js_var_name_re()
                        .is_match(name)
                        .then(|| format!("globalThis.{name} = globalThis.{name};"))
                })
                .collect::<Vec<_>>();
            if exports.is_empty() {
                whole.as_str().to_string()
            } else {
                format!("{prefix}{spaces}{}", exports.join(" "))
            }
        })
        .into_owned()
}

fn rewrite_terminal_if_completion(script: &str) -> String {
    let trimmed_end = script.trim_end();
    if !trimmed_end.ends_with('}') {
        return script.to_string();
    }
    let close = trimmed_end.len() - 1;
    let mut candidate = None;
    for mat in terminal_if_re().find_iter(trimmed_end) {
        let Some(open_relative) = trimmed_end[mat.end()..].find('{') else {
            continue;
        };
        let open = mat.end() + open_relative;
        if find_matching_brace(trimmed_end, open) == Some(close) {
            candidate = Some((mat.start(), open));
        }
    }
    let Some((if_start, open)) = candidate else {
        return script.to_string();
    };
    let body = &trimmed_end[open + 1..close];
    let Some(last_start_relative) = last_top_level_statement_start(body) else {
        return script.to_string();
    };
    let last_start = open + 1 + last_start_relative;
    let last_expr = trimmed_end[last_start..close].trim();
    if last_expr.is_empty()
        || last_expr.starts_with("return ")
        || last_expr.starts_with("throw ")
        || last_expr.starts_with("var ")
        || last_expr.starts_with("function ")
    {
        return script.to_string();
    }
    let suffix = &script[trimmed_end.len()..];
    format!(
        "{}globalThis.__legadoEvalCompletion = undefined; {}{}globalThis.__legadoEvalCompletion = ({});{}; globalThis.__legadoEvalCompletion{}",
        &trimmed_end[..if_start],
        &trimmed_end[if_start..last_start],
        if trimmed_end[..last_start].ends_with(';') { "" } else { "" },
        last_expr,
        &trimmed_end[close..=close],
        suffix
    )
}

fn last_top_level_statement_start(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut last = 0usize;
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
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth = depth.saturating_sub(1),
            b';' if depth == 0 => last = index + 1,
            _ => {}
        }
        index += 1;
    }
    Some(last).filter(|start| body[*start..].trim().len() > 0)
}

fn export_top_level_function_declarations(script: &str) -> String {
    let mut out = String::new();
    let mut index = 0usize;
    while let Some(caps) = top_level_function_re().captures(&script[index..]) {
        let whole = caps.get(0).expect("whole function prefix");
        let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let spaces = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let name = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
        let match_start = index + whole.start();
        let function_start = match_start + prefix.len() + spaces.len();
        if !is_top_level_js_position(script, function_start) {
            out.push_str(&script[index..index + whole.end()]);
            index += whole.end();
            continue;
        }
        let Some(open_relative) = script[function_start..].find('{') else {
            break;
        };
        let open = function_start + open_relative;
        let Some(close) = find_matching_brace(script, open) else {
            break;
        };
        out.push_str(&script[index..match_start]);
        out.push_str(&script[match_start..=close]);
        out.push('\n');
        out.push_str(spaces);
        out.push_str("globalThis.");
        out.push_str(name);
        out.push_str(" = ");
        out.push_str(name);
        out.push(';');
        index = close + 1;
    }
    out.push_str(&script[index..]);
    out
}

fn is_top_level_js_position(script: &str, position: usize) -> bool {
    let bytes = script.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut index = 0usize;
    while index < position && index < bytes.len() {
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
        if byte == b'/' && index + 1 < position {
            match bytes[index + 1] {
                b'/' => {
                    index += 2;
                    while index < position && index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                    continue;
                }
                b'*' => {
                    index += 2;
                    while index + 1 < position
                        && index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index = (index + 2).min(bytes.len());
                    continue;
                }
                _ => {}
            }
        }
        match byte {
            b'\'' | b'"' | b'`' => quote = Some(byte),
            b'{' => depth += 1,
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        index += 1;
    }
    depth == 0 && quote.is_none()
}

fn is_global_js_position(script: &str, position: usize) -> bool {
    if !is_js_position_outside_string_or_comment(script, position) {
        return false;
    }
    for caps in function_body_re().captures_iter(&script[..position.min(script.len())]) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        let Some(open_relative) = script[whole.start()..].find('{') else {
            continue;
        };
        let open = whole.start() + open_relative;
        if open >= position {
            continue;
        }
        let Some(close) = find_matching_brace(script, open) else {
            continue;
        };
        if position < close {
            return false;
        }
    }
    true
}

fn is_js_position_outside_string_or_comment(script: &str, position: usize) -> bool {
    let bytes = script.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = 0usize;
    while index < position && index < bytes.len() {
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
        if byte == b'/' && index + 1 < position {
            match bytes[index + 1] {
                b'/' => {
                    index += 2;
                    while index < position && index < bytes.len() && bytes[index] != b'\n' {
                        index += 1;
                    }
                    continue;
                }
                b'*' => {
                    index += 2;
                    while index + 1 < position
                        && index + 1 < bytes.len()
                        && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                    {
                        index += 1;
                    }
                    index = (index + 2).min(bytes.len());
                    continue;
                }
                _ => {}
            }
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        }
        index += 1;
    }
    quote.is_none()
}

fn remove_with_blocks(script: &str) -> String {
    let mut out = String::new();
    let mut index = 0;
    while let Some(relative_start) = script[index..].find("with") {
        let start = index + relative_start;
        out.push_str(&script[index..start]);
        let Some(open_relative) = script[start..].find('{') else {
            out.push_str(&script[start..]);
            return out;
        };
        let open = start + open_relative;
        if !script[start + 4..open].trim_start().starts_with('(') {
            out.push_str(&script[start..=open]);
            index = open + 1;
            continue;
        }
        let Some(close) = find_matching_brace(script, open) else {
            out.push_str(&script[start..]);
            return out;
        };
        out.push_str(&script[open + 1..close]);
        index = close + 1;
    }
    out.push_str(&script[index..]);
    out
}

fn find_matching_brace(script: &str, open: usize) -> Option<usize> {
    find_matching_delimiter(script, open, b'{', b'}')
}

fn find_matching_delimiter(
    script: &str,
    open: usize,
    open_byte: u8,
    close_byte: u8,
) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let bytes = script.as_bytes();
    let mut index = open;
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
            b'\'' | b'"' | b'`' => quote = Some(byte),
            current if current == open_byte => depth += 1,
            current if current == close_byte => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn normalize_crypto_algorithm(algorithm: &str) -> String {
    algorithm
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn digest_bytes(data: &str, algorithm: &str) -> Option<Vec<u8>> {
    match normalize_crypto_algorithm(algorithm).as_str() {
        "MD5" => Some(md5::compute(data).0.to_vec()),
        "SHA1" => Some(Sha1::digest(data.as_bytes()).to_vec()),
        "SHA224" => None,
        "SHA256" => Some(Sha256::digest(data.as_bytes()).to_vec()),
        "SHA384" => Some(Sha384::digest(data.as_bytes()).to_vec()),
        "SHA512" => Some(Sha512::digest(data.as_bytes()).to_vec()),
        _ => None,
    }
}

fn hmac_bytes(data: &str, algorithm: &str, key: &str) -> Option<Vec<u8>> {
    match normalize_crypto_algorithm(algorithm)
        .trim_start_matches("HMAC")
        .trim_start_matches("H")
    {
        "SHA1" => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key.as_bytes()).ok()?;
            mac.update(data.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        "SHA256" => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).ok()?;
            mac.update(data.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        "SHA384" => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key.as_bytes()).ok()?;
            mac.update(data.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        "SHA512" => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key.as_bytes()).ok()?;
            mac.update(data.as_bytes());
            Some(mac.finalize().into_bytes().to_vec())
        }
        _ => None,
    }
}

fn crypto_result_marker(result: std::result::Result<String, String>) -> String {
    match result {
        Ok(value) => value,
        Err(err) => format!("__LEGADO_CRYPTO_ERROR__:{err}"),
    }
}

fn normalize_asymmetric_algorithm(algorithm: &str) -> String {
    algorithm
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn asymmetric_plaintext_bytes(data: &str) -> Vec<u8> {
    data.as_bytes().to_vec()
}

fn asymmetric_ciphertext_bytes(data: &str) -> std::result::Result<Vec<u8>, String> {
    let trimmed = data.trim();
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        return Ok(bytes);
    }
    if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(trimmed) {
            return Ok(bytes);
        }
    }
    Ok(data.as_bytes().to_vec())
}

fn key_input_candidates(key: &str) -> Vec<Vec<u8>> {
    let trimmed = key.trim();
    let mut candidates = Vec::new();
    if !trimmed.is_empty() {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
            candidates.push(bytes);
        }
        if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            if let Ok(bytes) = hex::decode(trimmed) {
                candidates.push(bytes);
            }
        }
    }
    candidates.push(key.as_bytes().to_vec());
    candidates
}

fn parse_rsa_private_key(key: &str) -> std::result::Result<RsaPrivateKey, String> {
    let trimmed = key.trim();
    if trimmed.contains("-----BEGIN") {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
            return Ok(key);
        }
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(trimmed) {
            return Ok(key);
        }
    }
    for candidate in key_input_candidates(key) {
        if let Ok(key) = RsaPrivateKey::from_pkcs8_der(&candidate) {
            return Ok(key);
        }
        if let Ok(key) = RsaPrivateKey::from_pkcs1_der(&candidate) {
            return Ok(key);
        }
    }
    Err("invalid RSA private key; expected PEM, Base64 DER, hex DER, or DER bytes".to_string())
}

fn parse_rsa_public_key(key: &str) -> std::result::Result<RsaPublicKey, String> {
    let trimmed = key.trim();
    if trimmed.contains("-----BEGIN") {
        if let Ok(key) = RsaPublicKey::from_public_key_pem(trimmed) {
            return Ok(key);
        }
        if let Ok(key) = RsaPublicKey::from_pkcs1_pem(trimmed) {
            return Ok(key);
        }
    }
    for candidate in key_input_candidates(key) {
        if let Ok(key) = RsaPublicKey::from_public_key_der(&candidate) {
            return Ok(key);
        }
        if let Ok(key) = RsaPublicKey::from_pkcs1_der(&candidate) {
            return Ok(key);
        }
    }
    Err("invalid RSA public key; expected PEM, Base64 DER, hex DER, or DER bytes".to_string())
}

fn ensure_rsa_pkcs1_algorithm(algorithm: &str) -> std::result::Result<(), String> {
    let normalized = normalize_asymmetric_algorithm(algorithm);
    if normalized == "RSA"
        || normalized == "RSAECBPKCS1PADDING"
        || normalized == "RSANONEPKCS1PADDING"
    {
        Ok(())
    } else {
        Err(format!(
            "unsupported asymmetric algorithm `{algorithm}`; Rust analyzer currently supports RSA/ECB/PKCS1Padding"
        ))
    }
}

fn asymmetric_encrypt_bytes(
    algorithm: &str,
    public_key: &str,
    private_key: &str,
    data: &str,
    use_public_key: bool,
) -> std::result::Result<Vec<u8>, String> {
    ensure_rsa_pkcs1_algorithm(algorithm)?;
    if !use_public_key {
        return Err(
            "RSA private-key encryption is not supported by the Rust analyzer host API yet"
                .to_string(),
        );
    }
    let key = parse_rsa_public_key(public_key).or_else(|_| {
        parse_rsa_private_key(private_key).map(|private| RsaPublicKey::from(&private))
    })?;
    let mut rng = rsa::rand_core::OsRng;
    key.encrypt(&mut rng, Pkcs1v15Encrypt, &asymmetric_plaintext_bytes(data))
        .map_err(|err| err.to_string())
}

fn asymmetric_encrypt_base64(
    algorithm: &str,
    public_key: &str,
    private_key: &str,
    data: &str,
    use_public_key: bool,
) -> std::result::Result<String, String> {
    asymmetric_encrypt_bytes(algorithm, public_key, private_key, data, use_public_key)
        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn asymmetric_decrypt_bytes(
    algorithm: &str,
    _public_key: &str,
    private_key: &str,
    data: &str,
    use_public_key: bool,
) -> std::result::Result<Vec<u8>, String> {
    ensure_rsa_pkcs1_algorithm(algorithm)?;
    if use_public_key {
        return Err(
            "RSA public-key decryption is not supported by the Rust analyzer host API yet"
                .to_string(),
        );
    }
    let key = parse_rsa_private_key(private_key)?;
    key.decrypt(Pkcs1v15Encrypt, &asymmetric_ciphertext_bytes(data)?)
        .map_err(|err| err.to_string())
}

fn sign_bytes(
    algorithm: &str,
    private_key: &str,
    data: &str,
) -> std::result::Result<Vec<u8>, String> {
    let key = parse_rsa_private_key(private_key)?;
    match normalize_asymmetric_algorithm(algorithm).as_str() {
        "SHA256WITHRSA" | "SHA256RSA" => {
            Ok(SigningKey::<Sha256>::new(key).sign(data.as_bytes()).to_vec())
        }
        "SHA384WITHRSA" | "SHA384RSA" => {
            Ok(SigningKey::<Sha384>::new(key).sign(data.as_bytes()).to_vec())
        }
        "SHA512WITHRSA" | "SHA512RSA" => {
            Ok(SigningKey::<Sha512>::new(key).sign(data.as_bytes()).to_vec())
        }
        _ => Err(format!(
            "unsupported signature algorithm `{algorithm}`; Rust analyzer currently supports SHA256withRSA, SHA384withRSA, and SHA512withRSA"
        )),
    }
}

fn aes_base64_decode_to_string(
    data: &str,
    key: &str,
    algorithm: &str,
    iv: &str,
) -> std::result::Result<String, String> {
    let normalized = algorithm.to_ascii_uppercase();
    if !normalized.contains("AES") {
        return Err(format!("unsupported AES algorithm {algorithm}"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|err| err.to_string())?;
    let bytes = if normalized.contains("CBC") {
        let iv = if iv.is_empty() { key } else { iv };
        Aes128CbcDec::new_from_slices(key.as_bytes(), iv.as_bytes())
            .map_err(|err| err.to_string())?
            .decrypt_padded_vec_mut::<Pkcs7>(&bytes)
            .map_err(|err| err.to_string())?
    } else if normalized.contains("ECB") {
        aes_ecb_pkcs7_decrypt(&bytes, key.as_bytes())?
    } else {
        return Err(format!("unsupported AES algorithm {algorithm}"));
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn aes_encode_to_base64_string(
    data: &str,
    key: &str,
    algorithm: &str,
    iv: &str,
) -> std::result::Result<String, String> {
    let normalized = algorithm.to_ascii_uppercase();
    if !normalized.contains("AES") {
        return Err(format!("unsupported AES algorithm {algorithm}"));
    }
    let bytes = if normalized.contains("CBC") {
        let iv = if iv.is_empty() { key } else { iv };
        Aes128CbcEnc::new_from_slices(key.as_bytes(), iv.as_bytes())
            .map_err(|err| err.to_string())?
            .encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes())
    } else if normalized.contains("ECB") {
        aes_ecb_pkcs7_encrypt(data.as_bytes(), key.as_bytes())?
    } else {
        return Err(format!("unsupported AES algorithm {algorithm}"));
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn crypto_arg_bytes(value: &str, is_hex: bool) -> std::result::Result<Vec<u8>, String> {
    if is_hex {
        hex::decode(value).map_err(|err| err.to_string())
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

fn symmetric_ciphertext_bytes(data: &str, is_hex: bool) -> std::result::Result<Vec<u8>, String> {
    if is_hex {
        return hex::decode(data).map_err(|err| err.to_string());
    }
    let trimmed = data.trim();
    if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(trimmed) {
            return Ok(bytes);
        }
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|err| err.to_string())
}

fn symmetric_encrypt_bytes(
    algorithm: &str,
    key: &str,
    key_is_hex: bool,
    iv: &str,
    iv_is_hex: bool,
    data: &str,
    data_is_hex: bool,
) -> std::result::Result<Vec<u8>, String> {
    let key = crypto_arg_bytes(key, key_is_hex)?;
    let iv = if iv.is_empty() {
        key.clone()
    } else {
        crypto_arg_bytes(iv, iv_is_hex)?
    };
    let data = crypto_arg_bytes(data, data_is_hex)?;
    symmetric_crypt_bytes(algorithm, &key, &iv, &data, true)
}

fn symmetric_decrypt_bytes(
    algorithm: &str,
    key: &str,
    key_is_hex: bool,
    iv: &str,
    iv_is_hex: bool,
    data: &str,
    data_is_hex: bool,
) -> std::result::Result<Vec<u8>, String> {
    let key = crypto_arg_bytes(key, key_is_hex)?;
    let iv = if iv.is_empty() {
        key.clone()
    } else {
        crypto_arg_bytes(iv, iv_is_hex)?
    };
    let data = symmetric_ciphertext_bytes(data, data_is_hex)?;
    symmetric_crypt_bytes(algorithm, &key, &iv, &data, false)
}

fn symmetric_crypt_bytes(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> std::result::Result<Vec<u8>, String> {
    let normalized = algorithm.to_ascii_uppercase();
    let cbc = normalized.contains("CBC");
    let ecb = normalized.contains("ECB") || !cbc;
    if !normalized.contains("PKCS5") && !normalized.contains("PKCS7") {
        return Err(format!(
            "unsupported symmetric padding `{algorithm}`; Rust analyzer currently supports PKCS5/PKCS7 padding"
        ));
    }
    if normalized.contains("DESEDE")
        || normalized.contains("TRIPLEDES")
        || normalized.contains("3DES")
    {
        if encrypt {
            if cbc {
                TdesEde3CbcEnc::new_from_slices(key, iv)
                    .map_err(|err| err.to_string())
                    .map(|cipher| cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
            } else if ecb {
                tdes_ecb_pkcs7_encrypt(data, key)
            } else {
                Err(format!("unsupported 3DES mode `{algorithm}`"))
            }
        } else if cbc {
            TdesEde3CbcDec::new_from_slices(key, iv)
                .map_err(|err| err.to_string())?
                .decrypt_padded_vec_mut::<Pkcs7>(data)
                .map_err(|err| err.to_string())
        } else if ecb {
            tdes_ecb_pkcs7_decrypt(data, key)
        } else {
            Err(format!("unsupported 3DES mode `{algorithm}`"))
        }
    } else if normalized.contains("DES") {
        if encrypt {
            if cbc {
                DesCbcEnc::new_from_slices(key, iv)
                    .map_err(|err| err.to_string())
                    .map(|cipher| cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
            } else if ecb {
                des_ecb_pkcs7_encrypt(data, key)
            } else {
                Err(format!("unsupported DES mode `{algorithm}`"))
            }
        } else if cbc {
            DesCbcDec::new_from_slices(key, iv)
                .map_err(|err| err.to_string())?
                .decrypt_padded_vec_mut::<Pkcs7>(data)
                .map_err(|err| err.to_string())
        } else if ecb {
            des_ecb_pkcs7_decrypt(data, key)
        } else {
            Err(format!("unsupported DES mode `{algorithm}`"))
        }
    } else if normalized.contains("AES") {
        if encrypt {
            if cbc {
                Aes128CbcEnc::new_from_slices(key, iv)
                    .map_err(|err| err.to_string())
                    .map(|cipher| cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
            } else if ecb {
                aes_ecb_pkcs7_encrypt(data, key)
            } else {
                Err(format!("unsupported AES mode `{algorithm}`"))
            }
        } else if cbc {
            Aes128CbcDec::new_from_slices(key, iv)
                .map_err(|err| err.to_string())?
                .decrypt_padded_vec_mut::<Pkcs7>(data)
                .map_err(|err| err.to_string())
        } else if ecb {
            aes_ecb_pkcs7_decrypt(data, key)
        } else {
            Err(format!("unsupported AES mode `{algorithm}`"))
        }
    } else {
        Err(format!("unsupported symmetric algorithm `{algorithm}`"))
    }
}

fn response_json(out: crate::request::RequestOutput) -> serde_json::Value {
    response_json_with_call_time(out, 0)
}

fn response_json_with_call_time(
    out: crate::request::RequestOutput,
    call_time: i32,
) -> serde_json::Value {
    let headers_list = out
        .headers
        .iter()
        .map(|(key, value)| {
            serde_json::Value::Array(vec![
                serde_json::Value::String(key.clone()),
                serde_json::Value::String(value.clone()),
            ])
        })
        .collect::<Vec<_>>();
    let headers = out
        .headers
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "url": out.url,
        "body": out.body,
        "code": out.status.unwrap_or(200),
        "message": "OK",
        "headers": headers,
        "headersList": headers_list,
        "contentType": out.content_type,
        "raw": "",
        "callTime": call_time
    })
}

fn request_error_json(url: &str, message: String) -> serde_json::Value {
    request_error_json_with_call_time(url, message, 0)
}

fn request_error_json_with_call_time(
    url: &str,
    message: String,
    call_time: i32,
) -> serde_json::Value {
    serde_json::json!({
        "url": url,
        "body": message,
        "code": 500,
        "message": message,
        "headers": {},
        "headersList": [],
        "contentType": null,
        "raw": "",
        "callTime": call_time
    })
}

fn elapsed_millis_i32(start: Instant) -> i32 {
    start.elapsed().as_millis().min(i32::MAX as u128) as i32
}

fn ajax_test_error_call_time(message: &str) -> i32 {
    let message = message.to_ascii_lowercase();
    if message.contains("timed out")
        || message.contains("timeout")
        || message.contains("deadline has elapsed")
    {
        -1
    } else if message.contains("dns")
        || message.contains("resolve")
        || message.contains("unknown host")
        || message.contains("failed to lookup address")
    {
        -3
    } else if message.contains("connection refused")
        || message.contains("connect")
        || message.contains("error sending request")
    {
        -4
    } else if message.contains("connection reset")
        || message.contains("connection closed")
        || message.contains("broken pipe")
    {
        -5
    } else if message.contains("ssl")
        || message.contains("tls")
        || message.contains("certificate")
        || message.contains("handshake")
    {
        -6
    } else {
        -7
    }
}

fn js_timeout_arg(value: Option<&str>) -> Option<u64> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    let Ok(timeout) = value.parse::<f64>() else {
        return None;
    };
    if !timeout.is_finite() || timeout < 0.0 {
        None
    } else {
        Some(timeout as u64)
    }
}

fn js_bool_arg(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("true" | "1" | "yes" | "on" | "TRUE" | "True")
    )
}

fn header_map_json(header: &str) -> String {
    let map = parse_header_map(header)
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

fn source_header_map_json(
    source_header: &str,
    login_header: &str,
    has_login_header: bool,
) -> String {
    let mut map = parse_header_map(source_header)
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    if !map.keys().any(|key| key.eq_ignore_ascii_case("User-Agent")) {
        map.insert("User-Agent".to_string(), DEFAULT_USER_AGENT.to_string());
    }
    if has_login_header {
        for (key, value) in parse_header_map(login_header) {
            map.insert(key, value);
        }
    }
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}

fn login_header_cookie(header: &str) -> Option<String> {
    parse_header_map(header)
        .into_iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("cookie"))
        .map(|(_, value)| value)
}

fn user_agent_for_rule_url(rule_url: &str, source_header: &str, login_header: &str) -> String {
    let mut user_agent =
        header_value_case_insensitive(&parse_header_map(source_header), "User-Agent")
            .unwrap_or_else(|| DEFAULT_USER_AGENT.to_string());
    if let Some(value) =
        header_value_case_insensitive(&parse_header_map(login_header), "User-Agent")
    {
        user_agent = value;
    }
    if let Ok(request) = parse_legado_request(rule_url) {
        if let Some(value) = header_value_case_insensitive(&request.headers, "User-Agent") {
            user_agent = value;
        }
    }
    user_agent
}

fn header_value_case_insensitive(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

trait NonEmptyStringExt {
    fn or_else_nonempty<F: FnOnce() -> Option<String>>(self, f: F) -> Option<String>;
}

impl NonEmptyStringExt for String {
    fn or_else_nonempty<F: FnOnce() -> Option<String>>(self, f: F) -> Option<String> {
        if self.is_empty() {
            f()
        } else {
            Some(self)
        }
    }
}

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type DesCbcDec = cbc::Decryptor<Des>;
type DesCbcEnc = cbc::Encryptor<Des>;
type TdesEde3CbcDec = cbc::Decryptor<TdesEde3>;
type TdesEde3CbcEnc = cbc::Encryptor<TdesEde3>;

fn aes_ecb_pkcs7_decrypt(data: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = data.to_vec();
    if bytes.is_empty() || bytes.len() % 16 != 0 {
        return Err("invalid AES ECB payload length".to_string());
    }
    let cipher = Aes128::new_from_slice(key).map_err(|err| err.to_string())?;
    for chunk in bytes.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    let pad = *bytes
        .last()
        .ok_or_else(|| "empty AES payload".to_string())? as usize;
    if pad == 0 || pad > 16 || pad > bytes.len() {
        return Err("invalid PKCS7 padding".to_string());
    }
    bytes.truncate(bytes.len() - pad);
    Ok(bytes)
}

fn aes_ecb_pkcs7_encrypt(data: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = data.to_vec();
    let pad = 16 - (bytes.len() % 16);
    bytes.extend(std::iter::repeat(pad as u8).take(pad));
    let cipher = Aes128::new_from_slice(key).map_err(|err| err.to_string())?;
    for chunk in bytes.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(bytes)
}

fn des_ecb_pkcs7_decrypt(data: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = data.to_vec();
    if bytes.is_empty() || bytes.len() % 8 != 0 {
        return Err("invalid DES ECB payload length".to_string());
    }
    let cipher = Des::new_from_slice(key).map_err(|err| err.to_string())?;
    for chunk in bytes.chunks_exact_mut(8) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    strip_pkcs7_padding(bytes, 8)
}

fn des_ecb_pkcs7_encrypt(data: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = pkcs7_pad(data, 8);
    let cipher = Des::new_from_slice(key).map_err(|err| err.to_string())?;
    for chunk in bytes.chunks_exact_mut(8) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(bytes)
}

fn tdes_ecb_pkcs7_decrypt(data: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = data.to_vec();
    if bytes.is_empty() || bytes.len() % 8 != 0 {
        return Err("invalid 3DES ECB payload length".to_string());
    }
    let cipher = TdesEde3::new_from_slice(key).map_err(|err| err.to_string())?;
    for chunk in bytes.chunks_exact_mut(8) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    strip_pkcs7_padding(bytes, 8)
}

fn tdes_ecb_pkcs7_encrypt(data: &[u8], key: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = pkcs7_pad(data, 8);
    let cipher = TdesEde3::new_from_slice(key).map_err(|err| err.to_string())?;
    for chunk in bytes.chunks_exact_mut(8) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(bytes)
}

fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut bytes = data.to_vec();
    let pad = block_size - (bytes.len() % block_size);
    bytes.extend(std::iter::repeat(pad as u8).take(pad));
    bytes
}

fn strip_pkcs7_padding(
    mut bytes: Vec<u8>,
    block_size: usize,
) -> std::result::Result<Vec<u8>, String> {
    let pad = *bytes
        .last()
        .ok_or_else(|| "empty PKCS7 payload".to_string())? as usize;
    if pad == 0 || pad > block_size || pad > bytes.len() {
        return Err("invalid PKCS7 padding".to_string());
    }
    bytes.truncate(bytes.len() - pad);
    Ok(bytes)
}

fn aes_cbc_pkcs5_decrypt_hex(
    data_hex: &str,
    key_hex: &str,
    iv_hex: &str,
) -> std::result::Result<String, String> {
    let data = hex::decode(data_hex).map_err(|err| err.to_string())?;
    let key = hex::decode(key_hex).map_err(|err| err.to_string())?;
    let iv = hex::decode(iv_hex).map_err(|err| err.to_string())?;
    let decrypted = Aes128CbcDec::new_from_slices(&key, &iv)
        .map_err(|err| err.to_string())?
        .decrypt_padded_vec_mut::<Pkcs7>(&data)
        .map_err(|err| err.to_string())?;
    Ok(String::from_utf8_lossy(&decrypted).into_owned())
}

const RHINO_COMPAT_PRELUDE: &str = r#"
function JavaImporter() {
  var imports = (this && this !== globalThis) ? this : {};
  imports.importPackage = function() {};
  function addImport(value) {
    if (!value || typeof value !== "object" && typeof value !== "function") return;
    var importName = value.__legadoJavaImportName;
    if (importName) {
      importName = String(importName);
      imports[importName] = value;
      globalThis[importName] = value;
      return;
    }
    Object.keys(value).forEach(function(key) {
      if (key.indexOf("__legado") === 0) return;
      imports[key] = value[key];
      globalThis[key] = value[key];
    });
  }
  for (var i = 0; i < arguments.length; i++) addImport(arguments[i]);
  return imports;
}
var Packages = globalThis.Packages || {
  java: { lang: {}, util: {} },
  javax: { crypto: { spec: {} } }
};
globalThis.Packages = Packages;
function __legadoMarkJavaImport(value, name) {
  if (value && (typeof value === "object" || typeof value === "function")) {
    try {
      Object.defineProperty(value, "__legadoJavaImportName", {
        value: String(name || ""),
        configurable: true,
        enumerable: false
      });
    } catch (e) {}
  }
  return value;
}
function __legadoClassObject(name) {
  name = String(name || "Object");
  var simple = name.split(".").pop();
  return {
    getName: function() { return name; },
    getSimpleName: function() { return simple; },
    toString: function() { return "class " + name; }
  };
}
if (typeof globalThis.getClass !== "function") {
  globalThis.getClass = function(value) {
    if (value && value.__legadoUnsupportedPackage) {
      throw new Error("__LEGADO_UNSUPPORTED_HOST_API__:Unsupported Android/JVM package API: " + String(value));
    }
    if (value && value.__legadoJavaImportName) {
      return __legadoClassObject(value.__legadoJavaImportName);
    }
    if (value === null || typeof value === "undefined") return __legadoClassObject("null");
    if (value && value.constructor && value.constructor.name) {
      return __legadoClassObject(value.constructor.name);
    }
    return __legadoClassObject(typeof value);
  };
}
if (typeof source !== "undefined" && source.__getLoginInfoMapJson) {
  source.getLoginInfoMap = function() {
    var object;
    try {
      object = JSON.parse(source.__getLoginInfoMapJson() || "{}");
    } catch (e) {
      object = {};
    }
    if (object && typeof object.get !== "function") {
      object.get = function(key) { return this[String(key)] || ""; };
    }
    return object;
  };
  source.getLoginHeaderMap = function() {
    try {
      return JSON.parse(source.__getLoginHeaderMapJson ? (source.__getLoginHeaderMapJson() || "{}") : "{}");
    } catch (e) {
      return {};
    }
  };
  source.getHeaderMap = function(hasLoginHeader) {
    var object;
    try {
      object = JSON.parse(source.__getHeaderMapJson ? (source.__getHeaderMapJson(hasLoginHeader === true || hasLoginHeader === "true") || "{}") : "{}");
    } catch (e) {
      object = {};
    }
    if (object && typeof object.get !== "function") {
      object.get = function(key) { return this[String(key)] || ""; };
    }
    return object;
  };
  if (source.putLoginInfo) {
    source.__putLoginInfo = source.putLoginInfo;
    source.putLoginInfo = function(value, maybeValue) {
      if (arguments.length === 1 && value && typeof value === "object") {
        return source.__putLoginInfo(JSON.stringify(value));
      }
      return source.__putLoginInfo.apply(source, arguments);
    };
  }
  if (typeof source.loginUi === "function") {
    var __legadoLoginUiRaw = source.loginUi;
    var __legadoLoginUiText = String(source.__loginUiText || "");
    var __legadoLoginUi = function() {
      return __legadoLoginUiRaw.apply(source, arguments);
    };
    __legadoLoginUi.toString = function() { return __legadoLoginUiText; };
    __legadoLoginUi.valueOf = function() { return __legadoLoginUiText; };
    __legadoLoginUi.toJSON = function() { return __legadoLoginUiText; };
    [
      "charAt", "charCodeAt", "concat", "endsWith", "includes", "indexOf",
      "lastIndexOf", "match", "replace", "search", "slice", "split",
      "startsWith", "substring", "toLowerCase", "toUpperCase", "trim"
    ].forEach(function(name) {
      __legadoLoginUi[name] = function() {
        return String.prototype[name].apply(__legadoLoginUiText, arguments);
      };
    });
    source.loginUi = __legadoLoginUi;
  }
  source.login = function() {
    var loginJs = String(source.loginUrl || "");
    if (loginJs.indexOf("@js:") === 0) {
      loginJs = loginJs.substring(4);
    } else if (loginJs.indexOf("<js>") === 0) {
      var end = loginJs.lastIndexOf("<");
      loginJs = end > 4 ? loginJs.substring(4, end) : loginJs.substring(4);
    }
    if (!loginJs.trim()) return undefined;
    (0, eval)(loginJs);
    if (typeof login === "function") {
      return login.apply(this, arguments);
    }
    throw "Function login not implements!!!";
  };
  source.refreshExplore = function() {
    if (typeof java !== "undefined" && typeof java.__platformResponse === "function") {
      var response = java.__platformResponse("refreshExplore", arguments);
      return response.marker || "";
    }
    throw new Error("__LEGADO_UNSUPPORTED_PLATFORM_API__:source.refreshExplore");
  };
}
if (typeof java !== "undefined" && java.__platformAction) {
  java.__platformResponse = function(api, args) {
    var argsJson = JSON.stringify(Array.prototype.slice.call(args || []));
    var raw = java.__platformAction(String(api), argsJson);
    var response;
    try {
      response = JSON.parse(raw || "{}");
    } catch (e) {
      throw new Error("__LEGADO_PLATFORM_RESPONSE_ERROR__:" + api + ": invalid response JSON: " + e + ": " + String(raw || "").slice(0, 160));
    }
    if (response && response.unsupported) {
      throw new Error(response.marker || ("Unsupported platform API: " + api));
    }
    if (response && response.cookies && typeof cookie !== "undefined" && typeof cookie.setCookie === "function") {
      try {
        for (var host in response.cookies) {
          if (Object.prototype.hasOwnProperty.call(response.cookies, host)) {
            cookie.setCookie(host, String(response.cookies[host] || ""));
          }
        }
      } catch (e) {}
    }
    return response || {};
  };
  java.__strResponse = function(response) {
    response = response || {};
    var wrapped = {
      raw: function() { return response.raw || ""; },
      url: function() { return response.url || ""; },
      body: function() { return response.body || ""; },
      code: function() { return response.code || 200; },
      statusCode: function() { return response.code || 200; },
      message: function() { return response.message || "OK"; },
      statusMessage: function() { return response.message || "OK"; },
      contentType: function() { return response.contentType || ""; },
      headers: function(name) {
        if (arguments.length === 0) return response.headers || {};
        var wanted = String(name || "").toLowerCase();
        var values = [];
        var list = Array.isArray(response.headersList) ? response.headersList : [];
        for (var i = 0; i < list.length; i++) {
          var entry = list[i] || [];
          if (entry.length >= 2 && String(entry[0] || "").toLowerCase() === wanted) values.push(String(entry[1] || ""));
        }
        if (values.length) return values;
        var headers = response.headers || {};
        for (var key in headers) if (String(key).toLowerCase() === wanted) return [String(headers[key] || "")];
        return [];
      },
      headersList: function() { return response.headersList || []; },
      header: function(name) {
        var values = wrapped.headers(name);
        if (values.length) return values[0];
        return "";
      },
      isSuccessful: function() {
        var code = Number(response.code || 200);
        return code >= 200 && code < 300;
      },
      errorBody: function() { return response.errorBody || null; },
      callTime: function() { return Number(response.callTime || 0); },
      toString: function() { return response.raw || response.url || ""; }
    };
    Object.defineProperty(wrapped, "__legadoResponseJson", {
      value: function() { return JSON.stringify(response); },
      enumerable: false
    });
    return wrapped;
  };
  function __legadoErrorText(error) {
    if (error === null || typeof error === "undefined") return "";
    if (error && typeof error.stack === "string" && error.stack) {
      var message = error && typeof error.message === "string" ? error.message : "";
      return message && error.stack.indexOf(message) < 0 ? (message + "\n" + error.stack) : error.stack;
    }
    if (error && typeof error.toString === "function") return String(error);
    return String(error);
  }
  function __legadoErrorMessage(error) {
    if (error && typeof error.message === "string" && error.message) return error.message;
    return "Error Response";
  }
  java.getErrStrResponse = function(error) {
    var text = __legadoErrorText(error);
    return java.__strResponse({
      url: java.url || java.ruleUrl || "http://localhost/",
      body: text,
      code: 500,
      message: __legadoErrorMessage(error),
      headers: {},
      headersList: [],
      contentType: null,
      raw: "",
      errorBody: text
    });
  };
  java.getErrResponse = function(error) {
    return java.getErrStrResponse(error);
  };
  java.startBrowser = function(url, title, html) {
    var response = java.__platformResponse("startBrowser", arguments);
    return response.marker || "";
  };
  java.startBrowserAwait = function(url, title, refetchAfterSuccess, html) {
    return java.__strResponse(java.__platformResponse("startBrowserAwait", arguments));
  };
  java.showBrowser = function(url, html, preloadJs, config) {
    var response = java.__platformResponse("showBrowser", arguments);
    return response.marker || "";
  };
  java.openVideoPlayer = function(url, title, isFloat) {
    var response = java.__platformResponse("openVideoPlayer", arguments);
    return response.marker || "";
  };
  java.reLoginView = function(deltaUp) {
    var response = java.__platformResponse("reLoginView", arguments);
    return response.marker || "";
  };
  java.refreshExplore = function() {
    var response = java.__platformResponse("refreshExplore", arguments);
    return response.marker || "";
  };
  java.startBrowserDp = function(url, title, html) {
    var response = java.__platformResponse("startBrowserDp", arguments);
    return response.marker || "";
  };
  java.showReadingBrowser = function(url, title, html) {
    var response = java.__platformResponse("showReadingBrowser", arguments);
    return response.marker || "";
  };
  java.getReadBookConfig = function() {
    return java.__platformResponse("getReadBookConfig", arguments).body || "";
  };
  function __legadoConfigMap(raw, api) {
    raw = String(raw || "");
    if (!raw) return {};
    try {
      return JSON.parse(raw);
    } catch (e) {
      throw new Error("__LEGADO_CONFIG_ERROR__:" + api + ": invalid JSON: " + e + ": " + raw.slice(0, 160));
    }
  }
  java.getReadBookConfigMap = function() {
    return __legadoConfigMap(java.getReadBookConfig(), "getReadBookConfig");
  };
  java.getThemeMode = function() {
    return java.__platformResponse("getThemeMode", arguments).body || "";
  };
  java.getThemeConfig = function() {
    return java.__platformResponse("getThemeConfig", arguments).body || "";
  };
  java.getThemeConfigMap = function() {
    return __legadoConfigMap(java.getThemeConfig(), "getThemeConfig");
  };
  java.getWebViewUA = function() {
    return java.__platformResponse("getWebViewUA", arguments).body || "";
  };
  java.getUserAgent = function(url) {
    if (typeof java.__getUserAgentRaw !== "function") return "";
    return java.__getUserAgentRaw(arguments.length ? url : (java.ruleUrl || ""));
  };
  function __legadoEvalUrlSnippet(script, current) {
    globalThis.result = current;
    try {
      return Function("return (" + String(script || "") + "\n);")();
    } catch (exprError) {
      return Function(String(script || ""))();
    }
  }
  function __legadoInitUrlReplaceTemplates(value) {
    return String(value || "").replace(/\{\{([\s\S]*?)\}\}/g, function(_, script) {
      var out = __legadoEvalUrlSnippet(script, globalThis.result);
      if (typeof out === "number" && Math.floor(out) === out) return String(out);
      return out === null || typeof out === "undefined" ? "" : String(out);
    });
  }
  function __legadoInitUrlReplacePageLists(value) {
    var pageIndex = Math.max(1, Number(globalThis.page || 1));
    return String(value || "").replace(/<([^<>]*)>/g, function(_, body) {
      var values = String(body || "").split(",");
      var index = Math.min(values.length, pageIndex) - 1;
      return String(values[Math.max(0, index)] || "").trim();
    });
  }
  java.initUrl = function(url) {
    var rule = arguments.length ? String(url || "") : String(java.ruleUrl || java.url || "");
    var re = /<js>([\s\S]*?)<\/js>|@js:([\s\S]*)/gi;
    var start = 0;
    var result = rule;
    var match;
    while ((match = re.exec(rule)) !== null) {
      if (match.index > start) {
        var segment = rule.slice(start, match.index).trim();
        if (segment) result = segment.replace(/@result/g, result);
      }
      result = String(__legadoEvalUrlSnippet(match[2] !== undefined ? match[2] : match[1], result));
      start = match.index + match[0].length;
    }
    if (rule.length > start) {
      var tail = rule.slice(start).trim();
      if (tail) result = tail.replace(/@result/g, result);
    }
    result = __legadoInitUrlReplaceTemplates(result);
    result = __legadoInitUrlReplacePageLists(result);
    java.ruleUrl = result;
    if (/^data:/i.test(result)) {
      java.url = result;
      return java.url;
    }
    var parts = String(result).split(/\s*,\s*(?=\{)/);
    var resolved = java.toURL(parts[0], String(globalThis.baseUrl || ""));
    java.url = resolved.href;
    if (resolved.origin && resolved.pathname) {
      globalThis.baseUrl = resolved.origin + resolved.pathname.replace(/\/[^\/]*$/, "/");
    }
    return java.url;
  };
  java.setRedirectUrl = function(url) {
    url = String(url || "");
    if (/^data:/i.test(url)) return java.redirectUrl || null;
    var resolved = java.toURL(url, String(globalThis.baseUrl || ""));
    java.redirectUrl = resolved.href;
    if (resolved.origin && resolved.pathname) {
      globalThis.baseUrl = resolved.origin + resolved.pathname.replace(/\/[^\/]*$/, "/");
    }
    resolved.toString = function() { return this.href || ""; };
    return resolved;
  };
  java.androidId = function() {
    return java.__platformResponse("androidId", arguments).body || "";
  };
  java.getAppVersionName = function() {
    return java.__platformResponse("getAppVersionName", arguments).body || "";
  };
  java.getAppVersionCode = function() {
    return Number(java.__platformResponse("getAppVersionCode", arguments).body || 0);
  };
  java.getAppVariant = function() {
    return java.__platformResponse("getAppVariant", arguments).body || "";
  };
  java.reGetBook = function() {
    if (!globalThis.__legadoPreUpdateJs) {
      throw new Error("java.reGetBook can only be called in ruleToc.preUpdateJs");
    }
    return java.__preUpdateAction("reGetBook");
  };
  java.refreshTocUrl = function() {
    if (!globalThis.__legadoPreUpdateJs) {
      throw new Error("java.refreshTocUrl can only be called in ruleToc.preUpdateJs");
    }
    return java.__preUpdateAction("refreshTocUrl");
  };
  [
    "copyText", "upLoginData", "refreshBookInfo", "refreshBookToc", "refreshContent",
    "clearTtsCache", "openUrl", "showPhoto", "searchBook", "addBook", "open",
    "webView", "webViewGetSource", "webViewGetOverrideUrl", "getVerificationCode"
  ].forEach(function(api) {
    if (typeof java[api] !== "function") {
      java[api] = function() {
        var response = java.__platformResponse(api, arguments);
        return response.body || response.url || response.marker || "";
      };
    }
  });
}
if (typeof java !== "undefined") {
  java.getSource = function() {
    return typeof source === "undefined" ? null : source;
  };
  java.getTag = function() {
    return typeof source === "undefined" ? "" : String(source.sourceName || source.bookSourceName || "");
  };
  java.getCookie = function(tag, key) {
    tag = String(tag || "");
    if (key !== undefined && key !== null) {
      return typeof cookie !== "undefined" && cookie.getKey ? cookie.getKey(tag, String(key || "")) : "";
    }
    return typeof cookie !== "undefined" && cookie.getCookie ? cookie.getCookie(tag) : "";
  };
  if (typeof cookie !== "undefined") {
    cookie.setWebCookie = function(host, value) {
      var raw = java.__platformAction("setWebCookie", JSON.stringify([String(host || ""), String(value || "")]));
      if (String(raw || "").indexOf("__LEGADO_UNSUPPORTED_PLATFORM_API__:") === 0) {
        throw new Error(raw);
      }
      var response;
      try {
        response = JSON.parse(raw || "{}");
      } catch (e) {
        throw new Error("__LEGADO_PLATFORM_RESPONSE_ERROR__:setWebCookie: invalid response JSON: " + e + ": " + String(raw || "").slice(0, 160));
      }
      if (response && response.unsupported) {
        throw new Error(response.marker || "Unsupported platform API: setWebCookie");
      }
      return true;
    };
  }
}
if (typeof java !== "undefined" && !java.__platformAction) {
  [
    "startBrowser", "startBrowserAwait", "showBrowser", "openVideoPlayer",
    "reLoginView", "refreshExplore", "startBrowserDp", "showReadingBrowser",
    "getReadBookConfig", "getThemeMode", "getThemeConfig",
    "copyText", "upLoginData", "refreshBookInfo", "refreshBookToc", "refreshContent",
    "clearTtsCache", "openUrl", "showPhoto", "searchBook", "addBook", "open",
    "webView", "webViewGetSource", "webViewGetOverrideUrl", "getVerificationCode"
  ].forEach(function(api) {
    if (typeof java[api] !== "function") {
      java[api] = function() {
        throw new Error("__LEGADO_UNSUPPORTED_PLATFORM_API__:" + api);
      };
    }
  });
}
if (typeof java !== "undefined" && java.__timeFormatMillis) {
  java.timeFormat = function(time) {
    if (time instanceof Date) return java.__timeFormatMillis(time.getTime());
    return java.__timeFormatMillis(Number(time || 0));
  };
}
if (typeof java !== "undefined" && java.__timeFormatUtcMillis) {
  java.timeFormatUTC = function(time, format, sh) {
    var millis = time instanceof Date ? time.getTime() : Number(time || 0);
    return java.__timeFormatUtcMillis(millis, String(format || ""), Number(sh || 0));
  };
}
if (typeof java !== "undefined") {
  function __legadoAnyToString(value) {
    if (value === null || typeof value === "undefined") return "";
    if (typeof value === "string") return value;
    try {
      if (typeof value === "object") return JSON.stringify(value);
    } catch (e) {}
    return String(value);
  }
  ["toast", "longToast", "log"].forEach(function(api) {
    if (typeof java[api] === "function") {
      var raw = java[api];
      java[api] = function(value) {
        var message = __legadoAnyToString(value);
        var result = raw(message);
        try {
          if (typeof java.__platformAction === "function") {
            java.__platformAction(api, JSON.stringify([message]));
          }
        } catch (e) {}
        return result;
      };
    }
  });
  if (typeof java.logType === "function") {
    var rawLogType = java.logType;
    java.logType = function(value) {
      var message = typeof value;
      var result = rawLogType(message);
      try {
        if (typeof java.__platformAction === "function") {
          java.__platformAction("logType", JSON.stringify([message]));
        }
      } catch (e) {}
      return result;
    };
  }
  function __legadoCryptoThrow(value) {
    value = String(value || "");
    if (value.indexOf("__LEGADO_CRYPTO_ERROR__:") === 0) {
      throw new Error(value.substring("__LEGADO_CRYPTO_ERROR__:".length));
    }
    return value;
  }
  function __legadoCryptoArg(value) {
    if (value && typeof value === "object" && value.__hex) {
      return { text: String(value.__hex), isHex: true };
    }
    return { text: __legadoAnyToString(value), isHex: false };
  }
  globalThis.__legadoCryptoThrow = __legadoCryptoThrow;
  globalThis.__legadoCryptoArg = __legadoCryptoArg;
  ["digestHex", "digestBase64Str", "HMacHex", "HMacBase64"].forEach(function(api) {
    if (typeof java[api] === "function") {
      var raw = java[api];
      java[api] = function() {
        return __legadoCryptoThrow(raw.apply(java, arguments));
      };
    }
  });
  if (typeof java.aesBase64DecodeToString === "function") {
    var __legadoRawAesBase64DecodeToString = java.aesBase64DecodeToString;
    java.aesBase64DecodeToString = function(data, key, algorithm, iv) {
      return __legadoCryptoThrow(__legadoRawAesBase64DecodeToString(
        String(data || ""),
        String(key || ""),
        String(algorithm || ""),
        String(iv || "")
      ));
    };
  }
  if (typeof java.aesEncodeToBase64String === "function") {
    var __legadoRawAesEncodeToBase64String = java.aesEncodeToBase64String;
    java.aesEncodeToBase64String = function(data, key, algorithm, iv) {
      return __legadoCryptoThrow(__legadoRawAesEncodeToBase64String(
        String(data || ""),
        String(key || ""),
        String(algorithm || ""),
        String(iv || "")
      ));
    };
  }
  function __legadoBase64Bytes(value) {
    return Base64.getDecoder().decode(String(value || ""));
  }
  if (typeof java.__symmetricEncryptBase64 === "function") {
    java.createSymmetricCrypto = function(transformation, key, iv) {
      var algorithm = String(transformation || "AES/ECB/PKCS7Padding");
      var keyArg = __legadoCryptoArg(key);
      var ivArg = __legadoCryptoArg(iv || "");
      var cipher = {
        encryptBase64: function(data) {
          var dataArg = __legadoCryptoArg(data);
          return __legadoCryptoThrow(java.__symmetricEncryptBase64(algorithm, keyArg.text, keyArg.isHex, ivArg.text, ivArg.isHex, dataArg.text, dataArg.isHex));
        },
        encryptHex: function(data) {
          var dataArg = __legadoCryptoArg(data);
          return __legadoCryptoThrow(java.__symmetricEncryptHex(algorithm, keyArg.text, keyArg.isHex, ivArg.text, ivArg.isHex, dataArg.text, dataArg.isHex));
        },
        encrypt: function(data) {
          var dataArg = __legadoCryptoArg(data);
          return __javaBytes(__legadoCryptoThrow(java.__symmetricEncryptHex(algorithm, keyArg.text, keyArg.isHex, ivArg.text, ivArg.isHex, dataArg.text, dataArg.isHex)));
        },
        decryptStr: function(data) {
          var dataArg = __legadoCryptoArg(data);
          return __legadoCryptoThrow(java.__symmetricDecryptStr(algorithm, keyArg.text, keyArg.isHex, ivArg.text, ivArg.isHex, dataArg.text, dataArg.isHex));
        },
        decrypt: function(data) {
          var dataArg = __legadoCryptoArg(data);
          return __javaBytes(__legadoCryptoThrow(java.__symmetricDecryptHex(algorithm, keyArg.text, keyArg.isHex, ivArg.text, ivArg.isHex, dataArg.text, dataArg.isHex)));
        }
      };
      return cipher;
    };
    java.desDecodeToString = function(data, key, transformation, iv) {
      return java.createSymmetricCrypto(transformation, key, iv).decryptStr(data);
    };
    java.desBase64DecodeToString = java.desDecodeToString;
    java.desEncodeToString = function(data, key, transformation, iv) {
      var keyArg = __legadoCryptoArg(key);
      var ivArg = __legadoCryptoArg(iv || "");
      var dataArg = __legadoCryptoArg(data);
      return __legadoCryptoThrow(java.__symmetricEncryptLossyString(String(transformation || "DES/ECB/PKCS5Padding"), keyArg.text, keyArg.isHex, ivArg.text, ivArg.isHex, dataArg.text, dataArg.isHex));
    };
    java.desEncodeToBase64String = function(data, key, transformation, iv) {
      return java.createSymmetricCrypto(transformation, key, iv).encryptBase64(data);
    };
    java.aesDecodeToByteArray = function(data, key, transformation, iv) {
      return java.createSymmetricCrypto(transformation, key, iv).decrypt(data);
    };
    java.aesDecodeArgsBase64Str = function(data, key, mode, padding, iv) {
      return java.createSymmetricCrypto("AES/" + mode + "/" + padding, __legadoBase64Bytes(key), __legadoBase64Bytes(iv)).decryptStr(data);
    };
    java.aesBase64DecodeToByteArray = function(data, key, transformation, iv) {
      return java.createSymmetricCrypto(transformation, key, iv).decrypt(data);
    };
    java.aesEncodeToByteArray = function(data, key, transformation, iv) {
      return java.createSymmetricCrypto(transformation, key, iv).encrypt(data);
    };
    java.aesEncodeToBase64ByteArray = function(data, key, transformation, iv) {
      return __javaStringBytes(java.createSymmetricCrypto(transformation, key, iv).encryptBase64(data));
    };
    java.aesEncodeToString = function(data, key, transformation, iv) {
      return java.createSymmetricCrypto(transformation, key, iv).decryptStr(data);
    };
    java.tripleDESDecodeStr = function(data, key, mode, padding, iv) {
      return java.createSymmetricCrypto("DESede/" + mode + "/" + padding, key, iv).decryptStr(data);
    };
    java.tripleDESDecodeArgsBase64Str = function(data, key, mode, padding, iv) {
      return java.createSymmetricCrypto("DESede/" + mode + "/" + padding, __legadoBase64Bytes(key), iv).decryptStr(data);
    };
    java.tripleDESEncodeBase64Str = function(data, key, mode, padding, iv) {
      return java.createSymmetricCrypto("DESede/" + mode + "/" + padding, key, iv).encryptBase64(data);
    };
    java.tripleDESEncodeArgsBase64Str = function(data, key, mode, padding, iv) {
      return java.createSymmetricCrypto("DESede/" + mode + "/" + padding, __legadoBase64Bytes(key), iv).encryptBase64(data);
    };
  }
  if (typeof java.__asymmetricEncryptBase64 === "function") {
    java.createAsymmetricCrypto = function(transformation) {
      var publicKey = "";
      var privateKey = "";
      var algorithm = String(transformation || "RSA/ECB/PKCS1Padding");
      var cipher = {
        setPublicKey: function(key) {
          publicKey = __legadoAnyToString(key);
          return cipher;
        },
        setPrivateKey: function(key) {
          privateKey = __legadoAnyToString(key);
          return cipher;
        },
        encryptBase64: function(data, usePublicKey) {
          return __legadoCryptoThrow(java.__asymmetricEncryptBase64(algorithm, publicKey, privateKey, __legadoAnyToString(data), usePublicKey !== false));
        },
        encryptHex: function(data, usePublicKey) {
          return __legadoCryptoThrow(java.__asymmetricEncryptHex(algorithm, publicKey, privateKey, __legadoAnyToString(data), usePublicKey !== false));
        },
        encrypt: function(data, usePublicKey) {
          return cipher.encryptBase64(data, usePublicKey);
        },
        decryptStr: function(data, usePublicKey) {
          return __legadoCryptoThrow(java.__asymmetricDecryptStr(algorithm, publicKey, privateKey, __legadoAnyToString(data), usePublicKey !== false));
        },
        decrypt: function(data, usePublicKey) {
          return cipher.decryptStr(data, usePublicKey);
        }
      };
      return cipher;
    };
  }
  if (typeof java.__signHex === "function") {
    java.createSign = function(algorithm) {
      var publicKey = "";
      var privateKey = "";
      var signAlgorithm = String(algorithm || "SHA256withRSA");
      var signer = {
        setPublicKey: function(key) {
          publicKey = __legadoAnyToString(key);
          return signer;
        },
        setPrivateKey: function(key) {
          privateKey = __legadoAnyToString(key);
          return signer;
        },
        signHex: function(data) {
          return __legadoCryptoThrow(java.__signHex(signAlgorithm, privateKey, __legadoAnyToString(data)));
        },
        sign: function(data) {
          return __legadoCryptoThrow(java.__signBase64(signAlgorithm, privateKey, __legadoAnyToString(data)));
        }
      };
      return signer;
    };
  }
}
if (typeof java !== "undefined" && java.__strResponse) {
  function __legadoJavaMap(initial) {
    var actual = initial && typeof initial === "object" ? initial : {};
    return {
      get: function(key) {
        if (arguments.length === 0) return actual;
        var out = actual[String(key)];
        return out === undefined ? null : String(out);
      },
      put: function(key, value) {
        actual[String(key)] = String(value);
        return String(value);
      },
      remove: function(key) {
        var old = actual[String(key)];
        delete actual[String(key)];
        return old === undefined ? null : String(old);
      },
      putAll: function(next) {
        if (!next || typeof next !== "object") return;
        if (typeof next.get === "function" && typeof next.keySet === "function") {
          var keys = next.keySet();
          for (var i = 0; i < keys.length; i++) actual[String(keys[i])] = String(next.get(keys[i]));
          return;
        }
        Object.keys(next).forEach(function(key) {
          if (typeof next[key] !== "function") actual[String(key)] = String(next[key]);
        });
      },
      containsKey: function(key) {
        return Object.prototype.hasOwnProperty.call(actual, String(key));
      },
      keySet: function() { return Object.keys(actual); },
      clear: function() { actual = {}; },
      toJSON: function() { return actual; },
      __raw: function() { return actual; }
    };
  }
  if (!java.headerMap || typeof java.headerMap.__raw !== "function") java.headerMap = __legadoJavaMap(java.headerMap || {});
  java.getHeaderMap = function() { return java.headerMap; };
  globalThis.getHeaderMap = function() { return java.getHeaderMap(); };
  globalThis.initUrl = function(url) {
    return arguments.length ? java.initUrl(url) : java.initUrl();
  };
  function __legadoParseResponseJson(raw, api, url) {
    try {
      return JSON.parse(raw || "{}");
    } catch (e) {
      throw new Error("__LEGADO_HTTP_RESPONSE_ERROR__:" + api + ":" + String(url || "") + ": invalid response JSON: " + e + ": " + String(raw || "").slice(0, 160));
    }
  }
  function __legadoPrepareUrlOptions(rawUrl, consumeBodyJs) {
    rawUrl = String(rawUrl || "");
    var marker = rawUrl.lastIndexOf(",{");
    if (marker < 0) return { url: rawUrl, bodyJs: null, type: null };
    var base = rawUrl.slice(0, marker);
    var optionsText = rawUrl.slice(marker + 1);
    var options;
    try {
      options = JSON.parse(optionsText);
    } catch (e) {
      return { url: rawUrl, bodyJs: null, type: null };
    }
    if (!options || typeof options !== "object" || Array.isArray(options)) {
      return { url: rawUrl, bodyJs: null, type: null };
    }
    var fileType = typeof options.type === "string" && options.type.trim() ? String(options.type).trim() : null;
    var script = options.js;
    delete options.js;
    if (typeof script === "string" && script.trim()) {
      var result = base;
      var next = eval(script);
      if (next !== null && typeof next !== "undefined") base = String(next);
    }
    var bodyJs = null;
    if (consumeBodyJs) {
      bodyJs = options.bodyJs;
      delete options.bodyJs;
      if (typeof bodyJs !== "string" || !bodyJs.trim()) {
        bodyJs = options.body_js;
        delete options.body_js;
      }
      if (typeof bodyJs !== "string" || !bodyJs.trim()) bodyJs = null;
    }
    var keys = Object.keys(options);
    return { url: keys.length ? base + "," + JSON.stringify(options) : base, bodyJs: bodyJs, type: fileType };
  }
  function __legadoApplyBodyJs(script, body) {
    if (typeof script !== "string" || !script.trim()) return body;
    var result = String(body || "");
    var next = eval(script);
    return next === null || typeof next === "undefined" ? String(next) : String(next);
  }
  function __legadoAnalyzeUrlTarget() {
    if (!java.url && (java.ruleUrl || globalThis.baseUrl)) java.initUrl(java.ruleUrl || globalThis.baseUrl || "");
    return String(java.url || java.ruleUrl || globalThis.baseUrl || "");
  }
  function __legadoHeaderMapJson() {
    try {
      return JSON.stringify(java.headerMap && java.headerMap.__raw ? java.headerMap.__raw() : (java.headerMap || {}));
    } catch (e) {
      return "{}";
    }
  }
  globalThis.__legadoPrepareUrlOptions = __legadoPrepareUrlOptions;
  globalThis.__legadoApplyBodyJs = __legadoApplyBodyJs;
  function __legadoTimeoutArg(value) {
    return (value === null || typeof value === "undefined") ? -1 : Number(value || 0);
  }
  globalThis.__legadoTimeoutArg = __legadoTimeoutArg;
  if (typeof java.__httpRequestRaw === "function") {
    java.__httpResponse = function(method, url, body, headers, timeout) {
      var headersJson = "{}";
      try { headersJson = JSON.stringify(headers || {}); } catch (e) {}
      var raw = java.__httpRequestRaw(String(method || "GET"), String(url || ""), String(body || ""), headersJson, __legadoTimeoutArg(timeout));
      return java.__strResponse(__legadoParseResponseJson(raw, method || "GET", url));
    };
    if (typeof java.get === "function") {
      java.__storeGet = java.get;
      java.get = function(keyOrUrl, headers, timeout) {
        if (arguments.length <= 1) return java.__storeGet(String(keyOrUrl || ""));
        return java.__httpResponse("GET", keyOrUrl, "", headers, timeout);
      };
    }
    java.head = function(url, headers, timeout) {
      return java.__httpResponse("HEAD", url, "", headers, timeout);
    };
    java.post = function(url, body, headers, timeout) {
      return java.__httpResponse("POST", url, body, headers, timeout);
    };
    java.getResponse = function() {
      return java.__httpResponse("GET", __legadoAnalyzeUrlTarget(), "", java.headerMap && java.headerMap.__raw ? java.headerMap.__raw() : {}, -1);
    };
    java.getResponseAwait = java.getResponse;
    globalThis.getResponse = function() { return java.getResponse(); };
    globalThis.getResponseAwait = globalThis.getResponse;
    java.getStrResponse = function(jsStr, sourceRegex, useWebView) {
      if (sourceRegex !== null && typeof sourceRegex !== "undefined" && String(sourceRegex || "").trim()) {
        throw new Error("__LEGADO_UNSUPPORTED_HOST_API__:getStrResponse(sourceRegex) requires WebView/sourceRegex platform boundary");
      }
      var response = java.getResponse();
      if (typeof jsStr === "string" && jsStr.trim()) {
        var result = response.body();
        var next = eval(jsStr);
        var body = next === null || typeof next === "undefined" ? String(next) : String(next);
        return java.__strResponse({
          url: response.url(),
          body: body,
          code: response.code(),
          message: response.message(),
          headers: response.headers(),
          headersList: response.headersList(),
          contentType: response.contentType(),
          raw: response.raw()
        });
      }
      return response;
    };
    java.getStrResponseAwait = java.getStrResponse;
    globalThis.getStrResponse = function(jsStr, sourceRegex, useWebView) {
      return java.getStrResponse(jsStr, sourceRegex, useWebView);
    };
    globalThis.getStrResponseAwait = globalThis.getStrResponse;
    java.getByteArray = function(timeout) {
      if (typeof java.__requestBytesHex !== "function") return __javaBytes("");
      var hex = String(java.__requestBytesHex(__legadoAnalyzeUrlTarget(), __legadoHeaderMapJson(), __legadoTimeoutArg(timeout)) || "");
      if (hex.indexOf("__LEGADO_REQUEST_ERROR__:") === 0) throw new Error(hex);
      return __javaBytes(hex);
    };
    java.getByteArrayAwait = java.getByteArray;
    java.getInputStream = function(timeout) {
      return new ByteArrayInputStream(java.getByteArray(timeout));
    };
    java.getInputStreamAwait = java.getInputStream;
  }
  if (typeof java.connect === "function") {
    java.__connectRaw = java.connect;
    java.connect = function(url, header, callTimeout) {
      var prepared = __legadoPrepareUrlOptions(url, true);
      var raw = java.__connectRaw(prepared.url, header == null ? "{}" : String(header), __legadoTimeoutArg(callTimeout));
      var parsed = __legadoParseResponseJson(raw, "connect", prepared.url);
      parsed.body = __legadoApplyBodyJs(prepared.bodyJs, parsed.body);
      return java.__strResponse(parsed);
    };
  }
  if (typeof java.ajax === "function") {
    java.__ajaxRaw = java.ajax;
    java.ajax = function(url, callTimeout) {
      if (Array.isArray(url)) url = url.length ? url[0] : "";
      var prepared = __legadoPrepareUrlOptions(url, true);
      return __legadoApplyBodyJs(prepared.bodyJs, java.__ajaxRaw(prepared.url, __legadoTimeoutArg(callTimeout)));
    };
  }
  if (typeof java.ajaxAll === "function") {
    java.__ajaxAllRaw = java.ajaxAll;
    function __legadoAjaxAllThrow(value) {
      value = String(value || "");
      if (value.indexOf("__LEGADO_AJAX_ALL_ERROR__:") === 0) {
        throw new Error(value);
      }
      return value;
    }
    java.ajaxAll = function(urlList, skipRateLimit) {
      var list = Array.isArray(urlList) ? urlList : [];
      var prepared = list.map(function(url) { return __legadoPrepareUrlOptions(url, true); });
      var raw = __legadoAjaxAllThrow(java.__ajaxAllRaw(JSON.stringify(prepared.map(function(item) { return item.url; })), -1, skipRateLimit === true));
      try {
        return JSON.parse(raw || "[]").map(function(item, index) {
          item.body = __legadoApplyBodyJs(prepared[index] && prepared[index].bodyJs, item.body);
          return java.__strResponse(item);
        });
      } catch (e) {
        throw new Error("__LEGADO_AJAX_ALL_ERROR__:invalid response JSON: " + e + ": " + String(raw || "").slice(0, 160));
      }
    };
    java.ajaxTestAll = function(urlList, timeout, skipRateLimit) {
      var list = Array.isArray(urlList) ? urlList : [];
      var prepared = list.map(function(url) { return __legadoPrepareUrlOptions(url, true); });
      var raw = __legadoAjaxAllThrow(java.__ajaxAllRaw(JSON.stringify(prepared.map(function(item) { return item.url; })), __legadoTimeoutArg(timeout), skipRateLimit === true));
      try {
        return JSON.parse(raw || "[]").map(function(item, index) {
          item.body = __legadoApplyBodyJs(prepared[index] && prepared[index].bodyJs, item.body);
          return java.__strResponse(item);
        });
      } catch (e) {
        throw new Error("__LEGADO_AJAX_ALL_ERROR__:invalid response JSON: " + e + ": " + String(raw || "").slice(0, 160));
      }
    };
  }
}
if (typeof java !== "undefined") {
  function __legadoContentToString(value) {
    if (value === null || typeof value === "undefined") return "";
    if (typeof value === "string") return value;
    try {
      if (typeof value === "object") return JSON.stringify(value);
    } catch (e) {}
    return String(value);
  }
  function __legadoRuleThrow(value) {
    value = String(value || "");
    if (value.indexOf("__LEGADO_RULE_ERROR__:") === 0) {
      throw new Error(value);
    }
    return value;
  }
  if (typeof java.getString === "function") {
    var __legadoRawGetString = java.getString;
    java.getString = function(path) {
      return __legadoRuleThrow(__legadoRawGetString(String(path || "")));
    };
  }
  java.setContent = function(content, baseUrl) {
    java.__setContentRaw(__legadoContentToString(content));
    if (baseUrl) globalThis.baseUrl = String(baseUrl);
    return java;
  };
  function __legadoHtmlReplace(parent, target, replacement) {
    if (!parent || typeof parent.__html !== "string") return;
    parent.__html = parent.__html.replace(String(target || ""), String(replacement || ""));
  }
  function __legadoHtmlMutateCollection(nodes, op, value) {
    nodes.forEach(function(node) {
      if (!node.__parent) return;
      if (op === "remove") __legadoHtmlReplace(node.__parent, node.__html, "");
      else if (op === "before") __legadoHtmlReplace(node.__parent, node.__html, String(value || "") + node.__html);
      else if (op === "after") __legadoHtmlReplace(node.__parent, node.__html, node.__html + String(value || ""));
    });
    return nodes;
  }
  function __legadoElements(nodes) {
    nodes = Array.isArray(nodes) ? nodes : [];
    Object.defineProperty(nodes, "size", {
      enumerable: false,
      value: function() { return nodes.length; }
    });
    Object.defineProperty(nodes, "isEmpty", {
      enumerable: false,
      value: function() { return nodes.length === 0; }
    });
    Object.defineProperty(nodes, "get", {
      enumerable: false,
      value: function(index) { return nodes[Number(index || 0)] || null; }
    });
    Object.defineProperty(nodes, "first", {
      enumerable: false,
      value: function() { return nodes.length ? nodes[0] : null; }
    });
    Object.defineProperty(nodes, "last", {
      enumerable: false,
      value: function() { return nodes.length ? nodes[nodes.length - 1] : null; }
    });
    Object.defineProperty(nodes, "text", {
      enumerable: false,
      value: function() { return nodes.map(function(n) { return n.text(); }).join(""); }
    });
    Object.defineProperty(nodes, "eachText", {
      enumerable: false,
      value: function() { return nodes.map(function(n) { return n.text(); }); }
    });
    Object.defineProperty(nodes, "attr", {
      enumerable: false,
      value: function(name) { return nodes.length ? nodes[0].attr(name) : ""; }
    });
    Object.defineProperty(nodes, "eachAttr", {
      enumerable: false,
      value: function(name) { return nodes.map(function(n) { return n.attr(name); }); }
    });
    Object.defineProperty(nodes, "html", {
      enumerable: false,
      value: function() { return nodes.map(function(n) { return n.html(); }).join("\n"); }
    });
    Object.defineProperty(nodes, "outerHtml", {
      enumerable: false,
      value: function() { return nodes.map(function(n) { return n.outerHtml(); }).join("\n"); }
    });
    Object.defineProperty(nodes, "remove", {
      enumerable: false,
      value: function() { return __legadoHtmlMutateCollection(nodes, "remove", ""); }
    });
    Object.defineProperty(nodes, "before", {
      enumerable: false,
      value: function(value) { return __legadoHtmlMutateCollection(nodes, "before", value); }
    });
    Object.defineProperty(nodes, "after", {
      enumerable: false,
      value: function(value) { return __legadoHtmlMutateCollection(nodes, "after", value); }
    });
    return nodes;
  }
  function __legadoElementHtml(tag) {
    tag = String(tag || "div").replace(/[^A-Za-z0-9:_-]/g, "") || "div";
    return "<" + tag + "></" + tag + ">";
  }
  function __legadoHtmlNode(html, parent) {
    var node = {};
    Object.defineProperty(node, "__html", { value: String(html || ""), enumerable: false, writable: true });
    Object.defineProperty(node, "__originalHtml", { value: String(html || ""), enumerable: false, writable: true });
    Object.defineProperty(node, "__parent", { value: parent || null, enumerable: false, writable: true });
    Object.defineProperty(node, "select", {
      enumerable: false,
      value: function(rule) {
        var raw = java.__selectElementsJson(this.__html, String(rule || ""));
        raw = __legadoRuleThrow(raw);
        var values = [];
        try {
          values = JSON.parse(raw || "[]");
        } catch (e) {
          throw new Error("__LEGADO_RULE_ERROR__:invalid selected-node JSON: " + e + ": " + String(raw || "").slice(0, 160));
        }
        var parent = this;
        return __legadoElements(values.map(function(item) { return __legadoHtmlNode(item, parent); }));
      }
    });
    Object.defineProperty(node, "selectFirst", {
      enumerable: false,
      value: function(rule) {
        var nodes = this.select(rule);
        return nodes.length ? nodes[0] : null;
      }
    });
    Object.defineProperty(node, "text", {
      enumerable: false,
      value: function(value) {
        if (arguments.length === 0) return __legadoRuleThrow(java.__extractHtmlRule(this.__html, "text"));
        this.__html = this.__html.replace(/>[\s\S]*<\//, ">" + String(value || "") + "</");
        return this;
      }
    });
    Object.defineProperty(node, "ownText", {
      enumerable: false,
      value: function() { return __legadoRuleThrow(java.__extractHtmlRule(this.__html, "ownText")); }
    });
    Object.defineProperty(node, "attr", {
      enumerable: false,
      value: function(name, value) {
        name = String(name || "");
        if (arguments.length <= 1) return __legadoRuleThrow(java.__extractHtmlRule(this.__html, name));
        var escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        var attrRe = new RegExp("(\\s" + escaped + "\\s*=\\s*)(['\"])(.*?)\\2", "i");
        if (attrRe.test(this.__html)) {
          this.__html = this.__html.replace(attrRe, "$1\"" + String(value || "") + "\"");
        } else {
          this.__html = this.__html.replace(/^<([^\s>/]+)/, "<$1 " + name + "=\"" + String(value || "") + "\"");
        }
        return this;
      }
    });
    Object.defineProperty(node, "hasAttr", {
      enumerable: false,
      value: function(name) { return this.attr(name) !== ""; }
    });
    Object.defineProperty(node, "hasClass", {
      enumerable: false,
      value: function(name) {
        var cls = this.attr("class").split(/\s+/);
        return cls.indexOf(String(name || "")) >= 0;
      }
    });
    Object.defineProperty(node, "addClass", {
      enumerable: false,
      value: function(name) {
        name = String(name || "").trim();
        if (!name || this.hasClass(name)) return this;
        var current = this.attr("class");
        return this.attr("class", current ? current + " " + name : name);
      }
    });
    Object.defineProperty(node, "removeClass", {
      enumerable: false,
      value: function(name) {
        name = String(name || "").trim();
        var next = this.attr("class").split(/\s+/).filter(function(item) { return item && item !== name; }).join(" ");
        return this.attr("class", next);
      }
    });
    Object.defineProperty(node, "html", {
      enumerable: false,
      value: function(value) {
        if (arguments.length === 0) return __legadoRuleThrow(java.__extractHtmlRule(this.__html, "html"));
        this.__html = this.__html.replace(/>[\s\S]*<\//, ">" + String(value || "") + "</");
        return this;
      }
    });
    Object.defineProperty(node, "appendChild", {
      enumerable: false,
      value: function(child) {
        var childHtml = child && child.__html ? child.__html : String(child || "");
        this.__html = this.__html.replace(/<\/([^>]+)>\s*$/, childHtml + "</$1>");
        return this;
      }
    });
    Object.defineProperty(node, "outerHtml", {
      enumerable: false,
      value: function() { return this.__html; }
    });
    Object.defineProperty(node, "tagName", {
      enumerable: false,
      value: function() {
        var match = /^<\s*([A-Za-z0-9:_-]+)/.exec(this.__html);
        return match ? match[1].toLowerCase() : "";
      }
    });
    Object.defineProperty(node, "appendText", {
      enumerable: false,
      value: function(value) {
        this.__html = this.__html.replace(/<\/([^>]+)>\s*$/, String(value || "") + "</$1>");
        return this;
      }
    });
    Object.defineProperty(node, "remove", {
      enumerable: false,
      value: function() {
        if (this.__parent) __legadoHtmlReplace(this.__parent, this.__html, "");
        this.__html = "";
        return this;
      }
    });
    Object.defineProperty(node, "replaceWith", {
      enumerable: false,
      value: function(value) {
        var html = value && value.__html ? value.__html : String(value || "");
        if (this.__parent) {
          if (this.__parent.__html.indexOf(this.__html) >= 0) __legadoHtmlReplace(this.__parent, this.__html, html);
          else __legadoHtmlReplace(this.__parent, this.__originalHtml, html);
        }
        this.__html = html;
        return this;
      }
    });
    Object.defineProperty(node, "before", {
      enumerable: false,
      value: function(value) {
        if (this.__parent) __legadoHtmlReplace(this.__parent, this.__html, String(value || "") + this.__html);
        return this;
      }
    });
    Object.defineProperty(node, "after", {
      enumerable: false,
      value: function(value) {
        if (this.__parent) __legadoHtmlReplace(this.__parent, this.__html, this.__html + String(value || ""));
        return this;
      }
    });
    Object.defineProperty(node, "toString", {
      enumerable: false,
      value: function() { return this.__html; }
    });
    return node;
  }
  globalThis.__legadoHtmlNode = __legadoHtmlNode;
  function Element(tag) {
    return __legadoHtmlNode(__legadoElementHtml(tag));
  }
  globalThis.Element = Element;
  if (typeof org === "undefined") globalThis.org = {};
  if (!org.jsoup) org.jsoup = {};
  function __legadoJsoupConnect(url) {
    var state = {
      url: String(url || ""),
      headers: {},
      body: "",
      method: "GET",
      timeout: null
    };
    var connection = {
      timeout: function(value) {
        state.timeout = Number(value || 0);
        return connection;
      },
      ignoreContentType: function(value) {
        return connection;
      },
      followRedirects: function(value) {
        return connection;
      },
      headers: function(value) {
        if (value && typeof value === "object") {
          Object.keys(value).forEach(function(key) { state.headers[key] = String(value[key] || ""); });
        }
        return connection;
      },
      header: function(key, value) {
        state.headers[String(key || "")] = String(value || "");
        return connection;
      },
      requestBody: function(value) {
        state.body = String(value || "");
        return connection;
      },
      data: function(key, value) {
        var entry = encodeURIComponent(String(key || "")) + "=" + encodeURIComponent(String(value || ""));
        state.body = state.body ? state.body + "&" + entry : entry;
        if (state.method === "GET") state.method = "POST";
        return connection;
      },
      method: function(value) {
        state.method = String(value || "GET").toUpperCase();
        return connection;
      },
      execute: function() {
        if (!java.__httpResponse) throw new Error("__LEGADO_UNSUPPORTED_HOST_API__:Jsoup.connect requires java.__httpResponse");
        return java.__httpResponse(state.method, state.url, state.body, state.headers, state.timeout);
      },
      get: function() {
        state.method = "GET";
        return connection.execute().body();
      },
      post: function() {
        state.method = "POST";
        return connection.execute().body();
      }
    };
    return connection;
  }
  org.jsoup.Jsoup = {
    parse: function(html) {
      return __legadoHtmlNode(html);
    },
    connect: function(url) {
      return __legadoJsoupConnect(url);
    }
  };
  var __legadoJsoupConnection = {
    Method: {
      GET: "GET",
      POST: "POST",
      HEAD: "HEAD",
      PUT: "PUT",
      DELETE: "DELETE",
      PATCH: "PATCH",
      OPTIONS: "OPTIONS"
    }
  };
  if (!Packages.java) Packages.java = {};
  if (!Packages.java.util) Packages.java.util = {};
  if (!Packages.java.lang) Packages.java.lang = {};
  Packages.java.util.Collections = __legadoMarkJavaImport(Packages.java.util.Collections || {}, "Collections");
  Packages.java.util.Collections.reverse = function(value) {
    if (value && typeof value.reverse === "function") return value.reverse();
    return value;
  };
  Packages.java.lang.Thread = __legadoMarkJavaImport(Packages.java.lang.Thread || {}, "Thread");
  Packages.java.lang.Thread.sleep = function(value) {
    if (typeof java !== "undefined" && typeof java.__threadSleepRaw === "function") {
      return java.__threadSleepRaw(String(Number(value) || 0));
    }
    return null;
  };
  if (!Packages.org) Packages.org = {};
  if (!Packages.org.jsoup) Packages.org.jsoup = {};
  if (!Packages.org.jsoup.nodes) Packages.org.jsoup.nodes = {};
  if (!Packages.org.jsoup.select) Packages.org.jsoup.select = {};
  Packages.org.jsoup.Jsoup = __legadoMarkJavaImport(org.jsoup.Jsoup, "Jsoup");
  Packages.org.jsoup.Connection = __legadoMarkJavaImport(__legadoJsoupConnection, "Connection");
  Packages.org.jsoup.nodes.Element = __legadoMarkJavaImport(Element, "Element");
  Packages.org.jsoup.select.Elements = __legadoMarkJavaImport(Array, "Elements");
  function __legadoJavaList(values) {
    values = Array.isArray(values) ? values : [];
    Object.defineProperty(values, "get", {
      enumerable: false,
      value: function(index) { return values[Number(index || 0)] || null; }
    });
    Object.defineProperty(values, "size", {
      enumerable: false,
      value: function() { return values.length; }
    });
    Object.defineProperty(values, "isEmpty", {
      enumerable: false,
      value: function() { return values.length === 0; }
    });
    Object.defineProperty(values, "toArray", {
      enumerable: false,
      value: function() { return values.slice(); }
    });
    return values;
  }
  function __legadoRegexGroups(content, rule, single) {
    var regs = String(rule || "").split("&&").map(function(item) { return item.trim(); }).filter(Boolean);
    function run(input, index) {
      if (index >= regs.length) return single ? null : [];
      var re = new RegExp(regs[index], "g");
      var match;
      var matches = [];
      while ((match = re.exec(String(input || ""))) !== null) {
        matches.push(match);
        if (match[0] === "") re.lastIndex++;
        if (single && index + 1 === regs.length) break;
      }
      if (!matches.length) return single ? null : [];
      if (index + 1 === regs.length) {
        if (single) return __legadoJavaList(Array.prototype.slice.call(matches[0]).map(function(value) { return value == null ? "" : String(value); }));
        return __legadoJavaList(matches.map(function(item) { return __legadoJavaList(Array.prototype.slice.call(item).map(function(value) { return value == null ? "" : String(value); })); }));
      }
      var joined = matches.map(function(item) { return item[0] || ""; }).join("");
      return run(joined, index + 1);
    }
    return run(content, 0);
  }
  function __legadoReadJsonPathList(content, rule) {
    var path = String(rule || "");
    if (/^@Json:/i.test(path)) path = path.slice(6);
    var value = __legadoJsonPathRead(content, path, true);
    if (Array.isArray(value)) return value;
    if (value === null || typeof value === "undefined") return [];
    return [value];
  }
  function __legadoLooksJsonPath(rule) {
    rule = String(rule || "");
    return /^@Json:/i.test(rule) || rule.indexOf("$.") === 0 || rule.indexOf("$[") === 0 || rule === "$";
  }
  function __legadoElementRule(rule) {
    rule = String(rule || "");
    if (/<webJs>/i.test(rule) || /^@WebJs:/i.test(rule)) {
      throw new Error("__LEGADO_UNSUPPORTED_PLATFORM_API__:java.getElements.webJs");
    }
    if (/^@XPath:/i.test(rule)) return rule.slice(7);
    return rule;
  }
  java.getElements = function(rule) {
    rule = __legadoElementRule(rule);
    var content = java.__getContentRaw();
    if (rule.charAt(0) === ":") return __legadoRegexGroups(content, rule.slice(1), false);
    if (__legadoLooksJsonPath(rule)) return __legadoReadJsonPathList(content, rule);
    return __legadoHtmlNode(content).select(rule);
  };
  java.getElement = function(rule) {
    rule = __legadoElementRule(rule);
    var content = java.__getContentRaw();
    if (rule.charAt(0) === ":") return __legadoRegexGroups(content, rule.slice(1), true);
    if (__legadoLooksJsonPath(rule)) {
      var path = /^@Json:/i.test(rule) ? rule.slice(6) : rule;
      return __legadoJsonPathRead(content, path, true);
    }
    var list = java.getElements(rule);
    return list.length ? list[0] : null;
  };
  java.importScript = function(path) {
    path = String(path || "");
    var text = /^https?:/i.test(path)
      ? java.cacheFile(path, 0)
      : (typeof java.__readTextFile === "function" ? java.__readTextFile(path) : "");
    if (!text || /^__LEGADO_REQUEST_ERROR__/.test(text)) throw new Error("java.importScript failed: " + path + " " + text);
    return text;
  };
  java.cacheFile = function(url, saveTime) {
    url = String(url || "");
    var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, true) : { url: url, bodyJs: null };
    var text = typeof java.__cacheTextFile === "function"
      ? java.__cacheTextFile(prepared.url, Number(saveTime || 0))
      : java.__fetchText(prepared.url);
    if (/^__LEGADO_REQUEST_ERROR__/.test(String(text || ""))) {
      throw new Error("java.cacheFile failed: " + url + " " + text);
    }
    return globalThis.__legadoApplyBodyJs ? globalThis.__legadoApplyBodyJs(prepared.bodyJs, text) : text;
  };
  if (typeof globalThis.request === "function") {
    var __legadoRawRequest = globalThis.request;
    globalThis.request = function(url, method, body, headers, timeout) {
      var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, true) : { url: String(url || ""), bodyJs: null };
      var text;
      if (arguments.length <= 1) {
        text = __legadoRawRequest(prepared.url);
      } else {
        var headersJson = "{}";
        try { headersJson = JSON.stringify(headers || {}); } catch (e) {}
        text = __legadoRawRequest(prepared.url, String(method || "GET"), String(body || ""), headersJson, globalThis.__legadoTimeoutArg ? globalThis.__legadoTimeoutArg(timeout) : -1);
      }
      if (/^__LEGADO_REQUEST_ERROR__/.test(String(text || ""))) {
        throw new Error(String(text));
      }
      return globalThis.__legadoApplyBodyJs ? globalThis.__legadoApplyBodyJs(prepared.bodyJs, text) : text;
    };
  }
  function __legadoUrlSuffix(url) {
    var clean = String(url || "").split(',{')[0].split('#')[0].split('?')[0];
    var match = clean.match(/\.([A-Za-z0-9]+)$/);
    return match ? match[1] : "bin";
  }
  java.downloadFile = function(url) {
    var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, true) : { url: String(url || ""), bodyJs: null, type: null };
    var type = prepared.type || __legadoUrlSuffix(prepared.url);
    var path = "/" + java.md5Encode16(String(url || "")) + "." + type;
    var ok = java.__downloadFile ? String(java.__downloadFile(prepared.url, path)) : "";
    if (/^__LEGADO_REQUEST_ERROR__/.test(ok)) throw new Error("java.downloadFile failed: " + url + " " + ok);
    return path;
  };
  java.__downloadHexFile = function(content, url) {
    var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, false) : { url: String(url || ""), bodyJs: null, type: null };
    if (!prepared.type) return "";
    var path = "/" + java.md5Encode16(String(url || "")) + "." + prepared.type;
    if (!java.__writeBytesFileHex || !java.__writeBytesFileHex(path, String(content || ""))) {
      throw new Error("java.downloadFile hex failed: " + url);
    }
    return path;
  };
  java.readTxtFile = function(path, charset) { return java.__readTextFile ? __legadoCharsetThrow(java.__readTextFile(String(path || ""), String(charset || ""))) : ""; };
  java.writeTxtFile = function(path, text) { return java.__writeTextFile ? java.__writeTextFile(String(path || ""), String(text || "")) : false; };
  java.deleteFile = function(path) { return java.__deleteTextFile ? java.__deleteTextFile(String(path || "")) : false; };
  java.fileExist = function(path) { return java.__fileExists ? !!java.__fileExists(String(path || "")) : (!!(java.__readBytesFileHex && java.__readBytesFileHex(String(path || ""))) || !!java.readTxtFile(path)); };
  java.getFile = function(path) {
    path = String(path || "");
    var name = path.split(/[\\/]/).filter(Boolean).pop() || "";
    return {
      path: path,
      absolutePath: path,
      name: name,
      getPath: function() { return path; },
      getAbsolutePath: function() { return path; },
      getName: function() { return name; },
      exists: function() { return java.fileExist(path); },
      isFile: function() { return java.fileExist(path); },
      isDirectory: function() { return false; },
      length: function() {
        var bytes = java.readFile(path);
        return bytes && typeof bytes.length === "number" ? bytes.length : 0;
      },
      readBytes: function() { return java.readFile(path); },
      readText: function(charset) { return java.readTxtFile(path, charset || "UTF-8"); },
      delete: function() { return java.deleteFile(path); },
      toString: function() { return path; },
      valueOf: function() { return path; }
    };
  };
  java.readFile = function(path) {
    var hex = java.__readBytesFileHex ? java.__readBytesFileHex(String(path || "")) : "";
    if (hex) return __javaBytes(hex);
    if (java.fileExist(path)) return __javaBytes("");
    var text = java.readTxtFile(path);
    return text ? java.strToBytes(text, "UTF-8") : null;
  };
  function __legadoZipThrow(value) {
    value = String(value || "");
    if (value.indexOf("__LEGADO_ZIP_ERROR__:") === 0) {
      throw new Error(value);
    }
    return value;
  }
  function __legado7zThrow(value) {
    value = String(value || "");
    if (value.indexOf("__LEGADO_7Z_ERROR__:") === 0) {
      throw new Error(value);
    }
    return value;
  }
  function __legadoRarThrow(value) {
    value = String(value || "");
    if (value.indexOf("__LEGADO_RAR_ERROR__:") === 0) {
      throw new Error(value);
    }
    return value;
  }
  java.getZipByteArrayContent = function(url, path) {
    var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, true) : { url: String(url || ""), bodyJs: null };
    var hex = java.__zipEntryHex ? java.__zipEntryHex(prepared.url, String(path || "")) : "";
    hex = __legadoZipThrow(hex);
    return hex ? __javaBytes(hex) : null;
  };
  java.getZipStringContent = function(url, path, charset) {
    var bytes = java.getZipByteArrayContent(url, path);
    if (!bytes) return "";
    return charset ? java.bytesToStr(bytes, charset) : __legadoHexThrow(java.__hexToAutoString(bytes.__hex || ""));
  };
  java.getRarByteArrayContent = function(url, path) {
    var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, true) : { url: String(url || ""), bodyJs: null };
    var hex = java.__rarEntryHex ? java.__rarEntryHex(prepared.url, String(path || "")) : "";
    hex = __legadoRarThrow(hex);
    return hex ? __javaBytes(hex) : null;
  };
  java.getRarStringContent = function(url, path, charset) {
    var bytes = java.getRarByteArrayContent(url, path);
    if (!bytes) return "";
    return charset ? java.bytesToStr(bytes, charset) : __legadoHexThrow(java.__hexToAutoString(bytes.__hex || ""));
  };
  java.get7zByteArrayContent = function(url, path) {
    var prepared = globalThis.__legadoPrepareUrlOptions ? globalThis.__legadoPrepareUrlOptions(url, true) : { url: String(url || ""), bodyJs: null };
    var hex = java.__7zEntryHex ? java.__7zEntryHex(prepared.url, String(path || "")) : "";
    hex = __legado7zThrow(hex);
    return hex ? __javaBytes(hex) : null;
  };
  java.get7zStringContent = function(url, path, charset) {
    var bytes = java.get7zByteArrayContent(url, path);
    if (!bytes) return "";
    return charset ? java.bytesToStr(bytes, charset) : __legadoHexThrow(java.__hexToAutoString(bytes.__hex || ""));
  };
  function __legadoTtfThrow(value) {
    value = String(value || "");
    if (value.indexOf("__LEGADO_TTF_ERROR__:") === 0) {
      throw new Error(value);
    }
    return value;
  }
  function __legadoTtfObject(model) {
    model = model || {};
    var unicodeToGlyph = model.unicodeToGlyph || {};
    var unicodeToGlyphId = model.unicodeToGlyphId || {};
    var glyphToUnicode = model.glyphToUnicode || {};
    return {
      unicodeToGlyph: unicodeToGlyph,
      glyphToUnicode: glyphToUnicode,
      unicodeToGlyphId: unicodeToGlyphId,
      getGlyfIdByUnicode: function(unicode) { return Number(unicodeToGlyphId[String(unicode)] || 0); },
      getGlyfByUnicode: function(unicode) {
        var value = unicodeToGlyph[String(unicode)];
        return value === undefined ? null : value;
      },
      getUnicodeByGlyf: function(glyph) { return Number(glyphToUnicode[String(glyph)] || 0); },
      isBlankUnicode: function(unicode) {
        unicode = Number(unicode);
        return unicode === 0x0009 || unicode === 0x0020 || unicode === 0x00A0 ||
               unicode === 0x2002 || unicode === 0x2003 || unicode === 0x2007 ||
               unicode === 0x200A || unicode === 0x200B || unicode === 0x200C ||
               unicode === 0x200D || unicode === 0x202F || unicode === 0x205F;
      }
    };
  }
  function __legadoEnsureTtfObject(value) {
    if (!value) return null;
    if (typeof value.getGlyfByUnicode === "function" && typeof value.getUnicodeByGlyf === "function") return value;
    return __legadoTtfObject(value);
  }
  java.queryTTF = function(data, useCache) {
    if (data === null || data === undefined) return null;
    var json = "";
    if (data && data.__javaBytesHex !== undefined) {
      json = java.__queryTTFJsonFromHex ? java.__queryTTFJsonFromHex(String(data.__javaBytesHex)) : "";
    } else if (data && data.__hex !== undefined) {
      json = java.__queryTTFJsonFromHex ? java.__queryTTFJsonFromHex(String(data.__hex)) : "";
    } else {
      json = java.__queryTTFJsonFromInput ? java.__queryTTFJsonFromInput(String(data)) : "";
    }
    json = __legadoTtfThrow(json);
    return json ? __legadoTtfObject(JSON.parse(json)) : null;
  };
  java.queryBase64TTF = function(data) { return java.queryTTF(data, true); };
  java.replaceFont = function(text, errorQueryTTF, correctQueryTTF, filter) {
    if (!errorQueryTTF || !correctQueryTTF) return String(text || "");
    errorQueryTTF = __legadoEnsureTtfObject(errorQueryTTF);
    correctQueryTTF = __legadoEnsureTtfObject(correctQueryTTF);
    var out = [];
    Array.from(String(text || "")).forEach(function(ch) {
      var oldCode = ch.codePointAt(0);
      if (errorQueryTTF.isBlankUnicode(oldCode)) {
        out.push(ch);
        return;
      }
      var glyph = errorQueryTTF.getGlyfByUnicode(oldCode);
      if (errorQueryTTF.getGlyfIdByUnicode(oldCode) === 0) glyph = null;
      if (filter && glyph === null) return;
      var code = correctQueryTTF.getUnicodeByGlyf(glyph);
      out.push(code ? String.fromCodePoint(code) : ch);
    });
    return out.join("");
  };
  java.unArchiveFile = function(zipPath) {
    zipPath = String(zipPath || "");
    if (!zipPath) return "";
    var folder = "archive/" + java.md5Encode16(zipPath);
    var lower = zipPath.toLowerCase();
    function unzip() {
      return java.__unzipTextFolder ? String(java.__unzipTextFolder(zipPath, folder)) : "";
    }
    function un7z() {
      return java.__un7zTextFolder ? String(java.__un7zTextFolder(zipPath, folder)) : "";
    }
    function unrar() {
      return java.__unrarTextFolder ? String(java.__unrarTextFolder(zipPath, folder)) : "";
    }
    function ok(value) {
      return String(value || "") === "true";
    }
    if (/\.7z(?:$|[?#])/i.test(lower)) {
      __legado7zThrow(un7z());
    } else if (/\.rar(?:$|[?#])/i.test(lower)) {
      __legadoRarThrow(unrar());
    } else if (!ok(unzip()) && !ok(un7z()) && !ok(unrar())) {
      __legadoZipThrow("__LEGADO_ZIP_ERROR__:unsupported or invalid archive");
    }
    return folder;
  };
  java.unzipFile = function(zipPath) { return java.unArchiveFile(zipPath); };
  java.un7zFile = function(zipPath) {
    zipPath = String(zipPath || "");
    if (!zipPath) return "";
    var folder = "archive/" + java.md5Encode16(zipPath);
    var ok = java.__un7zTextFolder ? String(java.__un7zTextFolder(zipPath, folder)) : "";
    ok = __legado7zThrow(ok);
    return folder;
  };
  java.unrarFile = function(zipPath) {
    zipPath = String(zipPath || "");
    if (!zipPath) return "";
    var folder = "archive/" + java.md5Encode16(zipPath);
    var ok = java.__unrarTextFolder ? String(java.__unrarTextFolder(zipPath, folder)) : "";
    ok = __legadoRarThrow(ok);
    return folder;
  };
  java.getTxtInFolder = function(path) {
    path = String(path || "");
    if (!path) return "";
    return java.__readTextFolder ? java.__readTextFolder(path) : "";
  };
}
function __javaBytes(hex) {
  var bytes = { __hex: String(hex || ""), length: Math.floor(String(hex || "").length / 2) };
  Object.defineProperty(bytes, "__javaBytesHex", {
    value: String(hex || ""),
    enumerable: false,
    writable: true
  });
  return bytes;
}
function __javaStringBytes(value) {
  return __javaBytes(java.__utf8ToHex(String(value)));
}
function __legadoCharsetThrow(value) {
  value = String(value || "");
  if (value.indexOf("__LEGADO_CHARSET_ERROR__:") === 0) {
    throw new Error(value);
  }
  return value;
}
function __legadoBase64Throw(value) {
  value = String(value || "");
  if (value.indexOf("__LEGADO_BASE64_ERROR__:") === 0) {
    throw new Error(value);
  }
  return value;
}
function __legadoHexThrow(value) {
  value = String(value || "");
  if (value.indexOf("__LEGADO_HEX_ERROR__:") === 0) {
    throw new Error(value);
  }
  return value;
}
if (typeof java.base64Decode === "function") {
  var __legadoRawBase64Decode = java.base64Decode;
  java.base64Decode = function(value, flagsOrCharset) {
    if (arguments.length >= 2) {
      return __legadoBase64Throw(__legadoRawBase64Decode(String(value || ""), flagsOrCharset));
    }
    return __legadoBase64Throw(__legadoRawBase64Decode(String(value || "")));
  };
}
if (typeof java.hexDecodeToString === "function") {
  var __legadoRawHexDecodeToString = java.hexDecodeToString;
  java.hexDecodeToString = function(value) {
    return __legadoHexThrow(__legadoRawHexDecodeToString(String(value || "")));
  };
}
java.strToBytes = function(value, charset) {
  return __javaBytes(__legadoCharsetThrow(java.__strToHex(String(value), String(charset || "UTF-8"))));
};
java.bytesToStr = function(bytes, charset) {
  if (bytes === null || bytes === undefined) return "";
  var hex = "";
  if (typeof bytes === "string") {
    hex = bytes;
  } else if (typeof bytes === "object") {
    hex = bytes.__hex !== undefined ? bytes.__hex : (bytes.__javaBytesHex !== undefined ? bytes.__javaBytesHex : "");
  }
  return __legadoHexThrow(__legadoCharsetThrow(java.__hexToString(String(hex || ""), String(charset || "UTF-8"))));
};
function __legadoUrlThrow(value) {
  value = String(value || "");
  if (value.indexOf("__LEGADO_URL_ERROR__:") === 0) {
    throw new Error(value);
  }
  return value;
}
java.toURL = function(url, baseUrl) {
  return JSON.parse(__legadoUrlThrow(java.__toUrlJson(String(url || ""), String(baseUrl || ""))));
};
java.base64DecodeToByteArray = function(value, flags) {
  if (value === null || value === undefined || String(value).trim().length === 0) return null;
  return __javaBytes(__legadoBase64Throw(java.__base64DecodeToHex(String(value), Number(flags || 0))));
};
java.hexDecodeToByteArray = function(value) {
  if (value === null || value === undefined) return null;
  var hex = String(value || "");
  __legadoHexThrow(java.__hexToString(hex, "UTF-8"));
  return __javaBytes(hex);
};
var Base64 = globalThis.Base64 || {
  DEFAULT: 0,
  NO_PADDING: 1,
  NO_WRAP: 2,
  CRLF: 4,
  URL_SAFE: 8,
  getDecoder: function() {
    return {
      decode: function(value) {
        return __javaBytes(__legadoBase64Throw(java.__base64DecodeToHex(String(value), 0)));
      }
    };
  },
  encodeToString: function(bytes, flags) {
    var hex = bytes && bytes.__hex ? bytes.__hex : "";
    return __legadoBase64Throw(java.__base64EncodeHex(String(hex || ""), Number(flags || 0)));
  }
};
globalThis.Base64 = Base64;
var Arrays = globalThis.Arrays || {
  copyOfRange: function(bytes, start, end) {
    var hex = bytes && bytes.__hex ? bytes.__hex : "";
    var safeStart = Math.max(0, Number(start) || 0);
    var safeEnd = Math.max(safeStart, Number(end) || 0);
    return __javaBytes(hex.slice(safeStart * 2, safeEnd * 2));
  }
};
function SecretKeySpec(bytes, algorithm) {
  return { bytes: bytes, algorithm: String(algorithm || "") };
}
function IvParameterSpec(bytes) {
  return bytes;
}
function __legadoBytesHex(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return java.__utf8ToHex(value);
  if (typeof value === "object") return String(value.__hex !== undefined ? value.__hex : (value.__javaBytesHex !== undefined ? value.__javaBytesHex : ""));
  return java.__utf8ToHex(String(value));
}
function ByteArrayInputStream(bytes) {
  var hex = __legadoBytesHex(bytes);
  var offset = 0;
  return {
    read: function(buffer, start, length) {
      if (arguments.length === 0 || buffer === null || buffer === undefined) {
        if (offset * 2 >= hex.length) return -1;
        var byteHex = hex.slice(offset * 2, offset * 2 + 2);
        offset += 1;
        return parseInt(byteHex || "0", 16);
      }
      var targetHex = __legadoBytesHex(buffer);
      var safeStart = Math.max(0, Number(start || 0));
      var max = Math.max(0, Number(length || (targetHex.length / 2 - safeStart)));
      var remaining = Math.max(0, hex.length / 2 - offset);
      var count = Math.min(max, remaining);
      if (count <= 0) return -1;
      var chunk = hex.slice(offset * 2, (offset + count) * 2);
      var before = targetHex.slice(0, safeStart * 2);
      var after = targetHex.slice((safeStart + count) * 2);
      buffer.__hex = buffer.__javaBytesHex = before + chunk + after;
      buffer.length = Math.floor(buffer.__hex.length / 2);
      offset += count;
      return count;
    },
    available: function() { return Math.max(0, Math.floor(hex.length / 2) - offset); },
    close: function() {}
  };
}
function ByteArrayOutputStream() {
  var hex = "";
  return {
    write: function(value) {
      if (value && typeof value === "object") {
        hex += __legadoBytesHex(value);
      } else {
        var byte = Number(value || 0) & 255;
        hex += ("0" + byte.toString(16)).slice(-2);
      }
    },
    toByteArray: function() { return __javaBytes(hex); },
    toString: function(charset) { return java.bytesToStr(__javaBytes(hex), String(charset || "UTF-8")); },
    size: function() { return Math.floor(hex.length / 2); },
    reset: function() { hex = ""; },
    close: function() {}
  };
}
if (!String.prototype.getBytes) {
  Object.defineProperty(String.prototype, "getBytes", {
    enumerable: false,
    value: function(charset) { return java.strToBytes(String(this), String(charset || "UTF-8")); }
  });
}
var URLEncoder = globalThis.URLEncoder || {
  encode: function(value, charset) {
    return java.encodeURI(String(value || ""), String(charset || "UTF-8"));
  }
};
var DatatypeConverter = globalThis.DatatypeConverter || {
  printBase64Binary: function(bytes) { return Base64.encodeToString(bytes, Base64.NO_WRAP); },
  parseBase64Binary: function(value) { return Base64.getDecoder().decode(value); }
};
var Mac = globalThis.Mac || {
  getInstance: function(name) {
    var algorithm = String(name || "");
    return {
      key: null,
      init: function(keySpec) { this.key = keySpec; },
      doFinal: function(data) {
        var key = this.key && this.key.bytes ? java.bytesToStr(this.key.bytes, "UTF-8") : "";
        var text = java.bytesToStr(data, "UTF-8");
        return java.base64DecodeToByteArray(java.HMacBase64(text, algorithm, key), Base64.DEFAULT);
      }
    };
  }
};
globalThis.URLEncoder = URLEncoder;
globalThis.DatatypeConverter = DatatypeConverter;
globalThis.Mac = Mac;
globalThis.SecretKeySpec = SecretKeySpec;
globalThis.IvParameterSpec = IvParameterSpec;
if (!Packages.java) Packages.java = {};
if (!Packages.java.net) Packages.java.net = {};
if (!Packages.java.lang) Packages.java.lang = {};
if (!Packages.java.io) Packages.java.io = {};
if (!Packages.android) Packages.android = {};
if (!Packages.android.util) Packages.android.util = {};
if (!Packages.javax) Packages.javax = {};
if (!Packages.javax.crypto) Packages.javax.crypto = {};
if (!Packages.javax.crypto.spec) Packages.javax.crypto.spec = {};
if (!Packages.javax.xml) Packages.javax.xml = {};
if (!Packages.javax.xml.bind) Packages.javax.xml.bind = {};
Packages.java.net.URLEncoder = __legadoMarkJavaImport(URLEncoder, "URLEncoder");
Packages.java.lang.String = __legadoMarkJavaImport(String, "String");
Packages.java.io.ByteArrayInputStream = __legadoMarkJavaImport(ByteArrayInputStream, "ByteArrayInputStream");
Packages.java.io.ByteArrayOutputStream = __legadoMarkJavaImport(ByteArrayOutputStream, "ByteArrayOutputStream");
Packages.android.util.Base64 = __legadoMarkJavaImport(Base64, "Base64");
Packages.javax.crypto.Mac = __legadoMarkJavaImport(Mac, "Mac");
Packages.javax.crypto.spec.SecretKeySpec = __legadoMarkJavaImport(SecretKeySpec, "SecretKeySpec");
Packages.javax.xml.bind.DatatypeConverter = __legadoMarkJavaImport(DatatypeConverter, "DatatypeConverter");
Packages.javax.crypto.spec.IvParameterSpec = __legadoMarkJavaImport(IvParameterSpec, "IvParameterSpec");
function __legadoUnsupportedPackageError(path) {
  var message = "Unsupported Android/JVM package API: " + String(path || "Packages");
  try {
    if (typeof java !== "undefined" && typeof java.log === "function") java.log(message);
  } catch (e) {}
  throw new Error("__LEGADO_UNSUPPORTED_HOST_API__:" + message);
}
function __legadoUnsupportedPackage(path) {
  var fn = function() { return __legadoUnsupportedPackageError(path); };
  return new Proxy(fn, {
    get: function(_target, prop) {
      if (prop === "__legadoUnsupportedPackage") return true;
      if (prop === "toString") return function() { return "[unsupported " + path + "]"; };
      if (typeof prop === "symbol") return undefined;
      return __legadoUnsupportedPackage(path + "." + String(prop));
    },
    apply: function() { return __legadoUnsupportedPackageError(path); },
    construct: function() { return __legadoUnsupportedPackageError(path); }
  });
}
function __legadoPackageNamespace(path, object) {
  return new Proxy(object || {}, {
    get: function(target, prop) {
      if (prop in target) return target[prop];
      if (typeof prop === "symbol") return undefined;
      return __legadoUnsupportedPackage(path + "." + String(prop));
    }
  });
}
Packages.android = __legadoPackageNamespace("Packages.android", Packages.android || {});
var Cipher = globalThis.Cipher || {
  getInstance: function(name) {
    return {
      name: String(name || ""),
      init: function(mode, key, iv) {
        this.mode = mode;
        this.key = key;
        this.iv = iv;
      },
      doFinal: function(data) {
        return __legadoCryptoThrow(java.__aesCbcPkcs5DecryptHex(
          data && data.__hex ? data.__hex : "",
          this.key && this.key.bytes && this.key.bytes.__hex ? this.key.bytes.__hex : "",
          this.iv && this.iv.__hex ? this.iv.__hex : ""
        ));
      }
    };
  }
};
globalThis.Cipher = Cipher;
Packages.javax.crypto.Cipher = __legadoMarkJavaImport(Cipher, "Cipher");
function __legadoJsonPathTokens(path) {
  path = String(path || "$");
  if (path === "$") return [];
  if (path.charAt(0) === "$") path = path.slice(1);
  var tokens = [];
  var index = 0;
  while (index < path.length) {
    if (path.slice(index, index + 2) === "..") {
      index += 2;
      var recursive = "";
      while (index < path.length && path.charAt(index) !== "." && path.charAt(index) !== "[") {
        recursive += path.charAt(index++);
      }
      if (recursive) tokens.push({ type: "recursive", key: recursive });
      continue;
    }
    if (path.charAt(index) === ".") {
      index++;
      var key = "";
      while (index < path.length && path.charAt(index) !== "." && path.charAt(index) !== "[") {
        key += path.charAt(index++);
      }
      if (key) tokens.push({ type: "key", key: key });
      continue;
    }
    if (path.charAt(index) === "[") {
      var close = path.indexOf("]", index);
      if (close < 0) throw new Error("invalid JSONPath: " + path);
      var inner = path.slice(index + 1, close);
      if (inner === "*") tokens.push({ type: "wildcard" });
      else if (/^\?\([\s\S]*\)$/.test(inner)) tokens.push({ type: "filter", expr: inner.slice(2, -1) });
      else if (/^-?\d*:-?\d*(?::-?\d+)?$/.test(inner)) tokens.push({ type: "slice", expr: inner });
      else if (inner.indexOf(",") >= 0) {
        tokens.push({
          type: "union",
          items: inner.split(/\s*,\s*/).map(function(item) {
            item = String(item || "").trim();
            return /^-?\d+$/.test(item)
              ? { type: "index", index: Number(item) }
              : { type: "key", key: item.replace(/^['"]|['"]$/g, "") };
          })
        });
      }
      else if (/^-?\d+$/.test(inner)) tokens.push({ type: "index", index: Number(inner) });
      else tokens.push({ type: "key", key: inner.replace(/^['"]|['"]$/g, "") });
      index = close + 1;
      var tailKey = "";
      while (index < path.length && path.charAt(index) !== "." && path.charAt(index) !== "[") {
        tailKey += path.charAt(index++);
      }
      if (tailKey) tokens.push({ type: "key", key: tailKey });
      continue;
    }
    index++;
  }
  return tokens;
}
function __legadoJsonPathField(item, path) {
  var current = item;
  String(path || "").split(".").forEach(function(part) {
    if (!part) return;
    current = current === null || typeof current === "undefined" ? undefined : current[part];
  });
  return current;
}
function __legadoJsonPathFilterValue(raw) {
  raw = String(raw || "").trim();
  if (/^['"][\s\S]*['"]$/.test(raw)) return raw.slice(1, -1);
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (raw === "null") return null;
  return raw;
}
function __legadoJsonPathCompare(left, op, right) {
  if (op === "==") return String(left) === String(right);
  if (op === "!=") return String(left) !== String(right);
  if (op === ">") return Number(left) > Number(right);
  if (op === ">=") return Number(left) >= Number(right);
  if (op === "<") return Number(left) < Number(right);
  if (op === "<=") return Number(left) <= Number(right);
  return false;
}
function __legadoJsonPathFilter(item, expr) {
  expr = String(expr || "").trim();
  if (!expr) return true;
  var parts = expr.split(/\s*&&\s*/);
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i].trim();
    var exists = /^@\.(.+)$/.exec(part);
    var regex = /^@\.(.+?)\s*=~\s*\/([\s\S]*)\/([a-z]*)$/.exec(part);
    var cmp = /^@\.(.+?)\s*(==|!=|>=|<=|>|<)\s*([\s\S]+)$/.exec(part);
    if (regex) {
      if (!new RegExp(regex[2], regex[3]).test(String(__legadoJsonPathField(item, regex[1]) || ""))) return false;
    } else if (cmp) {
      if (!__legadoJsonPathCompare(__legadoJsonPathField(item, cmp[1]), cmp[2], __legadoJsonPathFilterValue(cmp[3]))) return false;
    } else if (exists) {
      var value = __legadoJsonPathField(item, exists[1]);
      if (value === null || typeof value === "undefined" || value === false) return false;
    } else {
      throw new Error("unsupported JSONPath filter: " + expr);
    }
  }
  return true;
}
function __legadoJsonPathDescendants(value, key, out) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (var i = 0; i < value.length; i++) __legadoJsonPathDescendants(value[i], key, out);
    return;
  }
  Object.keys(value).forEach(function(name) {
    if (name === key) out.push(value[name]);
    __legadoJsonPathDescendants(value[name], key, out);
  });
}
function __legadoJsonPathValues(value, tokens) {
  var current = [value];
  tokens.forEach(function(token) {
    var next = [];
    current.forEach(function(item) {
      if (token.type === "key") {
        if (item && typeof item === "object" && Object.prototype.hasOwnProperty.call(item, token.key)) next.push(item[token.key]);
      } else if (token.type === "wildcard") {
        if (Array.isArray(item)) next = next.concat(item);
        else if (item && typeof item === "object") Object.keys(item).forEach(function(key) { next.push(item[key]); });
      } else if (token.type === "index") {
        if (Array.isArray(item)) {
          var idx = token.index < 0 ? item.length + token.index : token.index;
          if (idx >= 0 && idx < item.length) next.push(item[idx]);
        }
      } else if (token.type === "union") {
        token.items.forEach(function(entry) {
          if (entry.type === "index" && Array.isArray(item)) {
            var idx = entry.index < 0 ? item.length + entry.index : entry.index;
            if (idx >= 0 && idx < item.length) next.push(item[idx]);
          } else if (entry.type === "key" && item && typeof item === "object" && Object.prototype.hasOwnProperty.call(item, entry.key)) {
            next.push(item[entry.key]);
          }
        });
      } else if (token.type === "slice") {
        if (Array.isArray(item)) {
          var bits = token.expr.split(":");
          var start = bits[0] === "" ? 0 : Number(bits[0]);
          var end = bits[1] === "" ? item.length : Number(bits[1]);
          var step = bits[2] === undefined || bits[2] === "" ? 1 : Number(bits[2]);
          if (start < 0) start = item.length + start;
          if (end < 0) end = item.length + end;
          step = step || 1;
          for (var i = Math.max(0, start); step > 0 ? i < Math.min(item.length, end) : i > Math.max(-1, end); i += step) next.push(item[i]);
        }
      } else if (token.type === "filter") {
        if (Array.isArray(item)) {
          item.forEach(function(child) { if (__legadoJsonPathFilter(child, token.expr)) next.push(child); });
        }
      } else if (token.type === "recursive") {
        __legadoJsonPathDescendants(item, token.key, next);
      }
    });
    current = next;
  });
  return current;
}
function __legadoJsonPathRead(value, path, suppress) {
  if (typeof value === "string") value = JSON.parse(value || "null");
  var tokens = __legadoJsonPathTokens(path);
  var values = __legadoJsonPathValues(value, tokens);
  if (values.length === 0) {
    if (suppress) return [];
    throw new Error("JSONPath returned no match: " + path);
  }
  var multi = tokens.some(function(token) { return token.type === "wildcard" || token.type === "recursive" || token.type === "union" || token.type === "slice" || token.type === "filter"; });
  return multi ? values : values[0];
}
var Option = globalThis.Option || {
  SUPPRESS_EXCEPTIONS: "SUPPRESS_EXCEPTIONS"
};
var Configuration = globalThis.Configuration || {
  builder: function() {
    var suppress = false;
    return {
      options: function() {
        for (var i = 0; i < arguments.length; i++) {
          if (arguments[i] === Option.SUPPRESS_EXCEPTIONS) suppress = true;
        }
        return this;
      },
      build: function() { return { suppressExceptions: suppress }; }
    };
  }
};
var JsonPath = globalThis.JsonPath || {
  read: function(value, path) { return __legadoJsonPathRead(value, path, false); },
  parse: function(value) { return JsonPath.using(Configuration.builder().build()).parse(value); },
  using: function(configuration) {
    var suppress = !!(configuration && configuration.suppressExceptions);
    return {
      parse: function(value) {
        var parsed = typeof value === "string" ? JSON.parse(value || "null") : value;
        return {
          read: function(path) { return __legadoJsonPathRead(parsed, path, suppress); }
        };
      }
    };
  }
};
globalThis.Option = Option;
globalThis.Configuration = Configuration;
globalThis.JsonPath = JsonPath;
if (typeof globalThis.com === "undefined") globalThis.com = {};
if (!com.jayway) com.jayway = {};
if (!com.jayway.jsonpath) com.jayway.jsonpath = {};
com.jayway.jsonpath.JsonPath = JsonPath;
com.jayway.jsonpath.Configuration = Configuration;
com.jayway.jsonpath.Option = Option;
if (!Packages.com) Packages.com = {};
if (!Packages.com.jayway) Packages.com.jayway = {};
Packages.com.jayway.jsonpath = com.jayway.jsonpath;
"#;

const RHINO_COMPAT_POSTLUDE: &str = r#""#;

fn value_to_string<'js>(ctx: rquickjs::Ctx<'js>, value: rquickjs::Value<'js>) -> Result<String> {
    if value.is_null() || value.is_undefined() {
        return Ok(String::new());
    }
    if value.is_string() {
        let s = String::from_js(&ctx, value.clone()).map_err(to_js_diag)?;
        return Ok(s);
    }
    if let Ok(object) = rquickjs::Object::from_js(&ctx, value.clone()) {
        if let Ok(func) = object.get::<_, rquickjs::Function>("__legadoResponseJson") {
            let json: String = func.call(()).map_err(to_js_diag)?;
            return Ok(format!("__LEGADO_STR_RESPONSE_JSON__{json}"));
        }
        if let Some(json) = ctx.json_stringify(value.clone()).map_err(to_js_diag)? {
            let json = json.to_string().unwrap_or_default();
            if json != "null" {
                return Ok(format!("__LEGADO_JSON_VALUE__{json}"));
            }
        }
    }
    let json = ctx
        .json_stringify(value)
        .map_err(to_js_diag)?
        .map(|s| s.to_string().unwrap_or_default())
        .unwrap_or_else(|| json!(null).to_string());
    Ok(json)
}

fn coerced_arg(args: &[Coerced<String>], index: usize) -> String {
    args.get(index)
        .map(|value| value.0.clone())
        .unwrap_or_default()
}

const ANDROID_BASE64_DEFAULT: i32 = 0;
const ANDROID_BASE64_NO_PADDING: i32 = 1;
const ANDROID_BASE64_NO_WRAP: i32 = 2;
const ANDROID_BASE64_CRLF: i32 = 4;
const ANDROID_BASE64_URL_SAFE: i32 = 8;

fn decode_base64_string(input: &str, charset: Option<&str>, flags: i32) -> String {
    let bytes = match android_base64_decode(input, flags) {
        Ok(bytes) => bytes,
        Err(err) => return format!("__LEGADO_BASE64_ERROR__:{input}:{err}"),
    };
    let Some(charset) = charset.filter(|value| !value.trim().is_empty()) else {
        return String::from_utf8_lossy(&bytes).into_owned();
    };
    let Some(encoding) = encoding_rs::Encoding::for_label(charset.trim().as_bytes()) else {
        return String::from_utf8_lossy(&bytes).into_owned();
    };
    let (decoded, _, _) = encoding.decode(&bytes);
    decoded.into_owned()
}

fn android_base64_encode(bytes: &[u8], flags: i32) -> String {
    let encoded = match (
        flags & ANDROID_BASE64_URL_SAFE != 0,
        flags & ANDROID_BASE64_NO_PADDING != 0,
    ) {
        (true, true) => base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
        (true, false) => base64::engine::general_purpose::URL_SAFE.encode(bytes),
        (false, true) => base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes),
        (false, false) => base64::engine::general_purpose::STANDARD.encode(bytes),
    };
    if flags & ANDROID_BASE64_NO_WRAP != 0 || encoded.len() <= 76 {
        if flags & ANDROID_BASE64_NO_WRAP != 0 {
            encoded
        } else {
            format!("{encoded}{}", android_base64_line_separator(flags))
        }
    } else {
        let line_separator = android_base64_line_separator(flags);
        let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 76 + 2);
        for chunk in encoded.as_bytes().chunks(76) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            wrapped.push_str(line_separator);
        }
        wrapped
    }
}

fn android_base64_line_separator(flags: i32) -> &'static str {
    if flags & ANDROID_BASE64_CRLF != 0 {
        "\r\n"
    } else {
        "\n"
    }
}

fn android_base64_decode(
    input: &str,
    flags: i32,
) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    let normalized = input
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    match (
        flags & ANDROID_BASE64_URL_SAFE != 0,
        flags & ANDROID_BASE64_NO_PADDING != 0,
    ) {
        (true, true) => base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(normalized),
        (true, false) => base64::engine::general_purpose::URL_SAFE.decode(normalized),
        (false, true) => base64::engine::general_purpose::STANDARD_NO_PAD.decode(normalized),
        (false, false) => base64::engine::general_purpose::STANDARD.decode(normalized),
    }
}

fn encode_string_to_hex(input: &str, charset: &str) -> String {
    let Some(encoding) = encoding_rs::Encoding::for_label(charset.trim().as_bytes()) else {
        return format!("__LEGADO_CHARSET_ERROR__:unsupported charset `{charset}`");
    };
    let (bytes, _, _) = encoding.encode(input);
    hex::encode(bytes.as_ref())
}

fn decode_hex_to_string(input: &str, charset: &str) -> String {
    let Some(encoding) = encoding_rs::Encoding::for_label(charset.trim().as_bytes()) else {
        return format!("__LEGADO_CHARSET_ERROR__:unsupported charset `{charset}`");
    };
    let bytes = match hex::decode(input.trim()) {
        Ok(bytes) => bytes,
        Err(err) => return format!("__LEGADO_HEX_ERROR__:{input}:{err}"),
    };
    let (decoded, _, _) = encoding.decode(&bytes);
    decoded.into_owned()
}

fn decode_bytes_to_string(bytes: &[u8], charset: &str) -> String {
    let Some(encoding) = encoding_rs::Encoding::for_label(charset.trim().as_bytes()) else {
        return format!("__LEGADO_CHARSET_ERROR__:unsupported charset `{charset}`");
    };
    let (decoded, _, _) = encoding.decode(bytes);
    decoded.into_owned()
}

fn decode_bytes_auto_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned();
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let (decoded, _, _) = encoding_rs::UTF_16LE.decode(&bytes[2..]);
        return decoded.into_owned();
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let (decoded, _, _) = encoding_rs::UTF_16BE.decode(&bytes[2..]);
        return decoded.into_owned();
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    for label in ["GBK", "Big5", "Shift_JIS", "EUC-KR"] {
        let Some(encoding) = encoding_rs::Encoding::for_label(label.as_bytes()) else {
            continue;
        };
        let (decoded, _, had_errors) = encoding.decode(bytes);
        if !had_errors {
            return decoded.into_owned();
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn zip_entry_hex(bytes: &[u8], path: &str) -> std::result::Result<String, String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|err| err.to_string())?;
    let mut file = archive.by_name(path).map_err(|err| err.to_string())?;
    let mut out = Vec::new();
    file.read_to_end(&mut out).map_err(|err| err.to_string())?;
    Ok(hex::encode(out))
}

fn zip_all_text(bytes: &[u8]) -> std::result::Result<String, String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|err| err.to_string())?;
    let mut parts = Vec::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).map_err(|err| err.to_string())?;
        if file.is_dir() {
            continue;
        }
        let mut out = Vec::new();
        file.read_to_end(&mut out).map_err(|err| err.to_string())?;
        parts.push(decode_bytes_auto_string(&out));
    }
    Ok(parts.join("\n"))
}

fn sevenz_entry_hex(bytes: &[u8], path: &str) -> std::result::Result<String, String> {
    let mut reader =
        sevenz_rust2::ArchiveReader::new(Cursor::new(bytes), sevenz_rust2::Password::empty())
            .map_err(|err| err.to_string())?;
    reader
        .read_file(path)
        .map(hex::encode)
        .map_err(|err| match err {
            sevenz_rust2::Error::FileNotFound => "specified file not found in archive".to_string(),
            other => other.to_string(),
        })
}

fn sevenz_all_text(bytes: &[u8]) -> std::result::Result<String, String> {
    let mut reader =
        sevenz_rust2::ArchiveReader::new(Cursor::new(bytes), sevenz_rust2::Password::empty())
            .map_err(|err| err.to_string())?;
    let mut parts = Vec::new();
    reader
        .for_each_entries(|entry, entry_reader| {
            if entry.is_directory() {
                return Ok(true);
            }
            let mut out = Vec::new();
            entry_reader
                .read_to_end(&mut out)
                .map_err(sevenz_rust2::Error::from)?;
            parts.push(decode_bytes_auto_string(&out));
            Ok(true)
        })
        .map_err(|err| err.to_string())?;
    Ok(parts.join("\n"))
}

fn rar_entry_hex(bytes: &[u8], path: &str) -> std::result::Result<String, String> {
    let extracted = extract_rar_to_temp(bytes)?;
    let target = safe_join(&extracted.out_dir, path)?;
    let out = if target.is_file() {
        fs::read(&target).map_err(|err| err.to_string())?
    } else {
        let _ = fs::remove_dir_all(&extracted.root);
        return Err("specified file not found in archive".to_string());
    };
    let _ = fs::remove_dir_all(&extracted.root);
    Ok(hex::encode(out))
}

fn rar_all_text(bytes: &[u8]) -> std::result::Result<String, String> {
    let extracted = extract_rar_to_temp(bytes)?;
    let mut parts = Vec::new();
    for name in &extracted.file_names {
        let path = safe_join(&extracted.out_dir, name)?;
        if path.is_file() {
            let bytes = fs::read(&path).map_err(|err| err.to_string())?;
            parts.push(decode_bytes_auto_string(&bytes));
        }
    }
    let _ = fs::remove_dir_all(&extracted.root);
    Ok(parts.join("\n"))
}

struct ExtractedRar {
    root: PathBuf,
    out_dir: PathBuf,
    file_names: Vec<String>,
}

fn extract_rar_to_temp(bytes: &[u8]) -> std::result::Result<ExtractedRar, String> {
    let root = std::env::temp_dir().join(format!("legado-rar-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).map_err(|err| err.to_string())?;
    let archive_path = root.join("archive.rar");
    let mut archive_file = fs::File::create(&archive_path).map_err(|err| err.to_string())?;
    archive_file
        .write_all(bytes)
        .map_err(|err| err.to_string())?;
    archive_file.flush().map_err(|err| err.to_string())?;
    drop(archive_file);
    let out_dir = root.join("out");
    fs::create_dir_all(&out_dir).map_err(|err| err.to_string())?;
    let archive = rar::Archive::extract_all(path_str(&archive_path)?, path_str(&out_dir)?, "")
        .map_err(|err| err.to_string())?;
    let names = archive.files.into_iter().map(|file| file.name).collect();
    Ok(ExtractedRar {
        root,
        out_dir,
        file_names: names,
    })
}

fn path_str(path: &Path) -> std::result::Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn safe_join(root: &Path, entry: &str) -> std::result::Result<PathBuf, String> {
    let candidate = root.join(entry);
    if !candidate.exists() {
        return Err("specified file not found in archive".to_string());
    }
    let canonical_root = root.canonicalize().map_err(|err| err.to_string())?;
    let canonical = candidate.canonicalize().map_err(|err| err.to_string())?;
    if canonical.starts_with(&canonical_root) {
        Ok(canonical)
    } else {
        Err(format!("archive entry escapes extraction root: {entry}"))
    }
}

#[derive(Default)]
struct GlyphOutline {
    parts: Vec<String>,
}

impl ttf_parser::OutlineBuilder for GlyphOutline {
    fn move_to(&mut self, x: f32, y: f32) {
        self.parts.push(format!("M{},{}", ttf_num(x), ttf_num(y)));
    }

    fn line_to(&mut self, x: f32, y: f32) {
        self.parts.push(format!("L{},{}", ttf_num(x), ttf_num(y)));
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        self.parts.push(format!(
            "Q{},{}:{},{}",
            ttf_num(x1),
            ttf_num(y1),
            ttf_num(x),
            ttf_num(y)
        ));
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        self.parts.push(format!(
            "C{},{}:{},{}:{},{}",
            ttf_num(x1),
            ttf_num(y1),
            ttf_num(x2),
            ttf_num(y2),
            ttf_num(x),
            ttf_num(y)
        ));
    }

    fn close(&mut self) {
        self.parts.push("Z".to_string());
    }
}

fn ttf_num(value: f32) -> String {
    if value.fract().abs() < 0.0001 {
        format!("{}", value as i32)
    } else {
        format!("{value:.4}")
    }
}

fn query_ttf_json(bytes: &[u8]) -> std::result::Result<String, String> {
    let face = ttf_parser::Face::parse(bytes, 0).map_err(|err| err.to_string())?;
    let Some(cmap) = face.tables().cmap else {
        return Err("font cmap table not found".to_string());
    };
    let mut unicode_to_glyph = serde_json::Map::new();
    let mut unicode_to_glyph_id = serde_json::Map::new();
    let mut glyph_to_unicode = serde_json::Map::new();
    for subtable in cmap.subtables {
        subtable.codepoints(|code| {
            let Some(ch) = char::from_u32(code) else {
                return;
            };
            let Some(glyph_id) = face.glyph_index(ch) else {
                return;
            };
            unicode_to_glyph_id.insert(code.to_string(), json!(glyph_id.0));
            if glyph_id.0 == 0 {
                return;
            }
            let mut outline = GlyphOutline::default();
            if face.outline_glyph(glyph_id, &mut outline).is_none() || outline.parts.is_empty() {
                return;
            }
            let glyph = outline.parts.join("|");
            unicode_to_glyph.insert(code.to_string(), json!(glyph));
            glyph_to_unicode.entry(glyph).or_insert_with(|| json!(code));
        });
    }
    serde_json::to_string(&json!({
        "unicodeToGlyph": unicode_to_glyph,
        "unicodeToGlyphId": unicode_to_glyph_id,
        "glyphToUnicode": glyph_to_unicode,
    }))
    .map_err(|err| err.to_string())
}

fn session_file_bytes(session: &AnalyzerSession, path: &str) -> Option<Vec<u8>> {
    let byte_key = format!("file-bytes:{path}");
    if let Some(bytes_hex) = session
        .cache
        .get(&byte_key)
        .cloned()
        .or_else(|| persistent_get_cache(&byte_key).ok().flatten())
    {
        return hex::decode(bytes_hex.trim()).ok();
    }
    let text_key = format!("file:{path}");
    session
        .cache
        .get(&text_key)
        .cloned()
        .or_else(|| persistent_get_cache(&text_key).ok().flatten())
        .map(|text| text.into_bytes())
}

fn session_file_exists(session: &AnalyzerSession, path: &str) -> bool {
    ["file-bytes:", "file:"].iter().any(|prefix| {
        let key = format!("{prefix}{path}");
        session.cache.contains_key(&key) || persistent_get_cache(&key).ok().flatten().is_some()
    })
}

fn to_num_chapter(input: &str) -> String {
    let Some(start) = input.find('第') else {
        return input.to_string();
    };
    let after_start = start + '第'.len_utf8();
    let Some(relative_end) = input[after_start..].find('章') else {
        return input.to_string();
    };
    let end = after_start + relative_end;
    let number = string_to_int_like_android(&input[after_start..end]);
    format!("第{number}章")
}

fn string_to_int_like_android(input: &str) -> i32 {
    let normalized = full_to_half(input)
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    normalized
        .parse::<i32>()
        .unwrap_or_else(|_| chinese_num_to_int_like_android(&normalized))
}

fn full_to_half(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch as u32 {
            12288 => ' ',
            65281..=65374 => char::from_u32(ch as u32 - 65248).unwrap_or(ch),
            _ => ch,
        })
        .collect()
}

fn chinese_num_to_int_like_android(input: &str) -> i32 {
    let chars = input.chars().collect::<Vec<_>>();
    if chars.len() > 1
        && chars
            .iter()
            .all(|ch| matches!(chinese_num_value(*ch), Some(0..=9)))
    {
        let digits = chars
            .iter()
            .filter_map(|ch| chinese_num_value(*ch))
            .map(|value| char::from_digit(value as u32, 10).unwrap_or('0'))
            .collect::<String>();
        return digits.parse::<i32>().unwrap_or(-1);
    }

    let mut result = 0i32;
    let mut tmp = 0i32;
    let mut billion = 0i32;
    for (index, ch) in chars.iter().enumerate() {
        let Some(tmp_num) = chinese_num_value(*ch) else {
            return -1;
        };
        match tmp_num {
            100_000_000 => {
                result += tmp;
                result *= tmp_num;
                billion = billion * 100_000_000 + result;
                result = 0;
                tmp = 0;
            }
            10_000 => {
                result += tmp;
                result *= tmp_num;
                tmp = 0;
            }
            10.. => {
                if tmp == 0 {
                    tmp = 1;
                }
                result += tmp_num * tmp;
                tmp = 0;
            }
            _ => {
                tmp = if index >= 2 && index == chars.len() - 1 {
                    let previous = chinese_num_value(chars[index - 1]).unwrap_or(0);
                    if previous > 10 {
                        tmp_num * previous / 10
                    } else {
                        tmp * 10 + tmp_num
                    }
                } else {
                    tmp * 10 + tmp_num
                };
            }
        }
    }
    result + tmp + billion
}

fn chinese_num_value(ch: char) -> Option<i32> {
    match ch {
        '零' | '〇' => Some(0),
        '一' | '壹' => Some(1),
        '二' | '贰' | '两' => Some(2),
        '三' | '叁' => Some(3),
        '四' | '肆' => Some(4),
        '五' | '伍' => Some(5),
        '六' | '陆' => Some(6),
        '七' | '柒' => Some(7),
        '八' | '捌' => Some(8),
        '九' | '玖' => Some(9),
        '十' | '拾' => Some(10),
        '百' | '佰' => Some(100),
        '千' | '仟' => Some(1000),
        '万' => Some(10_000),
        '亿' => Some(100_000_000),
        _ => None,
    }
}

fn js_url_json(input: &str, base_url: &str) -> String {
    let parsed = if base_url.trim().is_empty() {
        url::Url::parse(input)
    } else {
        url::Url::parse(base_url).and_then(|base| base.join(input))
    };
    let Ok(parsed) = parsed else {
        return format!("__LEGADO_URL_ERROR__:invalid URL `{input}` with base `{base_url}`");
    };
    let Some(host) = parsed.host_str() else {
        return format!("__LEGADO_URL_ERROR__:URL has no host `{input}`");
    };
    let origin = if let Some(port) = parsed.port() {
        format!("{}://{}:{}", parsed.scheme(), host, port)
    } else {
        format!("{}://{}", parsed.scheme(), host)
    };
    let search_params = parsed.query().map(|query| {
        let mut params = serde_json::Map::new();
        for entry in query.split('&') {
            let mut parts = entry.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let Some(value) = parts.next() else {
                continue;
            };
            params.insert(
                key.to_string(),
                serde_json::Value::String(java_url_decode(value)),
            );
        }
        serde_json::Value::Object(params)
    });
    json!({
        "href": parsed.as_str(),
        "host": host,
        "origin": origin,
        "pathname": parsed.path(),
        "search": parsed.query().map(|query| format!("?{query}")).unwrap_or_default(),
        "searchParams": search_params,
    })
    .to_string()
}

fn java_url_decode(input: &str) -> String {
    let plus_as_space = input.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_as_space)
        .decode_utf8_lossy()
        .into_owned()
}

fn java_url_encode(input: &str, charset: &str) -> String {
    let Some(encoding) = encoding_rs::Encoding::for_label(charset.trim().as_bytes()) else {
        return String::new();
    };
    let (bytes, _, _) = encoding.encode(input);
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes.as_ref() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                output.push(*byte as char)
            }
            b' ' => output.push('+'),
            other => output.push_str(&format!("%{other:02X}")),
        }
    }
    output
}

fn java_time_format_utc(millis: i64, pattern: &str, offset_millis: i32) -> String {
    let offset_seconds = offset_millis / 1000;
    let Some(offset) = FixedOffset::east_opt(offset_seconds) else {
        return String::new();
    };
    let Some(time) = offset.timestamp_millis_opt(millis).single() else {
        return String::new();
    };
    format_java_simple_date(time, pattern)
}

fn format_java_simple_date(time: chrono::DateTime<FixedOffset>, pattern: &str) -> String {
    let mut output = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                output.push('\'');
                continue;
            }
            for quoted in chars.by_ref() {
                if quoted == '\'' {
                    break;
                }
                output.push(quoted);
            }
            continue;
        }

        if !ch.is_ascii_alphabetic() {
            output.push(ch);
            continue;
        }

        let mut count = 1usize;
        while chars.peek() == Some(&ch) {
            chars.next();
            count += 1;
        }
        append_java_date_field(&mut output, time, ch, count);
    }
    output
}

fn append_java_date_field(
    output: &mut String,
    time: chrono::DateTime<FixedOffset>,
    field: char,
    count: usize,
) {
    match field {
        'y' => {
            if count == 2 {
                output.push_str(&format!("{:02}", time.year().rem_euclid(100)));
            } else {
                output.push_str(&format!("{:0width$}", time.year(), width = count.max(4)));
            }
        }
        'M' => {
            let month = time.month();
            if count >= 4 {
                output.push_str(MONTH_NAMES[(month - 1) as usize]);
            } else if count == 3 {
                output.push_str(MONTH_SHORT_NAMES[(month - 1) as usize]);
            } else if count == 2 {
                output.push_str(&format!("{month:02}"));
            } else {
                output.push_str(&month.to_string());
            }
        }
        'd' => append_number(output, time.day(), count),
        'H' => append_number(output, time.hour(), count),
        'k' => append_number(
            output,
            if time.hour() == 0 { 24 } else { time.hour() },
            count,
        ),
        'K' => append_number(output, time.hour() % 12, count),
        'h' => append_number(
            output,
            {
                let hour = time.hour() % 12;
                if hour == 0 {
                    12
                } else {
                    hour
                }
            },
            count,
        ),
        'm' => append_number(output, time.minute(), count),
        's' => append_number(output, time.second(), count),
        'S' => {
            let millis = time.nanosecond() / 1_000_000;
            let value = format!("{millis:03}");
            if count <= 3 {
                output.push_str(&value[..count]);
            } else {
                output.push_str(&value);
                for _ in 3..count {
                    output.push('0');
                }
            }
        }
        'E' => {
            let index = time.weekday().num_days_from_sunday() as usize;
            output.push_str(if count >= 4 {
                WEEKDAY_NAMES[index]
            } else {
                WEEKDAY_SHORT_NAMES[index]
            });
        }
        'a' => output.push_str(if time.hour() < 12 { "AM" } else { "PM" }),
        'Z' => {
            let seconds = time.offset().local_minus_utc();
            let sign = if seconds < 0 { '-' } else { '+' };
            let seconds = seconds.abs();
            output.push_str(&format!(
                "{sign}{:02}{:02}",
                seconds / 3600,
                (seconds % 3600) / 60
            ));
        }
        _ => {
            for _ in 0..count {
                output.push(field);
            }
        }
    }
}

fn append_number(output: &mut String, value: u32, count: usize) {
    if count >= 2 {
        output.push_str(&format!("{value:0width$}", width = count));
    } else {
        output.push_str(&value.to_string());
    }
}

const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const MONTH_SHORT_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAY_NAMES: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const WEEKDAY_SHORT_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

fn set_result_global<'js>(
    ctx: rquickjs::Ctx<'js>,
    globals: &rquickjs::Object<'js>,
    result: &str,
) -> Result<()> {
    if let Some(result) = result.strip_prefix(FORCED_STRING_RESULT_PREFIX) {
        globals.set("result", result).map_err(to_js_diag)?;
        return Ok(());
    }
    let parsed = serde_json::from_str::<serde_json::Value>(result).ok();
    if parsed.as_ref().is_some_and(|value| {
        value
            .as_object()
            .and_then(|object| object.get("__strResponse"))
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    }) {
        let raw = serde_json::to_string(result).unwrap_or_else(|_| "\"{}\"".to_string());
        let script =
            format!("globalThis.result = java.__strResponse(JSON.parse({raw} || \"{{}}\"));");
        ctx.eval::<(), _>(script)
            .catch(&ctx)
            .map_err(js_caught_to_diag)?;
        return Ok(());
    }
    if let Some(hex) = parsed
        .as_ref()
        .and_then(|value| value.as_object())
        .and_then(|object| object.get("__javaBytesHex"))
        .and_then(|value| value.as_str())
    {
        let raw = serde_json::to_string(hex).unwrap_or_else(|_| "\"\"".to_string());
        let script = format!("globalThis.result = __javaBytes({raw});");
        ctx.eval::<(), _>(script)
            .catch(&ctx)
            .map_err(js_caught_to_diag)?;
        return Ok(());
    }
    if parsed
        .as_ref()
        .is_some_and(|value| value.is_object() || value.is_array())
    {
        let value = ctx.json_parse(result).map_err(to_js_diag)?;
        globals.set("result", value).map_err(to_js_diag)?;
    } else {
        globals.set("result", result).map_err(to_js_diag)?;
    }
    Ok(())
}

fn to_js_diag(err: rquickjs::Error) -> Diagnostic {
    Diagnostic::new(DiagnosticKind::JavaScript, err.to_string())
}

fn js_caught_to_diag(err: CaughtError<'_>) -> Diagnostic {
    Diagnostic::new(DiagnosticKind::JavaScript, err.to_string())
}

fn get_string_from_rule(input: &str, path: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(input) else {
        return match extract_html_rule_from_str(input, path) {
            Ok(value) => value,
            Err(err) => format!("__LEGADO_RULE_ERROR__:{err}"),
        };
    };
    let path = path.trim().trim_start_matches("$.").trim_start_matches('$');
    if path.is_empty() {
        return value_to_plain_string(&value);
    }
    let mut current = &value;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        let Some(next) = current.get(segment) else {
            return String::new();
        };
        current = next;
    }
    value_to_plain_string(current)
}

fn value_to_plain_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::PlatformHost;
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::rc::Rc;
    use std::thread;
    use std::time::Duration;

    fn source() -> BookSource {
        BookSource {
            book_source_name: "test".to_string(),
            ..BookSource::parse_first("[{}]").unwrap()
        }
    }

    #[test]
    fn evals_basic_js() {
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        assert_eq!(
            js.eval_rule_script("@js: return 1 + 2", "x", "", "", "", 1)
                .unwrap(),
            "3"
        );
    }

    #[test]
    fn eval_bindings_preserve_android_byte_array_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();

        let from_result = js
            .eval_rule_script_with_bindings(
                "@js: return result",
                "image.decode.result",
                r#"{"__javaBytesHex":"0102ff"}"#,
                "https://image.example/",
                "",
                1,
                "",
            )
            .unwrap();
        assert_eq!(
            from_result,
            r#"__LEGADO_JSON_VALUE__{"__hex":"0102ff","length":3}"#
        );

        let from_binding = js
            .eval_rule_script_with_bindings(
                "@js: return result",
                "image.decode.binding",
                "",
                "https://image.example/",
                "",
                1,
                r#"{"result":{"__javaBytesHex":"0a0b0c"}}"#,
            )
            .unwrap();
        assert_eq!(
            from_binding,
            r#"__LEGADO_JSON_VALUE__{"__hex":"0a0b0c","length":3}"#
        );
    }

    #[test]
    fn eval_bindings_wrap_info_map_like_android_mutable_map() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script_with_bindings(
                r#"<js>
                var before = infoMap.get('seen');
                var had = infoMap.containsKey('seen');
                infoMap.put('seen', 'new');
                infoMap.putAll({extra: 7});
                var removed = infoMap.remove('missing');
                [before, had, infoMap.get('seen'), infoMap.get('extra'), removed === null].join('|');
                </js>"#,
                "bindings.infoMap",
                "",
                "https://example.test/",
                "",
                1,
                r#"{"infoMap":{"seen":"old"}}"#,
            )
            .unwrap();
        assert_eq!(out, "old|true|new|7|true");
    }

    #[test]
    fn eval_bindings_expose_scalar_android_globals() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script_with_bindings(
                "<js>[src, nextChapterUrl, fromBookInfo].join('|')</js>",
                "bindings.scalars",
                "",
                "https://example.test/",
                "",
                1,
                r#"{"src":"https://img.example/pic.jpg","nextChapterUrl":"https://book.example/c2","fromBookInfo":true}"#,
            )
            .unwrap();
        assert_eq!(
            out,
            "https://img.example/pic.jpg|https://book.example/c2|true"
        );
    }

    #[test]
    fn eval_bindings_merge_book_and_chapter_reading_state() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script_with_bindings(
                r#"<js>
                var before = [book.durChapterTitle, book.durChapterIndex, chapter.index].join('|');
                book.durChapterTitle = 'Next';
                book.durChapterIndex = 8;
                chapter.index = 9;
                before;
                </js>"#,
                "bindings.bookChapterState",
                "",
                "https://example.test/",
                "",
                1,
                r#"{"book":{"durChapterTitle":"Current","durChapterIndex":7},"chapter":{"index":3}}"#,
            )
            .unwrap();
        assert_eq!(out, "Current|7|3");

        let session = js.session();
        assert_eq!(
            session
                .book_variables
                .get("durChapterTitle")
                .map(String::as_str),
            Some("Next")
        );
        assert_eq!(
            session
                .book_variables
                .get("durChapterIndex")
                .map(String::as_str),
            Some("8")
        );
        assert_eq!(
            session.chapter_variables.get("index").map(String::as_str),
            Some("9")
        );
    }

    #[test]
    fn java_byte_array_decode_helpers_return_android_byte_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();

        let from_base64 = js
            .eval_rule_script(
                "@js: return java.base64DecodeToByteArray('AQID/w==')",
                "bytes.base64",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            from_base64,
            r#"__LEGADO_JSON_VALUE__{"__hex":"010203ff","length":4}"#
        );

        let from_hex = js
            .eval_rule_script(
                "@js: return java.hexDecodeToByteArray('0a0b0c')",
                "bytes.hex",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            from_hex,
            r#"__LEGADO_JSON_VALUE__{"__hex":"0a0b0c","length":3}"#
        );

        let empty_hex = js
            .eval_rule_script(
                "@js: return java.hexDecodeToByteArray('')",
                "bytes.hex.empty",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(empty_hex, r#"__LEGADO_JSON_VALUE__{"__hex":"","length":0}"#);

        let nulls = js
            .eval_rule_script(
                "@js: return [java.base64DecodeToByteArray('') === null, java.base64DecodeToByteArray('   ') === null, java.hexDecodeToByteArray(null) === null].join('|')",
                "bytes.null",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(nulls, "true|true|true");
    }

    #[test]
    fn java_hex_decode_helpers_fail_fast_on_invalid_input() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();

        let ok = js
            .eval_rule_script(
                "<js>[java.hexDecodeToString('e4b8ad'), java.bytesToStr(java.hexDecodeToByteArray('e69687'))].join('|')</js>",
                "hex.decode.ok",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(ok, "中|文");

        let err = js
            .eval_rule_script(
                "<js>java.hexDecodeToString('not-hex')</js>",
                "hex.string.invalid",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_HEX_ERROR__"), "{err}");
        assert!(err.contains("hex.string.invalid"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>java.hexDecodeToByteArray('not-hex')</js>",
                "hex.bytes.invalid",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_HEX_ERROR__"), "{err}");
        assert!(err.contains("hex.bytes.invalid"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>java.bytesToStr({__hex:'not-hex'})</js>",
                "hex.bytesToStr.invalid",
                "",
                "https://bytes.example/",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_HEX_ERROR__"), "{err}");
        assert!(err.contains("hex.bytesToStr.invalid"), "{err}");
    }

    #[test]
    fn java_zip_content_helpers_extract_hex_archives() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("dir/a.txt", options).unwrap();
        writer.write_all("hello".as_bytes()).unwrap();
        writer.start_file("gbk.txt", options).unwrap();
        let (gbk, _, _) = encoding_rs::GBK.encode("中文");
        writer.write_all(gbk.as_ref()).unwrap();
        let archive_bytes = writer.finish().unwrap().into_inner();
        let archive_hex = hex::encode(&archive_bytes);
        let archive_data_url = format!(
            "data:application/zip;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&archive_bytes)
        );

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var archive = '{}';
            var archiveUrl = '{}';
            var bytes = java.getZipByteArrayContent(archive, 'dir/a.txt');
            [
              java.getZipStringContent(archive, 'dir/a.txt'),
              bytes.__hex,
              bytes.length,
              java.getZipStringContent(archive, 'gbk.txt'),
              java.getZipStringContent(archive, 'gbk.txt', 'GBK'),
              java.getZipStringContent(archiveUrl, 'dir/a.txt'),
              java.getZipStringContent(archive, 'missing.txt') === ''
            ].join('|');
            </js>"#,
            archive_hex, archive_data_url
        );
        let out = js
            .eval_rule_script(&script, "zip.content", "", "https://zip.example/", "", 1)
            .unwrap();
        assert_eq!(out, "hello|68656c6c6f|5|中文|中文|hello|true");

        let err = js
            .eval_rule_script(
                "<js>java.getZipByteArrayContent('not-hex', 'dir/a.txt')</js>",
                "zip.invalid.hex",
                "",
                "https://zip.example/",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_ZIP_ERROR__"), "{err}");
        assert!(err.contains("zip.invalid.hex"), "{err}");
    }

    #[test]
    fn java_zip_content_remote_url_applies_analyze_url_js_options() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("dir/a.txt", options).unwrap();
        writer.write_all(b"signed").unwrap();
        let archive_bytes = writer.finish().unwrap().into_inner();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 2048];
            let read = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            assert!(request.starts_with("GET /signed HTTP/1.1"), "{request}");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\n\r\n",
                archive_bytes.len()
            )
            .unwrap();
            stream.write_all(&archive_bytes).unwrap();
        });
        let options = serde_json::json!({
            "js": "result.replace('start', 'signed')",
            "bodyJs": "throw new Error('raw byte helpers must not apply bodyJs')"
        });
        let url = format!("{base}/start,{options}");
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            "<js>java.getZipStringContent({}, 'dir/a.txt')</js>",
            serde_json::to_string(&url).unwrap()
        );

        let out = js
            .eval_rule_script(&script, "zip.remote.urlOption.js", "", &base, "", 1)
            .unwrap();

        assert_eq!(out, "signed");
        handle.join().unwrap();
    }

    #[test]
    fn java_7z_content_helpers_extract_hex_archives() {
        let mut writer = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_file("dir/a.txt"),
                Some("hello".as_bytes()),
            )
            .unwrap();
        let (gbk, _, _) = encoding_rs::GBK.encode("中文");
        writer
            .push_archive_entry(
                sevenz_rust2::ArchiveEntry::new_file("gbk.txt"),
                Some(gbk.as_ref()),
            )
            .unwrap();
        let archive_bytes = writer.finish().unwrap().into_inner();
        let archive_hex = hex::encode(&archive_bytes);

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var archive = '{}';
            var bytes = java.get7zByteArrayContent(archive, 'dir/a.txt');
            java.__writeBytesFileHex('sample.7z', archive);
            java.__writeBytesFileHex('sample-generic.7z', archive);
            var folder = java.un7zFile('sample.7z');
            var genericFolder = java.unArchiveFile('sample-generic.7z');
            [
              java.get7zStringContent(archive, 'dir/a.txt'),
              bytes.__hex,
              bytes.length,
              java.get7zStringContent(archive, 'gbk.txt'),
              java.getTxtInFolder(folder),
              java.getTxtInFolder(genericFolder),
              java.get7zStringContent(archive, 'missing.txt') === ''
            ].join('|');
            </js>"#,
            archive_hex
        );
        let out = js
            .eval_rule_script(&script, "7z.content", "", "https://7z.example/", "", 1)
            .unwrap();
        assert_eq!(out, "hello|68656c6c6f|5|中文|hello\n中文|hello\n中文|true");

        let err = js
            .eval_rule_script(
                "<js>java.get7zByteArrayContent('not-hex', 'dir/a.txt')</js>",
                "7z.invalid.hex",
                "",
                "https://7z.example/",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_7Z_ERROR__"), "{err}");
        assert!(err.contains("7z.invalid.hex"), "{err}");
    }

    #[test]
    fn archive_and_font_helpers_are_present_and_fail_fast_on_invalid_rar() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let present = js
            .eval_rule_script(
                r#"<js>
                [
                  'getFile', 'readFile', 'getTxtInFolder',
                  'unArchiveFile', 'unzipFile', 'unrarFile', 'un7zFile',
                  'getRarByteArrayContent', 'getRarStringContent',
                  'get7zByteArrayContent', 'get7zStringContent',
                  'queryTTF', 'queryBase64TTF', 'replaceFont'
                ].filter(function(api) { return typeof java[api] !== 'function'; }).join(',');
                </js>"#,
                "unsupported.host.present",
                "",
                "https://unsupported.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(present, "");

        let err = js
            .eval_rule_script(
                "@js: return java.getRarStringContent('00', 'a.txt')",
                "rar.invalid.archive",
                "",
                "https://unsupported.example/",
                "",
                1,
            )
            .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("__LEGADO_RAR_ERROR__"), "{err}");
        assert!(err.contains("java.getRarStringContent"), "{err}");
        assert!(err.contains("rar.invalid.archive"), "{err}");
    }

    #[test]
    fn java_rar_content_helpers_extract_hex_archives() {
        let archive_bytes = include_bytes!("../tests/fixtures/rar5-save-32mb-txt.rar");
        let archive_hex = hex::encode(archive_bytes);
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var archive = '{}';
            var bytes = java.getRarByteArrayContent(archive, 'text.txt');
            java.__writeBytesFileHex('sample.rar', archive);
            java.__writeBytesFileHex('sample-generic.rar', archive);
            var folder = java.unrarFile('sample.rar');
            var genericFolder = java.unArchiveFile('sample-generic.rar');
            [
              java.getRarStringContent(archive, 'text.txt').indexOf('Far far away') >= 0,
              bytes.length > 100,
              java.getTxtInFolder(folder).indexOf('Far far away') >= 0,
              java.getTxtInFolder(genericFolder).indexOf('Far far away') >= 0,
              java.getRarStringContent(archive, 'missing.txt') === ''
            ].join('|');
            </js>"#,
            archive_hex
        );

        let out = js
            .eval_rule_script(&script, "rar.content", "", "https://rar.example/", "", 1)
            .unwrap();
        assert_eq!(out, "true|true|true|true|true");
    }

    #[test]
    fn java_ttf_query_and_replace_font_use_rust_font_parser() {
        let font = include_bytes!("../../../app/android/app/src/main/assets/font/number.ttf");
        let font_b64 = base64::engine::general_purpose::STANDARD.encode(font);
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var font = java.queryTTF({});
            var same = java.queryBase64TTF({});
            var code = '1'.codePointAt(0);
            var glyph = font.getGlyfByUnicode(code);
            [
              font.getGlyfIdByUnicode(code) > 0,
              glyph !== null,
              font.getUnicodeByGlyf(glyph) === code,
              font.isBlankUnicode(0x20),
              java.replaceFont('123', font, same) === '123',
              java.replaceFont('1🙂', font, same, true) === '1'
            ].join('|');
            </js>"#,
            serde_json::to_string(&font_b64).unwrap(),
            serde_json::to_string(&font_b64).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "ttf.query.replace",
                "",
                "https://ttf.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "true|true|true|true|true|true");

        let err = js
            .eval_rule_script(
                "<js>java.queryTTF('not-a-font')</js>",
                "ttf.invalid",
                "",
                "https://ttf.example/",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_TTF_ERROR__"), "{err}");
        assert!(err.contains("ttf.invalid"), "{err}");
    }

    #[test]
    fn java_get_file_returns_rust_virtual_file_object() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.writeTxtFile('scripts/get-file-object.js', 'abc');
                var file = java.getFile('scripts/get-file-object.js');
                [
                  file.path,
                  file.absolutePath,
                  file.name,
                  file.getPath(),
                  file.getAbsolutePath(),
                  file.getName(),
                  file.exists(),
                  file.isFile(),
                  file.isDirectory(),
                  file.length(),
                  java.bytesToStr(file.readBytes()),
                  file.readText(),
                  String(file),
                  file.delete(),
                  file.exists()
                ].join('|');
                </js>"#,
                "file.getFile",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "scripts/get-file-object.js|scripts/get-file-object.js|get-file-object.js|scripts/get-file-object.js|scripts/get-file-object.js|get-file-object.js|true|true|false|3|abc|abc|scripts/get-file-object.js|true|false"
        );
    }

    #[test]
    fn java_string_byte_helpers_honor_charset_and_byte_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var utf8 = java.strToBytes('中文');
                var gbk = java.strToBytes('中文', 'GBK');
                [
                  utf8.__hex,
                  utf8.length,
                  gbk.__hex,
                  gbk.length,
                  java.bytesToStr(utf8),
                  java.bytesToStr(gbk, 'GBK')
                ].join('|');
                </js>"#,
                "test.stringBytes",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "e4b8ade69687|6|d6d0cec4|4|中文|中文");
    }

    #[test]
    fn java_string_byte_helpers_fail_fast_on_unknown_charset() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                r#"<js>
                java.strToBytes('x', 'not-a-charset');
                </js>"#,
                "test.stringBytes.charset",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err();

        assert!(err.to_string().contains("__LEGADO_CHARSET_ERROR__"));
        assert!(err.to_string().contains("not-a-charset"));
    }

    #[test]
    fn source_js_lib_overrides_default_scope_helpers() {
        let mut source = source();
        source.js_lib = r#"
            var Region = Get('url');
            function Get(key) {
                var data = JSON.parse(source.getVariable());
                return data[key] || '';
            }
            function Reload(url) { return 'jsLib:' + url; }
        "#
        .to_string();
        let session = AnalyzerSession {
            source_variable: r#"{"url":"https://jslib.example"}"#.to_string(),
            ..AnalyzerSession::default()
        };
        let mut js = JsRuntime::new(&source, session).unwrap();
        let out = js
            .eval_rule_script(
                "@js: return [Region, Get('url'), Reload('x')].join('|')",
                "x",
                "",
                "https://fallback.example",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "https://jslib.example|https://jslib.example|jsLib:x");
    }

    #[test]
    fn eval_expression_statement_returns_completion_value() {
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "eval(String('JSON.stringify({value:\"ok\"})'));",
                "x",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, r#"{"value":"ok"}"#);
        let out = js
            .eval_rule_script(
                "eval(String('var x; JSON.stringify({value:\"ok\"});'));",
                "x",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, r#"{"value":"ok"}"#);
        let out = js
            .eval_rule_script(
                "eval(String('var User; globalThis.user_Check = function user_Check(){ User = true; }; user_Check(); globalThis.jishu = \"\"; if (User !== true) { jishu = \"\"; } JSON.stringify({jishu:jishu});'));",
                "x",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, r#"{"jishu":""}"#);
    }

    #[test]
    fn eval_if_statement_returns_rhino_style_completion_value() {
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "var ok = true; if (ok) { 'inside'; }",
                "x",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "inside");
    }

    #[test]
    fn eval_if_block_returns_last_runtime_expression_after_function_declarations() {
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "var ok = true; if (ok) { var values = []; function push(v) { values.push(v); } java.log('log'); push('a'); values.join('\\n'); }",
                "x",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "a");
    }

    #[test]
    fn host_session_store_roundtrip() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "@js: java.put('x', '42'); return java.get('x')",
                "x",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "42");
    }

    #[test]
    fn source_put_get_uses_source_scoped_store_not_global_cache() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "@js: source.put('token', 'abc'); cache.put('token', 'global'); return source.get('token') + '|' + cache.get('token')",
                "x",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "abc|global");
        let session = js.session();
        assert_eq!(
            session.source_store.get("token").map(String::as_str),
            Some("abc")
        );
        assert_eq!(
            session.cache.get("token").map(String::as_str),
            Some("global")
        );
    }

    #[test]
    fn cache_memory_apis_do_not_write_persistent_cache_layer() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                cache.putMemory('memoryOnly', 'volatile');
                var beforeDelete = [cache.getFromMemory('memoryOnly'), cache.get('memoryOnly')].join('|');
                cache.deleteMemory('memoryOnly');
                var afterDelete = [cache.getFromMemory('memoryOnly'), cache.get('memoryOnly')].join('|');
                beforeDelete + '>' + afterDelete;
                </js>"#,
                "cache.memory",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "volatile|volatile>|");
        let session = js.session();
        assert!(!session.cache.contains_key("memoryOnly"));
        assert_eq!(
            session
                .java_store
                .get("__cache_memory:memoryOnly")
                .map(String::as_str),
            None
        );
    }

    #[test]
    fn cache_file_apis_use_separate_channel_and_delete_clears_it() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                cache.put('blob', 'plain');
                cache.putFile('blob', 'large text', 60);
                var beforeDelete = [cache.get('blob'), cache.getFile('blob')].join('|');
                cache.delete('blob');
                var afterDelete = [cache.get('blob'), cache.getFile('blob')].join('|');
                beforeDelete + '>' + afterDelete;
                </js>"#,
                "cache.file",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "plain|large text>|");
        let session = js.session();
        assert!(!session.cache.contains_key("blob"));
        assert!(!session.cache.contains_key("__cache_file:blob"));
    }

    #[test]
    fn chapter_media_helpers_write_chapter_session_fields() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                chapter.putLyric('line one');
                chapter.putImgUrl('https://img.example/icon.png');
                [chapter.getVariable('lyric'), chapter.getVariable('imgUrl')].join('|');
                </js>"#,
                "chapter.media",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "line one|https://img.example/icon.png");
        let session = js.session();
        assert_eq!(
            session.chapter_variables.get("lyric").map(String::as_str),
            Some("line one")
        );
        assert_eq!(
            session.chapter_variables.get("imgUrl").map(String::as_str),
            Some("https://img.example/icon.png")
        );
    }

    #[test]
    fn host_store_writes_coerce_numbers_like_android_js_bridge() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "@js: cache.put('version', 26); java.put('count', 7); source.put('rank', 3); book.setVariable('idx', 2); chapter.putVariable('cid', 9); cookie.setCookie('example.com', 5); return [cache.get('version'), java.get('count'), source.get('rank'), book.getVariable('idx'), chapter.getVariable('cid'), cookie.getCookie('example.com')].join('|')",
                "x",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "26|7|3|2|9|5");
    }

    #[test]
    fn direct_book_and_chapter_property_mutations_sync_to_session() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "@js: book.type = 64; book.variable = JSON.stringify({custom:'x'}); chapter.title = '第一章'; return String(book.type)",
                "x",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "64");
        let session = js.session();
        assert_eq!(
            session.book_variables.get("type").map(String::as_str),
            Some("64")
        );
        assert_eq!(
            session.book_variables.get("variable").map(String::as_str),
            Some(r#"{"custom":"x"}"#)
        );
        assert_eq!(
            session.chapter_variables.get("title").map(String::as_str),
            Some("第一章")
        );
    }

    #[test]
    fn rhino_with_block_keeps_function_visible() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "@js: var javaImport = new JavaImporter(); with(javaImport) { function decode(v) { return String(v) + '!'; } } decode('ok')",
                "x",
                "",
                "",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "ok!");
    }

    #[test]
    fn eval_exports_implicit_function_assignments_like_rhino_top_level() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                eval("user_Check = function(){ return 'ok'; }");
                user_Check();
                </js>"#,
                "test.implicitFunctionAssignment",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "ok");
    }

    #[test]
    fn eval_reload_explicit_global_assignment_functions_remain_available() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                eval("globalThis.mark = function(){ User = true; }");
                User = "";
                mark();
                User === true ? "ok" : String(User);
                </js>"#,
                "test.implicitGlobalAssignment",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "ok");
    }

    #[test]
    fn native_eval_keeps_function_local_scope_visible_like_rhino() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                function pick(tag, index) {
                    var region = ["*", "cn"];
                    return eval(tag + "[" + index + "]");
                }
                pick("region", 1);
                </js>"#,
                "test.directEvalScope",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "cn");
    }

    #[test]
    fn import_script_preprocesses_implicit_globals_without_replacing_eval() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body =
                "var cache_api = 'https://cache.test/'; original = { url: 'ok' }; function read(){ return cache_api + original.url; }";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                &format!("eval(String(Reload('{base_url}/script.js'))); read();"),
                "test.importScriptImplicitGlobal",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out, "https://cache.test/ok");
    }

    #[test]
    fn import_script_returns_raw_text_for_template_embedding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = r#"Array.from(items).filter(
  child => !child.classList.contains('x')
);
const TimeManager = {
  init(videoUrl) { this.currentVideoUrl = videoUrl; this._loadFromStorage(); },
  _loadFromStorage() { return this.currentVideoUrl; }
};
const headers = { Accept: 'text/html;q=0.9,*/*;q=0.8' };"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                &format!("String(Reload('{base_url}/player.js'));"),
                "test.importScriptRaw",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert!(out.contains("child =>"), "{out}");
        assert!(!out.contains("globalThis.child"), "{out}");
        assert!(out.contains("this._loadFromStorage()"), "{out}");
        assert!(!out.contains("globalThis._loadFromStorage"), "{out}");
        assert!(out.contains("q=0.9"), "{out}");
        assert!(!out.contains("q = globalThis.q"), "{out}");
    }

    #[test]
    fn imported_eval_preprocessing_does_not_rewrite_template_literal_text() {
        let mut source = source();
        source.js_lib = r#"
            function requestHeader() {
                let qttoken = 'abc';
                let device = '0000000000000000';
                let options = {
                    headers: {
                        cookie: `qttoken=${qttoken};deviceId=${device};`
                    }
                };
                return options.headers.cookie;
            }
        "#
        .to_string();
        let raw_pos = source
            .js_lib
            .find(";deviceId=")
            .expect("template literal marker");
        let expression_pos = source
            .js_lib
            .find("${qttoken}")
            .expect("template literal expression marker")
            + 2;
        assert!(is_in_js_literal(&source.js_lib, raw_pos));
        assert!(!is_in_js_literal(&source.js_lib, expression_pos));
        let processed = preprocess_imported_eval_script(&source.js_lib);
        assert!(processed.contains("deviceId=${device}"), "{processed}");
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "requestHeader();",
                "test.templateLiteralAssignmentText",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "qttoken=abc;deviceId=0000000000000000;");
    }

    #[test]
    fn imported_eval_preprocessing_rewrites_this_inside_template_expressions() {
        let mut source = source();
        source.js_lib = r#"
            function host() { return 'https://example.test'; }
            function url() { return `${this.host()}/static/js/config.json`; }
        "#
        .to_string();
        let literal_text_pos = source
            .js_lib
            .find("/static/js/config")
            .expect("template literal text");
        let expression_pos = source
            .js_lib
            .find("this.host")
            .expect("template expression this");
        assert!(is_in_js_literal(&source.js_lib, literal_text_pos));
        assert!(!is_in_js_literal(&source.js_lib, expression_pos));
        let processed = preprocess_imported_eval_script(&source.js_lib);
        assert!(processed.contains("${globalThis.host()}"), "{processed}");
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script("url();", "test.templateThisExpression", "", "", "", 1)
            .unwrap();
        assert_eq!(out, "https://example.test/static/js/config.json");
    }

    #[test]
    fn source_login_url_is_preprocessed_when_scripts_eval_it_as_text() {
        let mut source = source();
        source.login_url = r#"
            eval("user_Check = function(){ User = true; }");
            User = "";
            user_Check();
        "#
        .to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                eval(String(source.loginUrl));
                User === true ? "ok" : String(User);
                </js>"#,
                "test.sourceLoginUrlEval",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "ok");
    }

    #[test]
    fn source_login_evals_login_url_and_invokes_login_function_like_original_app() {
        let mut source = source();
        source.login_url =
            r#"<js>function login(){ source.putLoginInfo("token", "abc"); return "done"; }</js>"#
                .to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();

        let out = js
            .eval_rule_script(
                r#"<js>source.login() + "|" + source.getLoginInfoMap().get("token")</js>"#,
                "test.sourceLogin",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "done|abc");
    }

    #[test]
    fn source_login_strips_at_js_login_url_like_original_app() {
        let mut source = source();
        source.login_url = r#"@js:function login(){ return "at-js"; }"#.to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();

        let out = js
            .eval_rule_script(
                r#"<js>source.login()</js>"#,
                "test.sourceLoginAtJs",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "at-js");
    }

    #[test]
    fn imported_script_completion_survives_global_helper_preprocessing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = r#"
                var User;
                put({url:"https://example.test"});
                function user_Check(){ User = true; }
                function put(data){ return source.setVariable(JSON.stringify(data)); }
                user_Check();
                var jishu = "";
                if (User !== true) { jishu = ""; }
                JSON.stringify({jishu:jishu, stored:JSON.parse(source.getVariable()).url});
            "#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                &format!("eval(String(Reload('{base_url}/script.js')));"),
                "test.importScriptCompletion",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out, r#"{"jishu":"","stored":"https://example.test"}"#);
    }

    #[test]
    fn imported_script_keeps_function_local_var_from_overwriting_global_helper() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = r#"
                function get(tag, num) {
                    var region = ['*', 'cn'];
                    return eval(tag + '[' + num + ']');
                }
                function Get(key) {
                    var get = JSON.parse(source.getVariable());
                    return get[key];
                }
                var _0x5646, _0xe2b8, User;
                _0xe2b8 = function(value) {
                    return value + '?';
                };
                try {
                    missingValue;
                } catch (err) {
                    $$$ = { ok: true };
                }
                var decode = function(value) {
                    return value + '!';
                };
                function touchLocalDecoderName() {
                    for (var index = 0, decode; decode = 'local', index < 1; index++) {}
                    return decode;
                }
                function loopUndeclaredForIn() {
                    for (i in { a: 1 }) {}
                    return i;
                }
            "#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let session = AnalyzerSession {
            source_variable: r#"{"o":1}"#.to_string(),
            ..AnalyzerSession::default()
        };
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, session).unwrap();
        let out = js
            .eval_rule_script(
                &format!(
                    "eval(String(Reload('{base_url}/script.js'))); [Get('o'), get('region', Get('o')), _0xe2b8('x'), $$$.ok, touchLocalDecoderName(), decode('ok'), loopUndeclaredForIn()].join('|');"
                ),
                "test.importScriptLocalVarScope",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out, "1|cn|x?|true|local|ok!|a");
    }

    #[test]
    fn imported_script_terminal_if_preserves_native_eval_completion() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "var ok = true; if (ok) { var values = []; function add(v) { values.push(v); } add('分类::https://example.test/a'); values.join('\\n') }";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                &format!("eval(String(Reload('{base_url}/script.js')));"),
                "test.importScriptIfCompletion",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out, "分类::https://example.test/a");
    }

    #[test]
    fn imported_child_eval_updates_parent_top_level_var_like_rhino_scope() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server_base_url = base_url.clone();
        let handle = std::thread::spawn(move || {
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let body = if request_index == 0 {
                    format!(
                        "var flag; eval(String(Reload('{server_base_url}/child.js'))); flag = ''; childFn(); if (flag === true) {{ '分类::https://example.test/a' }}"
                    )
                } else {
                    "function childFn() { flag = true; }".to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                &format!("eval(String(Reload('{base_url}/parent.js')));"),
                "test.importedChildParentScope",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out, "分类::https://example.test/a");
    }

    #[test]
    fn imported_script_compact_block_tail_assignment_creates_implicit_global() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "if (true) { value = 1 }tailValue='ok'; tailValue";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut source = source();
        source.js_lib = "function Reload(url) { return java.importScript(url); }".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                &format!("eval(String(Reload('{base_url}/compact.js')));"),
                "test.compactImplicitGlobal",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        handle.join().unwrap();
        assert_eq!(out, "ok");
    }

    #[test]
    fn java_get_string_extracts_html_rule_from_current_content() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "java.getString('id.TextContent@html')",
                "x",
                "<html><body><div id=\"TextContent\"><p>正文</p></div><div>旁支</div></body></html>",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "<p>正文</p>");
    }

    #[test]
    fn java_html_rule_helpers_fail_fast_on_rule_errors() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();

        let missing = js
            .eval_rule_script(
                "java.getString('.missing@text')",
                "html.rule.missing",
                "<html><body><div class=\"ok\">正文</div></body></html>",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(missing, "");

        let err = js
            .eval_rule_script(
                "java.getString('div[@text')",
                "html.rule.invalid.getString",
                "<html><body><div class=\"ok\">正文</div></body></html>",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_RULE_ERROR__"), "{err}");
        assert!(err.contains("html.rule.invalid.getString"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>java.setContent('<html><body><div>正文</div></body></html>'); java.getElements('div[')</js>",
                "html.rule.invalid.select",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_RULE_ERROR__"), "{err}");
        assert!(err.contains("html.rule.invalid.select"), "{err}");
    }

    #[test]
    fn java_get_element_helpers_cover_regex_and_jsonpath_modes() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.setContent('A:10;B:20;');
                var first = java.getElement(':(\\w):(\\d+)');
                var all = java.getElements(':(\\w):(\\d+)');
                java.setContent('{"items":[{"name":"one"},{"name":"two"}],"meta":{"count":2}}');
                var names = java.getElements('$.items[*].name');
                var meta = java.getElement('@Json:$.meta.count');
                java.setContent('<html><body><section><div class="x">XPath</div></section></body></html>');
                var xpath = java.getElement('@XPath://div[@class="x"]').text();
                var absolute = java.getElement('/html/body/section/div').text();
                [first[1], first.get(2), first.size(), all.length, all.get(1).get(1), all.get(1).size(), names.join(','), meta, xpath, absolute].join('|');
                </js>"#,
                "java.getElement.modes",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "A|10|3|2|B|3|one,two|2|XPath|XPath");
    }

    struct RecordingPlatformHost {
        calls: RefCell<Vec<String>>,
    }

    impl PlatformHost for RecordingPlatformHost {
        fn handle_platform_action(&self, api: &str, _source_name: &str, args_json: &str) -> String {
            self.calls.borrow_mut().push(format!("{api}:{args_json}"));
            let body = match api {
                "getReadBookConfig" => r##"{"fontSize":18,"fontColor":"#123456"}"##.to_string(),
                "getThemeConfig" => r##"{"bgColor":"#ffffff","isNight":false}"##.to_string(),
                "getThemeMode" => "1".to_string(),
                "getWebViewUA" => "AndroidTestUA/1.0".to_string(),
                "androidId" => "android-id-test".to_string(),
                "getAppVersionName" => "3.26.test".to_string(),
                "getAppVersionCode" => "326052311".to_string(),
                "getAppVariant" => "appDebug".to_string(),
                _ => format!("{api}-body"),
            };
            serde_json::json!({
                "handled": true,
                "api": api,
                "url": "https://callback.example/",
                "body": body,
                "code": 200,
                "message": "OK",
                "marker": format!("__LEGADO_PLATFORM_API__:{api}"),
                "cookies": if api == "webView" {
                    serde_json::json!({"https://j.example": "client_type=2; sid=web"})
                } else {
                    serde_json::json!({})
                }
            })
            .to_string()
        }
    }

    #[test]
    fn source_book_chapter_variables_persist_across_eval_calls() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        js.eval_rule_script(
            r#"<js>
            source.setVariable('line', 'A');
            source.put('durable', 'S');
            book.setVariable('bookKey', 'B');
            chapter.setVariable('chapterKey', 'C');
            'ok';
            </js>"#,
            "vars.write",
            "",
            "https://example.test",
            "",
            1,
        )
        .unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [source.getVariable('line'), source.get('durable'), book.getVariable('bookKey'), chapter.getVariable('chapterKey')].join('|');
                </js>"#,
                "vars.read",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "A|S|B|C");
    }

    #[test]
    fn java_source_identity_helpers_match_android_shape() {
        let mut source = source();
        source.book_source_url = "https://source.example/".to_string();
        source.book_source_name = "Source Name".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var s = java.getSource();
                [java.getTag(), s.getKey(), s.bookSourceName, s.sourceName].join('|');
                </js>"#,
                "java.sourceIdentity",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "Source Name|https://source.example/|Source Name|Source Name"
        );
    }

    #[test]
    fn platform_host_dispatches_browser_webview_and_media_actions() {
        let host = Rc::new(RecordingPlatformHost {
            calls: RefCell::new(Vec::new()),
        });
        let mut js =
            JsRuntime::new_with_platform(&source(), AnalyzerSession::default(), Some(host.clone()))
                .unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var a = java.startBrowser("https://a.example", "A");
                var b = java.startBrowserAwait("https://b.example", "B").body();
                var c = java.showBrowser("https://c.example", "<p>C</p>", "", "");
                var d = java.openVideoPlayer("https://d.example/v.mp4", "D", true);
                var e = java.reLoginView(true);
                var f = java.refreshExplore();
                var g = java.startBrowserDp("https://g.example", "G");
                var h = java.showReadingBrowser("https://h.example", "H");
                var i = java.openUrl("https://i.example");
                var j = java.webView("<html>J</html>", "https://j.example", "document.body.innerText");
                var k = java.webViewGetSource("https://k.example");
                var l = java.webViewGetOverrideUrl("https://l.example");
                var m = java.getVerificationCode("https://m.example/code.png");
                var n = cookie.getKey("https://j.example", "client_type");
                var o = source.refreshExplore();
                var p = cookie.setWebCookie("https://web.example", "sid=web");
                [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p].join("|");
                </js>"#,
                "platform",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "__LEGADO_PLATFORM_API__:startBrowser|startBrowserAwait-body|__LEGADO_PLATFORM_API__:showBrowser|__LEGADO_PLATFORM_API__:openVideoPlayer|__LEGADO_PLATFORM_API__:reLoginView|__LEGADO_PLATFORM_API__:refreshExplore|__LEGADO_PLATFORM_API__:startBrowserDp|__LEGADO_PLATFORM_API__:showReadingBrowser|openUrl-body|webView-body|webViewGetSource-body|webViewGetOverrideUrl-body|getVerificationCode-body|2|__LEGADO_PLATFORM_API__:refreshExplore|true"
        );
        let calls = host.calls.borrow();
        assert_eq!(calls.len(), 15);
        assert!(calls[0].starts_with("startBrowser:"));
        assert!(calls[1].starts_with("startBrowserAwait:"));
        assert!(calls[2].starts_with("showBrowser:"));
        assert!(calls[3].starts_with("openVideoPlayer:"));
        assert!(calls[4].starts_with("reLoginView:"));
        assert!(calls[5].starts_with("refreshExplore:"));
        assert!(calls[6].starts_with("startBrowserDp:"));
        assert!(calls[7].starts_with("showReadingBrowser:"));
        assert!(calls[8].starts_with("openUrl:"));
        assert!(calls[9].starts_with("webView:"));
        assert!(calls[10].starts_with("webViewGetSource:"));
        assert!(calls[11].starts_with("webViewGetOverrideUrl:"));
        assert!(calls[12].starts_with("getVerificationCode:"));
        assert!(calls[13].starts_with("refreshExplore:"));
        assert!(calls[14].starts_with("setWebCookie:"));
    }

    #[test]
    fn source_refresh_explore_fails_fast_without_platform_host() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "<js>source.refreshExplore()</js>",
                "source.refreshExplore",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_UNSUPPORTED_PLATFORM_API__"), "{err}");
        assert!(err.contains("refreshExplore"), "{err}");
        assert!(err.contains("source.refreshExplore"), "{err}");
    }

    #[test]
    fn cookie_set_web_cookie_fails_fast_without_platform_host() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                r#"<js>cookie.setWebCookie("https://web.example", "sid=web")</js>"#,
                "cookie.setWebCookie",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_UNSUPPORTED_PLATFORM_API__"), "{err}");
        assert!(err.contains("setWebCookie"), "{err}");
        assert!(err.contains("cookie.setWebCookie"), "{err}");
    }

    #[test]
    fn source_refresh_js_lib_clears_remote_import_cache() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let js_url = format!("{base_url}/lib.js");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let body = "";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        let mut source = source();
        source.js_lib = serde_json::json!({ "remote": js_url }).to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        handle.join().unwrap();

        let remote_key = format!(
            "cacheFile:{:x}",
            md5::compute(
                serde_json::from_str::<serde_json::Value>(&source.js_lib)
                    .unwrap()
                    .get("remote")
                    .unwrap()
                    .as_str()
                    .unwrap()
            )
        );
        {
            let mut session = js.session.lock().expect("session poisoned");
            session
                .cache
                .insert(remote_key.clone(), "stale remote".to_string());
        }
        let out = js
            .eval_rule_script(
                "<js>source.refreshJSLib()</js>",
                "source.refreshJSLib",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "true");
        let session = js.session();
        assert!(!session.cache.contains_key(&remote_key));
    }

    #[test]
    fn java_config_map_helpers_parse_android_platform_json() {
        let host = Rc::new(RecordingPlatformHost {
            calls: RefCell::new(Vec::new()),
        });
        let mut js =
            JsRuntime::new_with_platform(&source(), AnalyzerSession::default(), Some(host.clone()))
                .unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var read = java.getReadBookConfigMap();
                var theme = java.getThemeConfigMap();
                [
                  java.getReadBookConfig().indexOf('fontSize') >= 0,
                  read.fontSize,
                  java.getThemeMode(),
                  theme.bgColor,
                  theme.isNight
                ].join('|');
                </js>"#,
                "java.configMaps",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "true|18|1|#ffffff|false");
        let calls = host.calls.borrow();
        assert!(calls
            .iter()
            .any(|call| call.starts_with("getReadBookConfig:")));
        assert!(calls.iter().any(|call| call.starts_with("getThemeMode:")));
        assert!(calls.iter().any(|call| call.starts_with("getThemeConfig:")));
    }

    struct BadConfigPlatformHost;

    impl PlatformHost for BadConfigPlatformHost {
        fn handle_platform_action(
            &self,
            api: &str,
            _source_name: &str,
            _args_json: &str,
        ) -> String {
            let body = match api {
                "getReadBookConfig" => "{bad read config",
                "getThemeConfig" => "{bad theme config",
                _ => "",
            };
            serde_json::json!({
                "handled": true,
                "api": api,
                "body": body,
                "code": 200,
                "message": "OK"
            })
            .to_string()
        }
    }

    #[test]
    fn java_config_map_helpers_fail_fast_on_invalid_platform_json() {
        let host = Rc::new(BadConfigPlatformHost);
        let mut js =
            JsRuntime::new_with_platform(&source(), AnalyzerSession::default(), Some(host))
                .unwrap();

        let err = js
            .eval_rule_script(
                "<js>java.getReadBookConfigMap()</js>",
                "java.readConfig.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_CONFIG_ERROR__"), "{err}");
        assert!(err.contains("getReadBookConfig"), "{err}");
        assert!(err.contains("java.readConfig.invalid"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>java.getThemeConfigMap()</js>",
                "java.themeConfig.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_CONFIG_ERROR__"), "{err}");
        assert!(err.contains("getThemeConfig"), "{err}");
        assert!(err.contains("java.themeConfig.invalid"), "{err}");
    }

    struct MalformedPlatformHost;

    impl PlatformHost for MalformedPlatformHost {
        fn handle_platform_action(
            &self,
            _api: &str,
            _source_name: &str,
            _args_json: &str,
        ) -> String {
            "not-json".to_string()
        }
    }

    #[test]
    fn platform_host_response_json_errors_fail_fast() {
        let host = Rc::new(MalformedPlatformHost);
        let mut js =
            JsRuntime::new_with_platform(&source(), AnalyzerSession::default(), Some(host))
                .unwrap();

        let err = js
            .eval_rule_script(
                "<js>java.startBrowser('https://bad.example', 'Bad')</js>",
                "platform.response.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_PLATFORM_RESPONSE_ERROR__"), "{err}");
        assert!(err.contains("startBrowser"), "{err}");
        assert!(err.contains("platform.response.invalid"), "{err}");
    }

    #[test]
    fn app_metadata_helpers_use_platform_host_values() {
        let host = Rc::new(RecordingPlatformHost {
            calls: RefCell::new(Vec::new()),
        });
        let mut js =
            JsRuntime::new_with_platform(&source(), AnalyzerSession::default(), Some(host.clone()))
                .unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.getWebViewUA(),
                  java.androidId(),
                  java.getAppVersionName(),
                  java.getAppVersionCode(),
                  java.getAppVariant()
                ].join('|');
                </js>"#,
                "java.appMetadata",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "AndroidTestUA/1.0|android-id-test|3.26.test|326052311|appDebug"
        );
        let calls = host.calls.borrow();
        for api in [
            "getWebViewUA",
            "androidId",
            "getAppVersionName",
            "getAppVersionCode",
            "getAppVariant",
        ] {
            assert!(calls
                .iter()
                .any(|call| call.starts_with(&format!("{api}:"))));
        }
    }

    #[test]
    fn java_get_user_agent_uses_source_login_and_url_option_headers() {
        let mut source = source();
        source.header = r#"{"User-Agent":"SourceUA/1.0"}"#.to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var sourceUa = java.getUserAgent();
                source.putLoginHeader('{"User-Agent":"LoginUA/2.0"}');
                var loginUa = java.getUserAgent();
                var optionUa = java.getUserAgent('https://example.test/path,{"headers":{"User-Agent":"OptionUA/3.0"}}');
                [sourceUa, loginUa, optionUa].join('|');
                </js>"#,
                "java.getUserAgent",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "SourceUA/1.0|LoginUA/2.0|OptionUA/3.0");
    }

    #[test]
    fn java_get_user_agent_falls_back_to_rust_default_user_agent() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "<js>java.getUserAgent()</js>",
                "java.getUserAgent.default",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, DEFAULT_USER_AGENT);
    }

    #[test]
    fn java_init_url_reparses_rule_url_like_analyze_url() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.ruleUrl = 'books/{{key + "-id"}}/<one,two>/<js>result + "?p=" + page</js>@result,{"headers":{"X-Test":"1"}}';
                var url = java.initUrl();
                [url, java.ruleUrl, baseUrl].join('|');
                </js>"#,
                "java.initUrl",
                "",
                "https://example.test/root/",
                "abc",
                2,
            )
            .unwrap();
        assert_eq!(
            out,
            r#"https://example.test/root/books/abc-id/two/?p=2|books/abc-id/two/?p=2,{"headers":{"X-Test":"1"}}|https://example.test/root/books/abc-id/two/"#
        );
    }

    #[test]
    fn java_ajax_honors_url_option_type_hex_body() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>java.ajax('data:application/octet-stream;base64,AGH/,{"type":"bytes"}')</js>"#,
                "java.ajax.type",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "0061ff");
    }

    #[test]
    fn java_set_redirect_url_updates_base_url_for_relative_resolution() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var redirected = java.setRedirectUrl('/book/reader/chapter.html?x=1');
                var ignored = java.setRedirectUrl('data:text/plain,ok');
                [String(redirected), ignored, baseUrl, java.toURL('../next.html', baseUrl).href].join('|');
                </js>"#,
                "java.setRedirectUrl",
                "",
                "https://example.test/root/index.html",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "https://example.test/book/reader/chapter.html?x=1|https://example.test/book/reader/chapter.html?x=1|https://example.test/book/reader/|https://example.test/book/next.html"
        );
    }

    #[test]
    fn java_error_response_helpers_match_analyze_url_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.ruleUrl = 'https://example.test/failing';
                var response = java.getErrStrResponse(new Error('boom'));
                var raw = java.getErrResponse('plain failure');
                [
                  response.code(),
                  response.message(),
                  response.url(),
                  response.body().indexOf('boom') >= 0,
                  response.errorBody().indexOf('boom') >= 0,
                  raw.code(),
                  raw.body()
                ].join('|');
                </js>"#,
                "java.errorResponse",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "500|boom|https://example.test/failing|true|true|500|plain failure"
        );
    }

    #[test]
    fn app_metadata_helpers_fail_fast_without_platform_host() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "<js>java.getAppVersionName()</js>",
                "java.appMetadata.noPlatform",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_UNSUPPORTED_PLATFORM_API__"), "{err}");
        assert!(err.contains("getAppVersionName"), "{err}");
        assert!(err.contains("java.appMetadata.noPlatform"), "{err}");
    }

    #[test]
    fn eval_bindings_preserve_login_ui_scope_objects() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script_with_bindings(
                "result.email + '|' + book.name + '|' + chapter.title + '|' + isLongClick",
                "bindings",
                "",
                "https://example.test",
                "",
                1,
                r#"{"result":{"email":"rust@example.com"},"book":{"name":"Book"},"chapter":{"title":"Chapter"},"isLongClick":true}"#,
            )
            .unwrap();
        assert_eq!(out, "rust@example.com|Book|Chapter|true");
    }

    #[test]
    fn eval_result_can_restore_android_str_response_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let result = serde_json::json!({
            "__strResponse": true,
            "url": "https://response.example/final",
            "body": "BODY",
            "code": 202,
            "message": "Accepted",
            "headers": { "etag": "abc" },
            "raw": "Response{code=202}"
        })
        .to_string();

        let out = js
            .eval_rule_script(
                "@js: return [result.body(), result.code(), result.url(), result.header('ETag'), result.message()].join('|')",
                "test.strResponseResult",
                &result,
                "https://response.example",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "BODY|202|https://response.example/final|abc|Accepted");
    }

    #[test]
    fn repeated_eval_reuses_normalized_script_without_stale_result() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = "<js>result.name + '|' + baseUrl</js>";
        let first = js
            .eval_rule_script(
                script,
                "test.normalizedScriptCache.first",
                r#"{"name":"one"}"#,
                "https://one.example/",
                "",
                1,
            )
            .unwrap();
        let second = js
            .eval_rule_script(
                script,
                "test.normalizedScriptCache.second",
                r#"{"name":"two"}"#,
                "https://two.example/",
                "",
                1,
            )
            .unwrap();

        assert_eq!(first, "one|https://one.example/");
        assert_eq!(second, "two|https://two.example/");
        assert_eq!(js.normalized_scripts.len(), 1);
    }

    #[test]
    fn html_node_collection_helpers_are_not_for_in_enumerable() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.setContent('<div class="topic-list-box"><a href="/x"><span class="h3">Name</span></a></div>');
                var list = java.getElements('.topic-list-box');
                var seen = [];
                for (i in list) {
                    seen.push(i + ':' + typeof list[i].select);
                }
                seen.join('|') + '|' + list[0].select('.h3').text();
                </js>"#,
                "test.htmlCollectionEnumeration",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "0:function|Name");
        assert!(!out.contains("text:"));
        assert!(!out.contains("attr:"));
        assert!(!out.contains("html:"));
    }

    #[test]
    fn jsoup_parse_compat_exposes_dom_select_helpers() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var J = org.jsoup.Jsoup.parse('<main><div class="row"><a href="/a">A</a></div></main>');
                var rows = J.select('.row');
                rows[0].select('a')[0].text() + '|' + rows[0].select('a')[0].attr('href');
                </js>"#,
                "test.jsoupCompat",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "A|/a");
    }

    #[test]
    fn packages_jsoup_connect_and_java_importer_cover_rhino_host_shape() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            assert!(request.starts_with("HEAD /probe "), "{request}");
            assert!(
                request.contains("X-Probe: rust") || request.contains("x-probe: rust"),
                "{request}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var rr = [1, 2, 3];
            var imports = new JavaImporter(Packages.org.jsoup.Jsoup, Packages.org.jsoup.Connection, Packages.java.util.Collections);
            with (imports) {{
              Collections.reverse(rr);
              var response = Jsoup.connect({})
                .timeout(1000)
                .ignoreContentType(true)
                .followRedirects(false)
                .header('X-Probe', 'rust')
                .method(Connection.Method.HEAD)
                .execute();
              [rr.join(','), response.statusCode(), response.header('Location')].join('|');
            }}
            </js>"#,
            serde_json::to_string(&format!("http://{addr}/probe")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "rhino.packages.jsoupConnect",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "3,2,1|204|/next");
        handle.join().unwrap();
    }

    #[test]
    fn packages_thread_sleep_blocks_like_java_thread_sleep() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let start = Instant::now();

        let out = js
            .eval_rule_script(
                r#"<js>Packages.java.lang.Thread.sleep(20); "ok"</js>"#,
                "rhino.packages.threadSleep",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "ok");
        assert!(start.elapsed() >= Duration::from_millis(15));
    }

    #[test]
    fn get_class_compat_reports_supported_imports_and_rejects_unsupported_packages() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  getClass(Packages.java.lang.String).getName(),
                  getClass(Packages.java.lang.String).getSimpleName(),
                  String(getClass("abc"))
                ].join("|")
                </js>"#,
                "rhino.getClass",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "String|String|class String");

        let err = js
            .eval_rule_script(
                r#"<js>getClass(Packages.android.content.Intent)</js>"#,
                "rhino.getClass.unsupported",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_UNSUPPORTED_HOST_API__"), "{err}");
        assert!(
            err.contains("unsupported Packages.android.content.Intent"),
            "{err}"
        );
    }

    #[test]
    fn packages_jsoup_dom_mutation_covers_dict_rule_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var aly = new JavaImporter(
                  Packages.org.jsoup.nodes.Element,
                  Packages.org.jsoup.Jsoup,
                  Packages.org.jsoup.select.Elements
                );
                with (aly) {
                  var result = Jsoup.parse('<main><img src="x"><div class="media-card-image"></div><a href="/v"><h3>Title</h3></a><script>bad</script></main>');
                  result.select('img').remove();
                  result.select('.media-card-image').before('<br>');
                  result.select('a').after('　');
                  var link = result.select('a')[0];
                  var h3 = link.selectFirst('h3');
                  var content = h3.text();
                  link.select('h3').remove();
                  var H3 = new Element('h3').appendChild(new Element('a').attr('href', link.attr('href')).text(content)).appendText('　');
                  link.replaceWith(H3);
                  result.select('script').remove();
                  result.html();
                }
                </js>"#,
                "rhino.packages.jsoupDomMutation",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert!(
            out.contains("<br><div class=\"media-card-image\"></div>"),
            "{out}"
        );
        assert!(out.contains("<h3><a href=\"/v\">Title</a>　</h3>"), "{out}");
        assert!(!out.contains("<img"), "{out}");
        assert!(!out.contains("<script"), "{out}");
    }

    #[test]
    fn jsoup_elements_cover_common_collection_methods_used_by_sources() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var doc = org.jsoup.Jsoup.parse('<main><a class="x" href="/a"><b>A</b><span>One</span></a><a href="/b">B</a></main>');
                var links = doc.select('a');
                var first = links.get(0);
                first.addClass('active');
                [
                  links.size(),
                  links.first().attr('href'),
                  links.last().text(),
                  links.eachAttr('href').join(','),
                  links.eachText().join('/'),
                  first.hasAttr('href'),
                  first.hasClass('active'),
                  first.tagName(),
                  first.ownText(),
                  links.outerHtml().indexOf('active') >= 0
                ].join('|');
                </js>"#,
                "jsoup.elements.collection",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "2|/a|B|/a,/b|AOne/B|true|true|a|AOne|true");
    }

    #[test]
    fn source_get_and_variable_tolerate_undefined_like_android_bridge() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                source.get(undefined) + '|' + source.getVariable(undefined);
                </js>"#,
                "test.sourceUndefinedArgs",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "|");
    }

    #[test]
    fn source_host_exposes_scalar_extra_fields_for_rss_scripts() {
        let mut source = source();
        source.extra = serde_json::json!({
            "sortUrl": "<js>sort</js>",
            "ruleContent": "<js>content</js>",
            "variableComment": "vc",
            "type": 4,
            "loginUi": "keep-special",
            "nested": { "enabled": true, "items": ["a", "b"] }
        });
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  source.sortUrl,
                  source.ruleContent,
                  source.variableComment,
                  source.type,
                  source.nested.enabled,
                  source.nested.items.join(","),
                  String(source.loginUi)
                ].join('|');
                </js>"#,
                "test.sourceExtraFields",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(
            out,
            "<js>sort</js>|<js>content</js>|vc|4|true|a,b|keep-special"
        );
    }

    #[test]
    fn cookie_helpers_tolerate_undefined_like_android_bridge() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                cookie.setCookie(undefined, undefined);
                [cookie.getCookie(undefined), cookie.getKey(undefined, undefined), cookie.removeCookie(undefined)].join('|');
                </js>"#,
                "test.cookieUndefinedArgs",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "undefined||");
    }

    #[test]
    fn eval_array_objects_preserve_json_value_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [{ name: 'A', url: '/a' }, { name: 'B', url: '/b' }];
                </js>"#,
                "test.jsonValueArray",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(
            out,
            r#"__LEGADO_JSON_VALUE__[{"name":"A","url":"/a"},{"name":"B","url":"/b"}]"#
        );
    }

    #[test]
    fn login_ui_source_put_login_info_accepts_object_and_date_time_format() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script_with_bindings(
                r#"
                source.putLoginInfo(result);
                java.timeFormat(new Date(1700000000000)).slice(0, 10);
                "#,
                "loginUi",
                "",
                "https://example.test",
                "",
                1,
                r#"{"result":{"邮箱":"rust@example.com","密码":"secret"}}"#,
            )
            .unwrap();
        assert_eq!(out, "2023/11/14");
        let session = js.session();
        assert_eq!(
            session.login_info.get("邮箱").map(String::as_str),
            Some("rust@example.com")
        );
        assert_eq!(
            session.login_info.get("密码").map(String::as_str),
            Some("secret")
        );
    }

    #[test]
    fn source_login_info_roundtrips_raw_string_and_remove() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                source.putLoginInfo('raw-login-payload');
                var first = source.getLoginInfo();
                source.removeLoginInfo();
                first + '|' + source.getLoginInfo();
                </js>"#,
                "source.loginInfo.raw",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "raw-login-payload|{}");
        let session = js.session();
        assert!(session.login_info_raw.is_empty());
        assert!(session.login_info.is_empty());
    }

    #[test]
    fn source_login_ui_preserves_text_while_remaining_android_probe_function() {
        let mut source = source();
        source.extra = serde_json::json!({
            "loginUi": r#"<js>[{"name":"邮箱","type":"text","default":"rust@example.com"}]</js>"#
        });
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  typeof source.loginUi,
                  source.loginUi(),
                  String(source.loginUi).startsWith("<js>"),
                  source.loginUi.startsWith("<js>"),
                  source.loginUi.substring(4, source.loginUi.lastIndexOf("<")),
                  JSON.stringify(source.loginUi).indexOf("rust@example.com") >= 0
                ].join("|");
                </js>"#,
                "source.loginUi",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            r#"function|true|true|true|[{"name":"邮箱","type":"text","default":"rust@example.com"}]|true"#
        );
    }

    #[test]
    fn java_time_format_utc_matches_android_simple_date_format() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.timeFormatUTC(1700000000000, 'yyyy-MM-dd HH:mm:ss', 0),
                  java.timeFormatUTC(new Date(1700000000000), "yyyy/MM/dd HH:mm 'UTC'Z", 8 * 3600 * 1000),
                  java.timeFormatUTC(1700000000123, 'HH:mm:ss.SSS', 0)
                ].join('|');
                </js>"#,
                "test.timeFormatUTC",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(
            out,
            "2023-11-14 22:13:20|2023/11/15 06:13 UTC+0800|22:13:20.123"
        );
    }

    #[test]
    fn java_encode_uri_matches_android_url_encoder_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.encodeURI('a b*~中文'),
                  java.encodeURI('中文', 'GBK'),
                  java.encodeURI('x', 'not-a-charset')
                ].join('|');
                </js>"#,
                "test.encodeURI",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "a+b*%7E%E4%B8%AD%E6%96%87|%D6%D0%CE%C4|");
    }

    #[test]
    fn java_chinese_conversion_helpers_are_not_identity_stubs() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.t2s('繁體中文與後臺'),
                  java.s2t('简体中文与后台')
                ].join('|');
                </js>"#,
                "test.chineseConversion",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "繁体中文与后台|簡體中文與後臺");
    }

    #[test]
    fn java_to_num_chapter_matches_android_title_number_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.toNumChapter('第一章 风起'),
                  java.toNumChapter('第两百三十四章'),
                  java.toNumChapter('序 第一千二章 尾'),
                  java.toNumChapter('第１２３章'),
                  java.toNumChapter('番外')
                ].join('|');
                </js>"#,
                "test.toNumChapter",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "第1章|第234章|第1200章|第123章|番外");
    }

    #[test]
    fn java_to_num_chapter_returns_minus_one_for_unparseable_android_match() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                "@js: return java.toNumChapter('第abc章 正文')",
                "test.toNumChapter.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "第-1章");
    }

    #[test]
    fn java_to_url_matches_android_js_url_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var absolute = java.toURL('https://example.com:8443/a/b?x=1&name=%E4%B8%AD+文&x=2');
                var relative = java.toURL('../c?raw=a=b&flag', 'https://host.test/root/dir/page.html');
                [
                  absolute.host,
                  absolute.origin,
                  absolute.pathname,
                  absolute.searchParams.x,
                  absolute.searchParams.name,
                  relative.host,
                  relative.origin,
                  relative.pathname,
                  relative.searchParams.raw,
                  String(relative.searchParams.flag)
                ].join('|');
                </js>"#,
                "test.toURL",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(
            out,
            "example.com|https://example.com:8443|/a/b|2|中 文|host.test|https://host.test|/root/c|a=b|undefined"
        );
    }

    #[test]
    fn java_to_url_fails_fast_on_invalid_url() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "@js: return java.toURL('/relative-without-base')",
                "test.toURL.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err();

        assert!(err.to_string().contains("__LEGADO_URL_ERROR__"));
        assert!(err.to_string().contains("relative-without-base"));
    }

    #[test]
    fn java_toast_log_helpers_accept_any_value_like_android_js_extensions() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.longToast(1);
                java.toast({ ok: true });
                java.log(null);
                "ok";
                </js>"#,
                "loginUi.anyToast",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "ok");
        let session = js.session();
        assert_eq!(session.toasts, vec!["1", "{\"ok\":true}"]);
        assert_eq!(session.logs, vec![""]);
    }

    #[test]
    fn unsupported_android_packages_fail_fast_and_log() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                r#"<js>
                var intent = new Packages.android.content.Intent("android.intent.action.VIEW");
                intent;
                </js>"#,
                "packages.android.unsupported",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();

        assert!(err.contains("__LEGADO_UNSUPPORTED_HOST_API__"), "{err}");
        assert!(err.contains("Packages.android.content.Intent"), "{err}");
        let session = js.session();
        assert!(
            session
                .logs
                .iter()
                .any(|entry| entry.contains("Packages.android.content.Intent")),
            "{:?}",
            session.logs
        );
    }

    #[test]
    fn ajax_eval_path_carries_cookie_session_across_ajax_and_ajax_all() {
        let server = CookieEchoServer::start(4);
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = r#"<js>
            cookie.setCookie('127.0.0.1', 'sid=manual');
            var first = java.ajax([BASE + '/echo'], 1000);
            var seed = java.ajax(BASE + '/seed');
            var all = java.ajaxAll([BASE + '/set2', BASE + '/echo']);
            [first, seed, all[0].body(), all[1].body(), cookie.getCookie('127.0.0.1')].join('|');
            </js>"#
            .replace("BASE", &serde_json::to_string(&server.base_url()).unwrap());
        let out = js
            .eval_rule_script(&script, "ajax.session", "", &server.base_url(), "", 1)
            .unwrap();
        assert_eq!(
            out,
            "sid=manual|seed|set2|sid=server; token=two|sid=server; token=two"
        );
    }

    #[test]
    fn java_get_cookie_uses_rust_cookie_store_like_android_host() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                cookie.setCookie('https://cookie.example', 'sid=abc; token=xyz');
                [java.getCookie('https://cookie.example'), java.getCookie('https://cookie.example', 'token')].join('|');
                </js>"#,
                "java.cookie",
                "",
                "https://cookie.example",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "sid=abc; token=xyz|xyz");
    }

    #[test]
    fn java_digest_and_hmac_helpers_match_original_string_shapes() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.digestHex('abc', 'SHA-256'),
                  java.digestBase64Str('abc', 'SHA-256'),
                  java.digestHex('abc', 'MD5'),
                  java.HMacHex('hello', 'HmacSHA256', 'key'),
                  java.HMacBase64('hello', 'HmacSHA256', 'key')
                ].join('|');
                </js>"#,
                "crypto.digest",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=|900150983cd24fb0d6963f7d28e17f72|9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b|kwezuRXvtRcf8U2MtV+8x5jGwO8UVtZt7RpqpyOli3s="
        );
    }

    #[test]
    fn packages_crypto_urlencoder_and_android_base64_cover_http_tts_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var aly = new JavaImporter(
                  Packages.javax.crypto.Mac,
                  Packages.javax.crypto.spec.SecretKeySpec,
                  Packages.javax.xml.bind.DatatypeConverter,
                  Packages.java.net.URLEncoder,
                  Packages.java.lang.String,
                  Packages.android.util.Base64
                );
                with (aly) {
                  function percentEncode(value) {
                    return URLEncoder.encode(value, "UTF-8").replace("+", "%20")
                      .replace("*", "%2A").replace("%7E", "~");
                  }
                  function sign(stringToSign, accessKeySecret) {
                    var mac = Mac.getInstance('HmacSHA1');
                    mac.init(new SecretKeySpec(String(accessKeySecret + '&').getBytes("UTF-8"), "HmacSHA1"));
                    var signData = mac.doFinal(String(stringToSign).getBytes("UTF-8"));
                    return percentEncode(Base64.encodeToString(signData, Base64.NO_WRAP));
                  }
                  [percentEncode('a b*~'), sign('abc', 'key')].join('|');
                }
                </js>"#,
                "rhino.packages.httpTtsCrypto",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "a%20b%2A~|V8X2UtOH1yaE4BRN38kxLJRSv%2Fc%3D");
    }

    #[test]
    fn packages_java_io_byte_array_streams_cover_image_decode_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var io = new JavaImporter(
                  Packages.java.io.ByteArrayInputStream,
                  Packages.java.io.ByteArrayOutputStream
                );
                with (io) {
                  function decodeImage(data, key) {
                    var input = new ByteArrayInputStream(data);
                    var out = new ByteArrayOutputStream();
                    var byte;
                    while ((byte = input.read()) != -1) {
                      out.write(byte ^ key);
                    }
                    return out.toByteArray();
                  }
                  java.bytesToStr(decodeImage(java.hexDecodeToByteArray('030003'), 0x42));
                }
                </js>"#,
                "rhino.packages.javaIoByteArrayStreams",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "ABA");
    }

    #[test]
    fn packages_jayway_jsonpath_covers_cover_and_dict_rule_shapes() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var json = JSON.stringify({
                  data: {
                    data: [{ title: '书名', cover: 'cover-a' }],
                    pinyin: 'shu',
                    definitionInfo: {
                      definition: 'def',
                      detailMeans: [{ word: 'w', definition: 'd' }]
                    },
                    nested: {
                      comprehensiveDefinition: [{
                        pinyin: 'pin',
                        basicDefinition: [{ cixing: ['n'], definition: 'basic' }]
                      }]
                    }
                  }
                });
                var direct = com.jayway.jsonpath.JsonPath.read(json, '$.data.data[*]');
                var aly = new JavaImporter(Packages.com.jayway.jsonpath);
                with (aly) {
                  var rr = JsonPath.using(
                    Configuration.builder().options(Option.SUPPRESS_EXCEPTIONS).build()
                  ).parse(json);
                  [
                    direct[0].cover,
                    rr.read('$.data.pinyin'),
                    rr.read('$.data.definitionInfo.detailMeans[*]')[0].word,
                    rr.read('$.data..comprehensiveDefinition[*].pinyin')[0],
                    rr.read('$.data..basicDefinition[*]cixing')[0][0],
                    JSON.stringify(rr.read('$.missing'))
                  ].join('|');
                }
                </js>"#,
                "rhino.packages.jaywayJsonPath",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "cover-a|shu|w|pin|n|[]");
    }

    #[test]
    fn jsonpath_supports_filters_unions_and_slices() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var json = {
                  books: [
                    {name: "A", type: "novel", score: 7, tag: "hot"},
                    {name: "B", type: "comic", score: 9},
                    {name: "C", type: "novel", score: 10, tag: "new"}
                  ],
                  meta: { title: "Shelf", count: 3 }
                };
                var novels = JsonPath.read(json, '$.books[?(@.type=="novel" && @.score>=8)].name').join(',');
                var union = JsonPath.read(json, "$.meta['title','count']").join('/');
                var slice = JsonPath.parse(json).read('$.books[0:2].name').join(',');
                var regex = JsonPath.read(json, '$.books[?(@.tag =~ /h.*/)].name').join(',');
                [novels, union, slice, regex].join('|');
                </js>"#,
                "rhino.packages.jaywayJsonPath.filterUnionSlice",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "C|Shelf/3|A,B|A");
    }

    #[test]
    fn java_digest_and_hmac_helpers_fail_fast_on_unsupported_algorithms() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "<js>java.digestHex('abc', 'NO-SUCH-DIGEST')</js>",
                "crypto.digest.unsupported",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported digest algorithm"), "{err}");
        assert!(err.contains("NO-SUCH-DIGEST"), "{err}");
        assert!(err.contains("crypto.digest.unsupported"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>java.HMacHex('abc', 'NO-SUCH-HMAC', 'key')</js>",
                "crypto.hmac.unsupported",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported HMAC algorithm"), "{err}");
        assert!(err.contains("NO-SUCH-HMAC"), "{err}");
        assert!(err.contains("crypto.hmac.unsupported"), "{err}");
    }

    #[test]
    fn java_http_overloads_return_response_objects_without_breaking_store_get() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.put('token', 'stored');
                var stored = java.get('token');
                var getBody = java.get('data:text/plain,hello', {'X-Test': '1'}).body();
                var postBody = java.post('data:text/plain,posted', 'ignored', {}).body();
                var headCode = java.head('data:text/plain,head', {}).statusCode ? java.head('data:text/plain,head', {}).statusCode() : java.head('data:text/plain,head', {}).code();
                var all = java.ajaxTestAll(['data:text/plain,a', 'data:text/plain,b'], 1000);
                [stored, getBody, postBody, headCode, all[0].body(), all[1].body(), all[0].callTime() >= 0].join('|');
                </js>"#,
                "http.overloads",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "stored|hello|posted|200|a|b|true");
    }

    #[test]
    fn ajax_test_all_reports_original_style_negative_call_time_on_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var all = java.ajaxTestAll([{}], 1000, true);
            [all[0].code(), all[0].callTime(), all[0].body().length > 0].join('|');
            </js>"#,
            serde_json::to_string(&format!("http://{addr}/refused")).unwrap()
        );
        let out = js
            .eval_rule_script(
                &script,
                "ajaxTestAll.callTime",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "500|-4|true");
    }

    #[test]
    fn java_http_helpers_pass_headers_and_call_timeout_to_rust_request() {
        let header_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let header_addr = header_listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = header_listener.accept().unwrap();
            let mut buffer = [0_u8; 2048];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /headers "), "{request}");
            assert!(
                request.contains("X-Test: rust") || request.contains("x-test: rust"),
                "{request}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nheaders",
                )
                .unwrap();
        });

        let slow_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let slow_addr = slow_listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = slow_listener.accept().unwrap();
            let mut buffer = [0_u8; 256];
            let _ = stream.read(&mut buffer);
            thread::sleep(Duration::from_millis(250));
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
            );
        });

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var connectBody = java.connect({}, JSON.stringify({{'X-Test':'rust'}}), 1000).body();
            var timeoutBody = java.get({}, {{}}, 20).body();
            [connectBody, timeoutBody.indexOf('error sending request') >= 0].join('|');
            </js>"#,
            serde_json::to_string(&format!("http://{header_addr}/headers")).unwrap(),
            serde_json::to_string(&format!("http://{slow_addr}/slow")).unwrap()
        );
        let out = js
            .eval_rule_script(
                &script,
                "http.timeout.headers",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "headers|true");
    }

    #[test]
    fn java_http_get_head_post_do_not_follow_redirects_like_jsoup_helpers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
            assert!(request.starts_with("GET /start "), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var response = java.get({}, {{}}, 1000);
            [response.statusCode(), response.header('Location'), response.url()].join('|');
            </js>"#,
            serde_json::to_string(&format!("http://{addr}/start")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "http.redirect.noFollow",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, format!("302|/final|http://{addr}/start"));
        handle.join().unwrap();
    }

    #[test]
    fn java_http_response_preserves_duplicate_headers_like_jsoup_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /multi "), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nSet-Cookie: sid=abc; Path=/\r\nSet-Cookie: theme=dark; Path=/\r\nX-Multi: one\r\nX-Multi: two\r\nContent-Length: 5\r\nConnection: close\r\n\r\nmulti",
                )
                .unwrap();
        });

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var response = java.get({}, {{}}, 1000);
            var multiCount = response.headersList().filter(function(entry) {{
              return String(entry[0]).toLowerCase() === 'x-multi';
            }}).length;
            [
              response.header('set-cookie'),
              response.headers('set-cookie').join(','),
              response.headers('x-multi').join(','),
              multiCount,
              response.contentType()
            ].join('|');
            </js>"#,
            serde_json::to_string(&format!("http://{addr}/multi")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "http.response.duplicateHeaders",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(
            out,
            "sid=abc; Path=/|sid=abc; Path=/,theme=dark; Path=/|one,two|2|text/plain; charset=UTF-8"
        );
        handle.join().unwrap();
    }

    #[test]
    fn analyze_url_js_host_exposes_response_bytes_stream_and_header_map() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 2048];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /login-check "), "{request}");
            assert!(request.contains("x-login: 1"), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nchecked",
                )
                .unwrap();
        });

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            java.ruleUrl = {};
            initUrl();
            getHeaderMap().putAll({{"X-Login": "1"}});
            var response = getResponse();
            java.ruleUrl = "data:text/plain;base64,aGVsbG8=";
            initUrl();
            var bytes = java.getByteArray();
            var input = java.getInputStream();
            var strResponse = getStrResponse();
            var first = input.read();
            [
              response.code(),
              response.body(),
              strResponse.body(),
              java.bytesToStr(bytes, "UTF-8"),
              first,
              input.available()
            ].join("|");
            </js>"#,
            serde_json::to_string(&format!("http://{addr}/login-check")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "analyzeUrl.responseBytesStream",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "202|checked|hello|hello|104|4");
        handle.join().unwrap();
    }

    #[test]
    fn java_ajax_all_preserves_response_metadata_like_single_http_helpers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("GET /ajax-all "), "{request}");
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Type: text/plain; charset=UTF-8\r\nX-Multi: one\r\nX-Multi: two\r\nContent-Length: 8\r\nConnection: close\r\n\r\najax-all",
                )
                .unwrap();
        });

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var responses = java.ajaxAll([{}]);
            var response = responses[0];
            var multiCount = response.headersList().filter(function(entry) {{
              return String(entry[0]).toLowerCase() === 'x-multi';
            }}).length;
            [
              response.statusCode(),
              response.body(),
              response.contentType(),
              response.headers('x-multi').join(','),
              multiCount
            ].join('|');
            </js>"#,
            serde_json::to_string(&format!("http://{addr}/ajax-all")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "http.ajaxAll.metadata",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "201|ajax-all|text/plain; charset=UTF-8|one,two|2");
        handle.join().unwrap();
    }

    #[test]
    fn ajax_all_honors_and_skips_source_concurrent_rate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).unwrap_or(0);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
            }
        });

        let mut source = source();
        source.book_source_url = format!("rate-limit-test-{}", Uuid::new_v4());
        source.concurrent_rate = "1/80".to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var url = {};
            var start = Date.now();
            java.ajaxAll([url + "/limited-a", url + "/limited-b"]);
            var limited = Date.now() - start;
            start = Date.now();
            java.ajaxAll([url + "/skip-a", url + "/skip-b"], true);
            var skipped = Date.now() - start;
            [limited >= 60, skipped < limited].join("|");
            </js>"#,
            serde_json::to_string(&format!("http://{addr}")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "http.ajaxAll.concurrentRate",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "true|true");
        handle.join().unwrap();
    }

    #[test]
    fn source_put_concurrent_updates_rate_limit_for_later_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer).unwrap_or(0);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
            }
        });

        let mut source = source();
        source.book_source_url = format!("put-concurrent-test-{}", Uuid::new_v4());
        source.concurrent_rate.clear();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var url = {};
            source.putConcurrent("1/80");
            var start = Date.now();
            java.ajaxAll([url + "/limited-a", url + "/limited-b"]);
            var limited = Date.now() - start;
            source.putConcurrent("0");
            start = Date.now();
            java.ajaxAll([url + "/unlimited-a", url + "/unlimited-b"]);
            var unlimited = Date.now() - start;
            [limited >= 60, unlimited < 60].join("|");
            </js>"#,
            serde_json::to_string(&format!("http://{addr}")).unwrap()
        );

        let out = js
            .eval_rule_script(
                &script,
                "source.putConcurrent",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();

        assert_eq!(out, "true|true");
        handle.join().unwrap();
    }

    #[test]
    fn java_http_response_wrappers_fail_fast_on_invalid_internal_json() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                r#"<js>
                java.__httpRequestRaw = function() { return "not-json"; };
                java.get("data:text/plain,hello", {});
                </js>"#,
                "http.response.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_HTTP_RESPONSE_ERROR__"), "{err}");
        assert!(err.contains("http.response.invalid"), "{err}");

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                r#"<js>
                java.__connectRaw = function() { return "not-json"; };
                java.connect("data:text/plain,hello");
                </js>"#,
                "connect.response.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_HTTP_RESPONSE_ERROR__"), "{err}");
        assert!(err.contains("connect.response.invalid"), "{err}");
    }

    #[test]
    fn js_host_http_helpers_apply_url_option_js_and_body_js() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for expected in ["ajax", "connect", "all", "request", "cache"] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]);
                assert!(
                    request.starts_with(&format!("GET /{expected} HTTP/1.1")),
                    "{request}"
                );
                assert!(request.contains("x-debug: 1"), "{request}");
                let body = expected.as_bytes();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            function opt(path, target) {{
              return BASE + "/" + path + "," + JSON.stringify({{
                js: "result.replace('" + path + "','" + target + "')",
                bodyJs: "result.toUpperCase()",
                headers: {{ "X-Debug": "1" }}
              }});
            }}
            [
              java.ajax(opt("start", "ajax")),
              java.connect(opt("start", "connect")).body(),
              java.ajaxAll([opt("start", "all")])[0].body(),
              request(opt("start", "request")),
              java.cacheFile(opt("start", "cache"), 0)
            ].join("|");
            </js>"#
        )
        .replace("BASE", &serde_json::to_string(&base).unwrap());

        let out = js
            .eval_rule_script(&script, "host.http.urlOptionJs", "", &base, "", 1)
            .unwrap();
        handle.join().unwrap();

        assert_eq!(out, "AJAX|CONNECT|ALL|REQUEST|CACHE");
    }

    #[test]
    fn global_request_supports_method_body_headers_and_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("POST /submit HTTP/1.1"), "{request}");
            assert!(
                request.contains("X-Request-Test: rust")
                    || request.contains("x-request-test: rust"),
                "{request}"
            );
            assert!(request.ends_with("name=legado"), "{request}");
            let body = b"posted";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            request(BASE + "/submit", "POST", "name=legado", {{ "X-Request-Test": "rust" }}, 1000);
            </js>"#
        )
        .replace("BASE", &serde_json::to_string(&base).unwrap());

        let out = js
            .eval_rule_script(&script, "global.request.post", "", &base, "", 1)
            .unwrap();
        handle.join().unwrap();

        assert_eq!(out, "posted");
    }

    #[test]
    fn java_ajax_all_fails_fast_on_internal_json_errors() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();

        let err = js
            .eval_rule_script(
                r#"<js>
                java.__ajaxAllRaw = function() { return "not-json"; };
                java.ajaxAll(["data:text/plain,a"]);
                </js>"#,
                "ajaxAll.invalid.response",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_AJAX_ALL_ERROR__"), "{err}");
        assert!(err.contains("ajaxAll.invalid.response"), "{err}");

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let raw = js
            .eval_rule_script(
                "<js>java.__ajaxAllRaw('{bad json')</js>",
                "ajaxAll.invalid.urlList",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert!(raw.contains("__LEGADO_AJAX_ALL_ERROR__"), "{raw}");
        assert!(raw.contains("invalid URL list JSON"), "{raw}");
    }

    #[test]
    fn global_request_fails_fast_on_request_errors() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "<js>request('ftp://example.test/file')</js>",
                "global.request.error",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_REQUEST_ERROR__"), "{err}");
        assert!(err.contains("ftp://example.test/file"), "{err}");
        assert!(err.contains("global.request.error"), "{err}");
    }

    #[test]
    fn java_cache_file_fails_fast_on_request_errors() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "<js>java.cacheFile('ftp://example.test/file', 0)</js>",
                "java.cacheFile.error",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("java.cacheFile failed"), "{err}");
        assert!(err.contains("__LEGADO_REQUEST_ERROR__"), "{err}");
        assert!(err.contains("ftp://example.test/file"), "{err}");
        assert!(err.contains("java.cacheFile.error"), "{err}");
    }

    #[test]
    fn aes_base64_decode_to_string_handles_xh_variable_comment() {
        let json = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../sources/rssSource_XH发布页.json"),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let data = value[0]["variableComment"].as_str().unwrap();
        let out = super::aes_base64_decode_to_string(
            data,
            "####xiao-han&&&&",
            "AES/ECB/PKCS7Padding",
            "",
        )
        .unwrap();
        assert!(out.contains("function user_Check"), "{out}");

        let mut source = source();
        source.extra = serde_json::json!({ "variableComment": data });
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#####"<js>
                eval(String(java.aesBase64DecodeToString(source.variableComment, "####xiao-han&&&&", "AES/ECB/PKCS7Padding", "")));
                typeof user_Check;
                </js>"#####,
                "aes.evalScript",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "function");
    }

    #[test]
    fn java_file_helpers_roundtrip_text_in_rust_store() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.writeTxtFile('scripts/import-roundtrip.js', 'globalThis.importedValue = 42;');
                var text = java.readTxtFile('scripts/import-roundtrip.js');
                var bytes = java.readFile('scripts/import-roundtrip.js');
                eval(java.importScript('scripts/import-roundtrip.js'));
                [text, java.bytesToStr(bytes), importedValue, java.fileExist('scripts/import-roundtrip.js'), java.deleteFile('scripts/import-roundtrip.js'), java.fileExist('scripts/import-roundtrip.js'), java.readFile('scripts/import-roundtrip.js') === null].join('|');
                </js>"#,
                "file.helpers",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(
            out,
            "globalThis.importedValue = 42;|globalThis.importedValue = 42;|42|true|true|false|true"
        );
    }

    #[test]
    fn java_read_txt_file_honors_explicit_charset_for_rust_binary_files() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.__writeBytesFileHex('/gbk.txt', java.strToBytes('中文', 'GBK').__hex);
                [java.readTxtFile('/gbk.txt'), java.readTxtFile('/gbk.txt', 'GBK')].join('|');
                </js>"#,
                "file.readTxtFile.charset",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "中文|中文");
    }

    #[test]
    fn java_virtual_file_helpers_preserve_empty_file_existence() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                java.__writeBytesFileHex('/empty.bin', '');
                var file = java.getFile('/empty.bin');
                [java.fileExist('/empty.bin'), java.readFile('/empty.bin').length, file.exists(), file.length()].join('|');
                </js>"#,
                "file.empty.exists",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "true|0|true|0");
    }

    #[test]
    fn java_download_file_uses_rust_binary_store_and_zip_folder_helpers() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("a.txt", options).unwrap();
        writer.write_all(b"alpha").unwrap();
        writer.start_file("b.txt", options).unwrap();
        writer.write_all(b"beta").unwrap();
        writer.start_file("gbk.txt", options).unwrap();
        let (gbk, _, _) = encoding_rs::GBK.encode("中文");
        writer.write_all(gbk.as_ref()).unwrap();
        let archive_bytes = writer.finish().unwrap().into_inner();
        let archive_data_url = format!(
            "data:application/zip;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(&archive_bytes)
        );

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var url = {};
            var saved = java.downloadFile(url + ',{{"type":"zip"}}');
            var bytes = java.readFile(saved);
            var entry = java.getZipStringContent(saved, 'a.txt');
            var folder = java.unzipFile(saved);
            var text = java.getTxtInFolder(folder);
            var gone = java.deleteFile(saved);
            [saved.slice(-4), bytes.length > 20, entry, folder.indexOf('archive/') === 0, text.indexOf('alpha\nbeta\n中文') === 0, gone, java.readFile(saved) === null].join('|');
            </js>"#,
            serde_json::to_string(&archive_data_url).unwrap()
        );
        let out = js
            .eval_rule_script(
                &script,
                "file.download.binaryZip",
                "",
                "https://zip.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, ".zip|true|alpha|true|true|true|true");
    }

    #[test]
    fn java_deprecated_download_file_hex_uses_rust_binary_store() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var path = java.__downloadHexFile('68656c6c6f', 'https://example.test/file.bin,{"type":"txt"}');
                [path.slice(-4), java.bytesToStr(java.readFile(path)), java.__downloadHexFile('00', 'https://example.test/file.bin') === ''].join('|');
                </js>"#,
                "file.download.hex",
                "",
                "https://zip.example/",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, ".txt|hello|true");
    }

    #[test]
    fn java_base64_decode_honors_charset_argument() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                [
                  java.base64Decode('5Lit5paH'),
                  java.base64Decode('1tDOxA==', 'GBK'),
                  java.base64Decode('5Lit5paH', 0)
                ].join('|');
                </js>"#,
                "base64Decode.charset",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "中文|中文|中文");
    }

    #[test]
    fn java_base64_decode_helpers_fail_fast_on_invalid_input() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                "<js>java.base64Decode('@@@not-base64@@@')</js>",
                "base64.decode.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_BASE64_ERROR__"), "{err}");
        assert!(err.contains("base64.decode.invalid"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>java.base64DecodeToByteArray('@@@not-base64@@@')</js>",
                "base64.bytes.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_BASE64_ERROR__"), "{err}");
        assert!(err.contains("base64.bytes.invalid"), "{err}");

        let err = js
            .eval_rule_script(
                "<js>Base64.getDecoder().decode('@@@not-base64@@@')</js>",
                "base64.decoder.invalid",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("__LEGADO_BASE64_ERROR__"), "{err}");
        assert!(err.contains("base64.decoder.invalid"), "{err}");
    }

    #[test]
    fn java_aes_cbc_base64_helpers_use_iv() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var enc = java.aesEncodeToBase64String('hello', '1234567890123456', 'AES/CBC/PKCS7Padding', '6543210987654321');
                java.aesBase64DecodeToString(enc, '1234567890123456', 'AES/CBC/PKCS7Padding', '6543210987654321');
                </js>"#,
                "crypto.aesCbc",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn java_aes_helpers_fail_fast_on_crypto_errors() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let err = js
            .eval_rule_script(
                r#"<js>
                java.aesBase64DecodeToString('not-base64', 'bad-key', 'AES/CBC/PKCS7Padding', 'bad-iv');
                </js>"#,
                "crypto.aes.failFast",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("crypto.aes.failFast"), "{err}");
        assert!(
            !err.ends_with("JavaScript produced an empty result"),
            "{err}"
        );

        let err = js
            .eval_rule_script(
                r#"<js>
                var cipher = Cipher.getInstance('AES/CBC/PKCS5Padding');
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(java.strToBytes('bad-key'), 'AES'), new IvParameterSpec(java.strToBytes('bad-iv')));
                cipher.doFinal(java.hexDecodeToByteArray('00'));
                </js>"#,
                "crypto.cipher.failFast",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("crypto.cipher.failFast"), "{err}");
        assert!(
            !err.ends_with("JavaScript produced an empty result"),
            "{err}"
        );
    }

    #[test]
    fn java_symmetric_crypto_helpers_cover_aes_des_and_triple_des() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var aes = java.createSymmetricCrypto('AES/CBC/PKCS7Padding', '1234567890123456', '6543210987654321');
                var aesEnc = aes.encryptBase64('hello');
                var desEnc = java.desEncodeToBase64String('hello', '12345678', 'DES/CBC/PKCS5Padding', '87654321');
                var desDec = java.desBase64DecodeToString(desEnc, '12345678', 'DES/CBC/PKCS5Padding', '87654321');
                var tdesEnc = java.tripleDESEncodeBase64Str('hello', '123456789012345678901234', 'CBC', 'PKCS5Padding', '87654321');
                var tdesDec = java.tripleDESDecodeStr(tdesEnc, '123456789012345678901234', 'CBC', 'PKCS5Padding', '87654321');
                [
                  aes.decryptStr(aesEnc),
                  desDec,
                  tdesDec,
                  aes.encryptHex('x').length > 0,
                  aes.decrypt(aesEnc).length,
                  typeof java.desEncodeToString('hello', '12345678', 'DES/CBC/PKCS5Padding', '87654321')
                ].join('|');
                </js>"#,
                "crypto.symmetric",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "hello|hello|hello|true|5|string");
    }

    #[test]
    fn java_legacy_aes_byte_helpers_match_original_wrapper_shape() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var key = '1234567890123456';
                var iv = '6543210987654321';
                var transformation = 'AES/CBC/PKCS7Padding';
                var encB64 = java.aesEncodeToBase64String('hello', key, transformation, iv);
                var b64Key = java.base64Encode(key);
                var b64Iv = java.base64Encode(iv);
                var encBytes = java.aesEncodeToByteArray('hello', key, transformation, iv);
                var encB64Bytes = java.aesEncodeToBase64ByteArray('hello', key, transformation, iv);
                var decBytes = java.aesDecodeToByteArray(encB64, key, transformation, iv);
                var decBytes2 = java.aesBase64DecodeToByteArray(encB64, key, transformation, iv);
                [
                  java.bytesToStr(decBytes),
                  java.bytesToStr(decBytes2),
                  encBytes.length > 0,
                  java.bytesToStr(encB64Bytes) === encB64,
                  java.aesEncodeToString(encB64, key, transformation, iv),
                  java.aesDecodeArgsBase64Str(encB64, b64Key, 'CBC', 'PKCS7Padding', b64Iv)
                ].join('|');
                </js>"#,
                "crypto.legacyAesBytes",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "hello|hello|true|true|hello|hello");
    }

    #[test]
    fn java_triple_des_base64_key_helpers_match_old_wrappers() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                var key = '123456789012345678901234';
                var b64Key = java.base64Encode(key);
                var enc = java.tripleDESEncodeArgsBase64Str('hello', b64Key, 'ECB', 'PKCS5Padding', '');
                java.tripleDESDecodeArgsBase64Str(enc, b64Key, 'ECB', 'PKCS5Padding', '');
                </js>"#,
                "crypto.tripleDesBase64Args",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn java_asymmetric_crypto_and_sign_helpers_match_documented_chain_shape() {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

        let mut rng = rsa::rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = public.to_public_key_pem(LineEnding::LF).unwrap();

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            var publicKey = {};
            var privateKey = {};
            var cipher = java.createAsymmetricCrypto('RSA/ECB/PKCS1Padding')
                .setPublicKey(publicKey)
                .setPrivateKey(privateKey);
            var encrypted = cipher.encryptBase64('hello', true);
            var decrypted = cipher.decryptStr(encrypted, false);
            var signature = java.createSign('SHA256withRSA')
                .setPrivateKey(privateKey)
                .signHex('hello');
            [decrypted, encrypted.length > 100, signature.length > 100].join('|');
            </js>"#,
            serde_json::to_string(&public_pem).unwrap(),
            serde_json::to_string(&private_pem).unwrap()
        );
        let out = js
            .eval_rule_script(
                &script,
                "crypto.asymmetric",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "hello|true|true");
    }

    #[test]
    fn java_asymmetric_crypto_unsupported_direction_fails_fast() {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};

        let mut rng = rsa::rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();

        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let script = format!(
            r#"<js>
            java.createAsymmetricCrypto('RSA/ECB/PKCS1Padding')
                .setPrivateKey({})
                .encryptBase64('hello', false);
            </js>"#,
            serde_json::to_string(&private_pem).unwrap()
        );
        let err = js
            .eval_rule_script(
                &script,
                "crypto.asymmetric.unsupported",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("private-key encryption is not supported"),
            "{err}"
        );
    }

    #[test]
    fn source_login_header_roundtrips_map_cookie_and_remove() {
        let mut js = JsRuntime::new(&source(), AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                source.putLoginHeader(JSON.stringify({Cookie: 'a=1; b=2', Referer: 'https://r.example/'}));
                var header = source.getLoginHeader();
                var referer = source.getLoginHeaderMap().Referer;
                var cookie = java.getCookie(source.getKey ? source.getKey() : '');
                source.removeLoginHeader();
                [header.indexOf('Cookie') >= 0, referer, cookie, source.getLoginHeader()].join('|');
                </js>"#,
                "source.loginHeader",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "true|https://r.example/|a=1; b=2|");
    }

    #[test]
    fn source_get_header_map_matches_base_source_header_merge_shape() {
        let mut source = source();
        source.header = r#"{"X-Source":"1"}"#.to_string();
        let mut js = JsRuntime::new(&source, AnalyzerSession::default()).unwrap();
        let out = js
            .eval_rule_script(
                r#"<js>
                source.putLoginHeader(JSON.stringify({"X-Login":"2", Cookie:"sid=abc"}));
                var plain = source.getHeaderMap();
                var merged = source.getHeaderMap(true);
                [
                  source.header.indexOf('X-Source') >= 0,
                  plain.get('X-Source'),
                  plain.get('User-Agent').indexOf('LegadoRustAnalyzer') >= 0,
                  merged.get('X-Login'),
                  merged.get('Cookie')
                ].join('|');
                </js>"#,
                "source.getHeaderMap",
                "",
                "https://example.test",
                "",
                1,
            )
            .unwrap();
        assert_eq!(out, "true|1|true|2|sid=abc");
    }

    struct CookieEchoServer {
        base_url: String,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl CookieEchoServer {
        fn start(request_count: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                for _ in 0..request_count {
                    if let Ok((stream, _)) = listener.accept() {
                        handle_cookie_request(stream);
                    }
                }
            });
            Self {
                base_url: format!("http://{addr}"),
                handle: Some(handle),
            }
        }

        fn base_url(&self) -> String {
            self.base_url.clone()
        }

        fn is_finished(&self) -> bool {
            self.handle
                .as_ref()
                .is_none_or(|handle| handle.is_finished())
        }
    }

    impl Drop for CookieEchoServer {
        fn drop(&mut self) {
            while !self.is_finished() {
                let _ = std::net::TcpStream::connect(self.base_url.trim_start_matches("http://"));
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn handle_cookie_request(mut stream: TcpStream) {
        let mut buffer = [0u8; 4096];
        let read = stream.read(&mut buffer).unwrap_or(0);
        let request = String::from_utf8_lossy(&buffer[..read]);
        let first_line = request.lines().next().unwrap_or_default();
        let path = first_line.split_whitespace().nth(1).unwrap_or("/");
        let cookie = request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("cookie").then(|| value.trim())
            })
            .unwrap_or_default();
        let (body, set_cookie) = match path {
            "/seed" => ("seed".to_string(), Some("sid=server; Path=/")),
            "/set2" => ("set2".to_string(), Some("token=two; Path=/")),
            "/echo" => (cookie.to_string(), None),
            _ => (String::new(), None),
        };
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(cookie) = set_cookie {
            response.push_str(&format!("Set-Cookie: {cookie}\r\n"));
        }
        response.push_str("\r\n");
        response.push_str(&body);
        stream.write_all(response.as_bytes()).unwrap();
    }

    #[test]
    fn java_toast_log_helpers_dispatch_to_android_platform_when_attached() {
        let host = Rc::new(RecordingPlatformHost {
            calls: RefCell::new(Vec::new()),
        });
        let mut js =
            JsRuntime::new_with_platform(&source(), AnalyzerSession::default(), Some(host.clone()))
                .unwrap();
        js.eval_rule_script(
            r#"<js>
            java.longToast(1);
            java.toast({ ok: true });
            java.log("hello");
            "ok";
            </js>"#,
            "loginUi.platformToast",
            "",
            "https://example.test",
            "",
            1,
        )
        .unwrap();
        let calls = host.calls.borrow();
        assert!(calls.iter().any(|call| call == r#"longToast:["1"]"#));
        assert!(calls
            .iter()
            .any(|call| call == r#"toast:["{\"ok\":true}"]"#));
        assert!(calls.iter().any(|call| call == r#"log:["hello"]"#));
    }
}
