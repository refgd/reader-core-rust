use std::fmt::{Display, Formatter};

pub type Result<T> = std::result::Result<T, Diagnostic>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticKind {
    SourceParse,
    RuleParse,
    Request,
    JavaScript,
    UnsupportedPlatformApi,
    UnsupportedRule,
    Extraction,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub message: String,
    pub source_name: Option<String>,
    pub base_url: Option<String>,
    pub rule_path: Option<String>,
    pub script_excerpt: Option<String>,
    pub request_url: Option<String>,
    pub status: Option<u16>,
}

impl Display for Diagnostic {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)?;
        if let Some(source_name) = &self.source_name {
            write!(f, "; source={source_name}")?;
        }
        if let Some(base_url) = &self.base_url {
            write!(f, "; baseUrl={base_url}")?;
        }
        if let Some(rule_path) = &self.rule_path {
            write!(f, "; rulePath={rule_path}")?;
        }
        if let Some(script_excerpt) = &self.script_excerpt {
            write!(f, "; script={script_excerpt}")?;
        }
        if let Some(request_url) = &self.request_url {
            write!(f, "; requestUrl={request_url}")?;
        }
        if let Some(status) = self.status {
            write!(f, "; status={status}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}

impl Diagnostic {
    pub fn new(kind: DiagnosticKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source_name: None,
            base_url: None,
            rule_path: None,
            script_excerpt: None,
            request_url: None,
            status: None,
        }
    }

    pub fn with_source(mut self, source_name: impl Into<String>) -> Self {
        self.source_name = Some(source_name.into());
        self
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn with_rule_path(mut self, rule_path: impl Into<String>) -> Self {
        self.rule_path = Some(rule_path.into());
        self
    }

    pub fn with_script(mut self, script: impl AsRef<str>) -> Self {
        let script = script.as_ref();
        self.script_excerpt = Some(script.chars().take(240).collect());
        self
    }

    pub fn with_request(mut self, request_url: impl Into<String>, status: Option<u16>) -> Self {
        self.request_url = Some(request_url.into());
        self.status = status;
        self
    }
}

impl From<anyhow::Error> for Diagnostic {
    fn from(value: anyhow::Error) -> Self {
        Self::new(DiagnosticKind::Extraction, value.to_string())
    }
}
