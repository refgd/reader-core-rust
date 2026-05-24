use publicsuffix::{List, Psl};
use std::net::IpAddr;
use std::sync::OnceLock;
use url::{Host, Url};

static PUBLIC_SUFFIX_LIST: OnceLock<List> = OnceLock::new();

fn public_suffix_list() -> &'static List {
    PUBLIC_SUFFIX_LIST.get_or_init(|| {
        List::from_bytes(include_bytes!("../assets/public_suffix_list.dat"))
            .expect("bundled public suffix list must parse")
    })
}

pub fn effective_tld_plus_one(input: &str) -> Option<String> {
    let url = Url::parse(input).ok()?;
    match url.host()? {
        Host::Ipv4(addr) => Some(addr.to_string()),
        Host::Ipv6(addr) => Some(addr.to_string()),
        Host::Domain(host) => {
            if host.parse::<IpAddr>().is_ok() {
                return Some(host.to_string());
            }
            public_suffix_list()
                .domain(host.to_ascii_lowercase().as_bytes())
                .and_then(|domain| {
                    std::str::from_utf8(domain.trim().as_bytes())
                        .ok()
                        .map(ToOwned::to_owned)
                })
                .or_else(|| Some(host.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::effective_tld_plus_one;

    #[test]
    fn effective_tld_plus_one_matches_public_suffix_semantics() {
        assert_eq!(
            effective_tld_plus_one("https://www.example.com/a").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            effective_tld_plus_one("http://www.biquge.com.cn").as_deref(),
            Some("biquge.com.cn")
        );
        assert_eq!(
            effective_tld_plus_one("https://bar.foo.appspot.com").as_deref(),
            Some("foo.appspot.com")
        );
    }

    #[test]
    fn effective_tld_plus_one_preserves_ip_hosts() {
        assert_eq!(
            effective_tld_plus_one("http://1.2.3.4/path").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            effective_tld_plus_one("http://[2001:db8::1]/path").as_deref(),
            Some("2001:db8::1")
        );
    }
}
