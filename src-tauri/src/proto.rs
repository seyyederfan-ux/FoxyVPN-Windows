use serde::Serialize;

pub const FXA_AUTH_SERVER: &str = "https://api.accounts.firefox.com/v1";
pub const FIREFOX_CLIENT_ID: &str = "5882386c6d801776";
pub const OAUTH_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const PROTOCOL_VERSION: &str = "identity.mozilla.com/picl/v1/";
pub const GUARDIAN_ENDPOINT: &str = "https://vpn.mozilla.org";
pub const SERVER_LIST_URL: &str =
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";
pub const UA: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";
pub const EXIT_CHECK_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";

#[derive(Serialize, Clone)]
pub struct VpnCountry {
    pub name: String,
    pub code: String,
    pub cities: Vec<VpnCity>,
}

#[derive(Serialize, Clone)]
pub struct VpnCity {
    pub name: String,
    pub code: String,
    pub servers: Vec<VpnServer>,
}

#[derive(Serialize, Clone)]
pub struct VpnServer {
    pub hostname: String,
    pub port: u16,
    pub quarantined: bool,
    pub connect_host: String,
    pub connect_port: u16,
}

#[derive(Serialize, Clone)]
pub struct Entitlement {
    pub subscribed: bool,
    pub limited_bandwidth: bool,
    pub quota_remaining: Option<i64>,
    pub quota_max: Option<i64>,
}

#[derive(Serialize, Clone)]
pub struct ProxyPass {
    pub token: String,
    pub expires_at: i64,
    pub quota_remaining: Option<i64>,
    pub quota_max: Option<i64>,
}

#[derive(Clone, serde::Serialize)]
pub struct RuntimeAuth {
    pub session_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64,
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(UA)
        .danger_accept_invalid_certs(false)
        .build()
        .expect("client")
}

pub fn country_flag(code: &str) -> String {
    let c = code.to_uppercase();
    if c.len() != 2 {
        return String::new();
    }
    let b: Vec<char> = c.chars().collect();
    let a = 0x1F1E6u32 + (b[0] as u32 - 'A' as u32);
    let z = 0x1F1E6u32 + (b[1] as u32 - 'A' as u32);
    String::from_utf16(&[a as u16, z as u16]).unwrap_or_default()
}

pub async fn fetch_exit_info() -> Result<(String, String), String> {
    let txt = http_client().get(EXIT_CHECK_URL).send().await.map_err(|e| e.to_string())?
        .text().await.map_err(|e| e.to_string())?;
    let mut ip = String::new();
    let mut loc = String::new();
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix("ip=") { ip = v.to_string(); }
        if let Some(v) = line.strip_prefix("loc=") { loc = v.to_string(); }
    }
    Ok((ip, loc))
}
