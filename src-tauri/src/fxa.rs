// FxA auth: PBKDF2+HKDF authPW, Hawk, oauth token
use crate::proto::*;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn hkdf_sha256(ikm: &[u8], info: &str, len: usize) -> Vec<u8> {
    // extract
    let mut mac = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();
    // expand
    let mut out = Vec::new();
    let mut t: Vec<u8> = Vec::new();
    let mut i: u8 = 1;
    while out.len() < len {
        let mut m = HmacSha256::new_from_slice(&prk).unwrap();
        m.update(&t);
        m.update(info.as_bytes());
        m.update(&[i]);
        t = m.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    // ring's pbkdf2
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, std::num::NonZeroU32::new(rounds).unwrap(), salt, password, &mut out);
    out
}

pub fn derive_auth_pw(email: &str, password: &str) -> String {
    let salt = format!("{PROTOCOL_VERSION}quickStretch:{email}");
    let quick = pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), 1000, 32);
    let auth = hkdf_sha256(&quick, &format!("{PROTOCOL_VERSION}authPW"), 32);
    hex(&auth)
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn derive_hawk_credentials(session_token_hex: &str) -> (String, Vec<u8>) {
    // FxA sessionToken is a HEX string (64 hex chars = 32 bytes), NOT base64
    let key = hex_decode(session_token_hex);
    let expanded = hkdf_sha256(&key, &format!("{PROTOCOL_VERSION}sessionToken"), 64);
    let id = hex(&expanded[..32]); // tokenId is hex as well
    (id, expanded[32..].to_vec())
}

fn hawk_header(method: &str, url: &url::Url, token_id: &str, hmac_key: &[u8], body: &[u8]) -> String {
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs().to_string();
    let mut nonce_b = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut nonce_b);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_b);
    let path = match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    };
    let payload_hash = if body.is_empty() {
        String::new()
    } else {
        let mut d = Sha256::new();
        d.update(b"hawk.1.payload\napplication/json\n");
        d.update(body);
        d.update(b"\n");
        B64.encode(d.finalize())
    };
    let normalized = format!(
        "hawk.1.header\n{ts}\n{nonce}\n{}\n{path}\n{}\n{}\n{payload_hash}\n\n",
        method.to_uppercase(), url.host_str().unwrap_or(""), url.port_or_known_default().unwrap_or(443).to_string()
    );
    let mut mac = HmacSha256::new_from_slice(hmac_key).unwrap();
    mac.update(normalized.as_bytes());
    let mac_b64 = B64.encode(mac.finalize().into_bytes());
    if payload_hash.is_empty() {
        format!("Hawk id=\"{token_id}\", ts=\"{ts}\", nonce=\"{nonce}\", mac=\"{mac_b64}\"")
    } else {
        format!("Hawk id=\"{token_id}\", ts=\"{ts}\", nonce=\"{nonce}\", mac=\"{mac_b64}\", hash=\"{payload_hash}\"")
    }
}

pub async fn fxa_do(
    client: &reqwest::Client,
    method: &str,
    path: &str,
    session_token: Option<&str>,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let url_s = format!("{FXA_AUTH_SERVER}{path}");
    let url: url::Url = url::Url::parse(&url_s).map_err(|e| e.to_string())?;
    let body_bytes = body.to_string().into_bytes();
    let mut req = match method {
        "POST" => client.post(url.clone()),
        _ => client.get(url.clone()),
    };
    req = req.header("Content-Type", "application/json").header("Accept", "application/json");
    if let Some(st) = session_token {
        let (id, key) = derive_hawk_credentials(st);
        req = req.header("Authorization", hawk_header(method, &url, &id, &key, &body_bytes));
    }
    if method == "POST" {
        req = req.body(body_bytes);
    }
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if status.as_u16() == 406 {
        return Err("fastly-challenge (406): try again or solve challenge".into());
    }
    if status.as_u16() >= 400 {
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let msg = v["message"].as_str().unwrap_or(&text).to_string();
        let errno = v["errno"].as_i64().unwrap_or(0);
        return Err(format!("FxA error (errno {errno}): {msg}"));
    }
    if text.is_empty() { Ok(json!({})) } else { serde_json::from_str(&text).map_err(|e| e.to_string()) }
}

pub async fn fxa_login(client: &reqwest::Client, email: &str, password: &str) -> Result<serde_json::Value, String> {
    let auth_pw = derive_auth_pw(email, password);
    let body = json!({"email": email, "authPW": auth_pw, "verificationMethod": "email-2fa"});
    match fxa_do(client, "POST", "/account/login", None, body).await {
        Ok(v) => Ok(v),
        Err(e) if e.contains("errno 107") => {
            let body = json!({"email": email, "authPW": derive_auth_pw(email, password)});
            fxa_do(client, "POST", "/account/login", None, body).await
        }
        Err(e) => Err(e),
    }
}

pub async fn fxa_verify_code(client: &reqwest::Client, session_token: &str, code: &str) -> Result<(), String> {
    let body = json!({"code": code});
    fxa_do(client, "POST", "/session/verify_code", Some(session_token), body).await.map(|_| ())
}

pub async fn fxa_oauth(client: &reqwest::Client, session_token: &str) -> Result<serde_json::Value, String> {
    let body = json!({
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "fxa-credentials",
        "scope": OAUTH_SCOPE,
        "access_type": "offline",
    });
    fxa_do(client, "POST", "/oauth/token", Some(session_token), body).await
}

pub async fn fxa_refresh(client: &reqwest::Client, refresh_token: &str) -> Result<serde_json::Value, String> {
    let body = json!({
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": OAUTH_SCOPE,
    });
    fxa_do(client, "POST", "/oauth/token", None, body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auth_pw_vector() {
        // cross-checked against independent Python reference implementation
        // (PBKDF2 1000 rounds + HKDF-SHA256, "identity.mozilla.com/picl/v1/authPW")
        assert_eq!(derive_auth_pw("andré@example.org", "pässwörd"), "247b675ffb4c46310bc87e26d712153abe5e1c90ef00a4784594f97ef54f2375");
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::proto::http_client;
    #[tokio::test]
    async fn login_flow_real() {
        let client = http_client();
        let e = fxa_login(&client, "sadafadas132@gmail.com", "wrong-password-123").await;
        // expect "Incorrect password" (errno 103) — if we get errno 110 the Hawk code is broken
        println!("login result: {:?}", e);
        assert!(e.is_err());
        let msg = e.err().unwrap();
        assert!(msg.contains("errno 103"), "unexpected: {msg}");
    }
    #[tokio::test]
    async fn oauth_hawk_paths() {
        // derive + hawk shouldn't panic; verify hawk id decodes
        let (id, key) = derive_hawk_credentials("c0c23186f9d13e9ba8fac6ef7e8a9f6c0c23186f9d13e9ba8fac6ef7e8a9f6c1");
        assert_eq!(key.len(), 32);
        assert_eq!(id.len(), 64); // hex token id
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
