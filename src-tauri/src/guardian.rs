// Guardian client + server list
use crate::proto::*;
use base64::Engine;

fn jwt_expiry(token: &str) -> Option<i64> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 { return None; }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    v.get("exp").and_then(|e| e.as_i64())
}

async fn guardian_req(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    access_token: &str,
) -> Result<reqwest::Response, String> {
    let req = match method {
        "POST" => client.post(url).header("Content-Type", "application/json").body(""),
        _ => client.get(url),
    };
    let resp = req
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {access_token}"))
        .send().await.map_err(|e| e.to_string())?;
    Ok(resp)
}

pub async fn guardian_status(client: &reqwest::Client, access_token: &str) -> Result<Entitlement, String> {
    let url = format!("{GUARDIAN_ENDPOINT}/api/v1/fpn/status");
    let resp = guardian_req(client, "GET", &url, access_token).await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(format!("guardian status HTTP {status}: {}", &text[..text.len().min(300)]));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(Entitlement {
        subscribed: v["subscribed"].as_bool().unwrap_or(false),
        limited_bandwidth: v["limited_bandwidth"].as_bool().unwrap_or(false),
        quota_remaining: v.get("quotaRemaining").and_then(|x| x.as_i64()),
        quota_max: v.get("maxBytes").and_then(|x| x.as_i64()),
    })
}

pub async fn guardian_activate(client: &reqwest::Client, access_token: &str) -> Result<Entitlement, String> {
    let url = format!("{GUARDIAN_ENDPOINT}/api/v1/fpn/activate");
    let resp = guardian_req(client, "POST", &url, access_token).await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(format!("guardian activate HTTP {status}: {}", &text[..text.len().min(300)]));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(Entitlement {
        subscribed: v["subscribed"].as_bool().unwrap_or(false),
        limited_bandwidth: v["limited_bandwidth"].as_bool().unwrap_or(false),
        quota_remaining: None,
        quota_max: v.get("maxBytes").and_then(|x| x.as_i64()),
    })
}

pub async fn guardian_proxy_pass(client: &reqwest::Client, access_token: &str) -> Result<ProxyPass, String> {
    let url = format!("{GUARDIAN_ENDPOINT}/api/v1/fpn/token");
    let resp = guardian_req(client, "GET", &url, access_token).await?;
    let status = resp.status().as_u16();
    let quota_remaining = resp.headers().get("x-quota-remaining").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
    let quota_max = resp.headers().get("x-quota-limit").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
    let text = resp.text().await.map_err(|e| e.to_string())?;
    match status {
        401 | 403 => return Err("token-invalid".into()),
        429 => return Err("quota exceeded".into()),
        _ => {}
    }
    if status != 200 {
        return Err(format!("proxy pass HTTP {status}: {}", &text[..text.len().min(300)]));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let token = v["token"].as_str().unwrap_or("").to_string();
    if token.is_empty() { return Err("proxy pass response had no token".into()); }
    let expires_at = v["expires_at"].as_i64().filter(|&x| x > 0).or_else(|| jwt_expiry(&token)).unwrap_or(0);
    Ok(ProxyPass { token, expires_at, quota_remaining, quota_max })
}

pub async fn fetch_server_list(client: &reqwest::Client) -> Result<Vec<VpnCountry>, String> {
    let resp = client.get(SERVER_LIST_URL).header("Accept", "application/json").send()
        .await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if status != 200 {
        return Err(format!("server list HTTP {status}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(records) = v["data"].as_array() {
        for rec in records {
            let c = rec.get("country").unwrap_or(rec);
            let code = c["code"].as_str().unwrap_or("").to_string();
            let name = c["name"].as_str().unwrap_or("").to_string();
            if name.eq_ignore_ascii_case("CatchAll Anycast") || code.is_empty() { continue; }
            let mut cities = Vec::new();
            if let Some(city_arr) = c["cities"].as_array() {
                for city in city_arr {
                    let cname = city["name"].as_str().unwrap_or("").to_string();
                    let ccode = city["code"].as_str().unwrap_or("").to_string();
                    let mut servers = Vec::new();
                    if let Some(srv_arr) = city["servers"].as_array() {
                        for s in srv_arr {
                            let hostname = s["hostname"].as_str().unwrap_or("").to_string();
                            let port = s["port"].as_u64().unwrap_or(0) as u16;
                            let quarantined = s["quarantined"].as_bool().unwrap_or(false);
                            let mut connect_host = hostname.clone();
                            let mut connect_port = port;
                            if let Some(protos) = s["protocols"].as_array() {
                                for p in protos {
                                    if p["name"].as_str() == Some("connect") {
                                        connect_host = p["host"].as_str().unwrap_or("").to_string();
                                        if connect_host.is_empty() { connect_host = hostname.clone(); }
                                        connect_port = p["port"].as_u64().unwrap_or(0) as u16;
                                        if connect_port == 0 { connect_port = port; }
                                        break;
                                    }
                                }
                                if connect_host.is_empty() { continue; }
                            }
                            if hostname.is_empty() || quarantined { continue; }
                            servers.push(VpnServer { hostname, port, quarantined, connect_host, connect_port });
                        }
                    }
                    if !servers.is_empty() {
                        cities.push(VpnCity { name: cname, code: ccode, servers });
                    }
                }
            }
            if !cities.is_empty() { out.push(VpnCountry { name, code, cities }); }
        }
    }
    Ok(out)
}
