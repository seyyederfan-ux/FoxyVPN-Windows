// FoxyVPN Windows — Tauri commands & app state
mod fxa;
mod guardian;
mod proto;
mod tunnel;

use proto::*;
use serde_json::json;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex as AsyncMutex;

pub struct AppState {
    pub auth: AsyncMutex<Option<RuntimeAuth>>,
    pub countries: AsyncMutex<Vec<VpnCountry>>,
    pub tunnel: AsyncMutex<Option<tunnel::Tunnel>>,
    pub logs: Arc<AsyncMutex<Vec<String>>>,
    pub connected_since: AsyncMutex<Option<i64>>,
    pub edge_ip: AsyncMutex<Option<(String, String)>>,
    pub settings: AsyncMutex<Settings>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Settings {
    pub socks_port: u16,
    pub http_port: u16,
    pub selected_code: String, // country code or "" = recommended
    pub selected_city: String,
    #[serde(default = "default_true")]
    pub full_tunnel: bool,
}

fn default_true() -> bool { true }

impl Default for Settings {
    fn default() -> Self {
        Settings { socks_port: 1080, http_port: 8080, selected_code: String::new(), selected_city: String::new(), full_tunnel: true }
    }
}

fn settings_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    let dir = app.path().app_data_dir().ok()?;
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("settings.json"))
}

fn auth_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    let dir = app.path().app_data_dir().ok()?;
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("auth.json"))
}

#[tauri::command]
async fn login(app: AppHandle, state: State<'_, Arc<AppState>>, email: String, password: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let data = fxa::fxa_login(&client, &email, &password).await?;
    let session_token = data["sessionToken"].as_str().ok_or("no sessionToken in response")?.to_string();
    let verified = data["verified"].as_bool().unwrap_or(true);
    if !verified {
        // 2FA needed
        let mut auth = state.auth.lock().await;
        *auth = Some(RuntimeAuth {
            session_token,
            access_token: String::new(),
            refresh_token: None,
            expires_at: 0,
        });
            return Ok(json!({"needs2fa": true}));
    }
    finish_login(&app, &state, session_token).await?;
    Ok(json!({"needs2fa": false}))
}

#[tauri::command]
async fn submit_2fa(state: State<'_, Arc<AppState>>, code: String) -> Result<(), String> {
    let auth = state.auth.lock().await.clone();
    let Some(a) = auth else { return Err("no pending session".into()) };
    let client = http_client();
    fxa::fxa_verify_code(&client, &a.session_token, &code).await?;
    Ok(())
}

#[tauri::command]
async fn complete_2fa(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let auth = state.auth.lock().await.clone();
    let Some(a) = auth else { return Err("no pending session".into()) };
    finish_login(&app, &state, a.session_token).await?;
    Ok(())
}

async fn finish_login(app: &AppHandle, state: &State<'_, Arc<AppState>>, session_token: String) -> Result<(), String> {
    let client = http_client();
    let oauth = fxa::fxa_oauth(&client, &session_token).await?;
    let access = oauth["access_token"].as_str().ok_or("no access_token")?.to_string();
    let refresh = oauth["refresh_token"].as_str().map(|s| s.to_string());
    let expires_in = oauth["expires_in"].as_i64().unwrap_or(86400);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let auth = RuntimeAuth {
        session_token,
        access_token: access,
        refresh_token: refresh,
        expires_at: now + expires_in,
    };
    if let Some(p) = auth_path(app) {
        if let Ok(json_v) = serde_json::to_value(&auth) {
            if let Ok(txt) = serde_json::to_string(&json_v) {
                let _ = std::fs::write(&p, txt);
            }
        }
    }
    *state.auth.lock().await = Some(auth);
    Ok(())
}

#[tauri::command]
async fn get_auth_state(state: State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    let a = state.auth.lock().await;
    Ok(match &*a {
        Some(auth) => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            json!({"signedIn": auth.access_token.len() > 10 && auth.expires_at > now, "has2faPending": auth.access_token.is_empty() && !auth.session_token.is_empty()})
        }
        None => json!({"signedIn": false, "has2faPending": false}),
    })
}

#[tauri::command]
async fn logout(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    if let Some(t) = state.tunnel.lock().await.take() { t.stop(); }
    *state.auth.lock().await = None;
    if let Some(p) = auth_path(&app) { let _ = std::fs::remove_file(p); }
    Ok(())
}

#[tauri::command]
async fn get_entitlement(state: State<'_, Arc<AppState>>) -> Result<Entitlement, String> {
    let auth = current_access(&state).await?;
    let client = http_client();
    guardian::guardian_status(&client, &auth).await
}

async fn current_access(state: &State<'_, Arc<AppState>>) -> Result<String, String> {
    let mut guard = state.auth.lock().await;
    let Some(a) = guard.as_mut() else { return Err("not signed in".into()) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    if a.expires_at <= now + 60 {
        if let Some(rt) = &a.refresh_token {
            let client = http_client();
            if let Ok(v) = fxa::fxa_refresh(&client, rt).await {
                if let Some(at) = v["access_token"].as_str() {
                    a.access_token = at.to_string();
                    a.expires_at = now + v["expires_in"].as_i64().unwrap_or(86400);
                    return Ok(a.access_token.clone());
                }
            }
        }
        return Err("access token expired — sign in again".into());
    }
    Ok(a.access_token.clone())
}

#[tauri::command]
async fn fetch_countries(state: State<'_, Arc<AppState>>) -> Result<Vec<VpnCountry>, String> {
    let client = http_client();
    let list = guardian::fetch_server_list(&client).await?;
    *state.countries.lock().await = list.clone();
    Ok(list)
}

#[tauri::command]
async fn connect(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    country_code: Option<String>,
    city_code: Option<String>,
) -> Result<(), String> {
    // disconnect existing
    if let Some(t) = state.tunnel.lock().await.take() { t.stop(); }

    let auth = current_access(&state).await?;
    let client = http_client();

    // pick target
    let countries = state.countries.lock().await;
    let (sel_code, sel_city) = { let st = state.settings.lock().await; (st.selected_code.clone(), st.selected_city.clone()) };
    let code = country_code.unwrap_or(sel_code);
    let city = city_code.unwrap_or(sel_city);
    let mut candidates: Vec<(String, u16)> = Vec::new();
    for c in countries.iter() {
        if !code.is_empty() && !c.code.eq_ignore_ascii_case(&code) { continue; }
        for city_ in &c.cities {
            if !city.is_empty() && !city_.code.eq_ignore_ascii_case(&city) { continue; }
            for s in &city_.servers {
                candidates.push((s.connect_host.clone(), s.connect_port));
            }
        }
    }
    drop(countries);
    if candidates.is_empty() { return Err("no servers for the selected location".into()); }

    // acquire proxy pass (activate if rejected)
    let pass = match guardian::guardian_proxy_pass(&client, &auth).await {
        Ok(p) => p,
        Err(e) if e.starts_with("token-invalid") => {
            guardian::guardian_activate(&client, &auth).await?;
            guardian::guardian_proxy_pass(&client, &auth).await?
        }
        Err(e) => return Err(e),
    };

    // try candidates in order
    let mut last_err = String::new();
    let mut tunnel_opt = None;
    let socks_p = state.settings.lock().await.socks_port;
    let http_p = state.settings.lock().await.http_port;
    let full_t = state.settings.lock().await.full_tunnel;
    for (host, port) in candidates.iter().take(5) {
        let attempt = tunnel::start_tunnel(
            host.clone(), *port, pass.token.clone(),
            socks_p, http_p, state.logs.clone(), full_t,
        );
        match tokio::time::timeout(std::time::Duration::from_secs(20), attempt).await {
            Ok(Ok(t)) => { tunnel_opt = Some(t); break; }
            Ok(Err(e)) => { last_err = e; continue; }
            Err(_) => { last_err = format!("timeout dialing {host}:{port} (20s)"); continue; }
        }
    }
    let t = tunnel_opt.ok_or_else(|| format!("all dial attempts failed; last: {last_err}"))?;
    *state.tunnel.lock().await = Some(t);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    *state.connected_since.lock().await = Some(now);

    // verify exit
    let app2 = app.clone();
    tokio::spawn(async move {
        let app = app2;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if let Ok((ip, loc)) = fetch_exit_info().await {
            let _ = app.emit("vpn-edge-ip", json!({"ip": ip, "country": loc}));
            let sel = code.to_uppercase();
            if !sel.is_empty() && !loc.eq_ignore_ascii_case(&sel) {
                let _ = app.emit("vpn-mismatch", json!({
                    "message": format!("Traffic is NOT exiting via {sel} (exit: {loc}). The tunnel is not carrying your traffic — check Settings/Logs, or the tunnel fell back to proxy-only mode.")
                }));
            }
        }
    });
    let _ = app.emit("vpn-state", "CONNECTED");
    Ok(())
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<(), String> {
    if let Some(t) = state.tunnel.lock().await.take() { t.stop(); }
    *state.connected_since.lock().await = None;
    *state.edge_ip.lock().await = None;
    let _ = app.emit("vpn-state", "DISCONNECTED");
    Ok(())
}

#[tauri::command]
async fn get_state(state: State<'_, Arc<AppState>>) -> Result<serde_json::Value, String> {
    let t = state.tunnel.lock().await;
    let since = *state.connected_since.lock().await;
    Ok(json!({
        "connected": t.is_some(),
        "connectedSince": since,
        "socksPort": t.as_ref().map(|x| x.socks_port).unwrap_or(state.settings.lock().await.socks_port),
        "httpPort": t.as_ref().map(|x| x.http_port).unwrap_or(state.settings.lock().await.http_port),
        "edge": t.as_ref().map(|x| format!("{}:{}", x.edge_host, x.edge_port)),
    }))
}

#[tauri::command]
async fn get_logs(state: State<'_, Arc<AppState>>) -> Result<Vec<String>, String> {
    Ok(state.logs.lock().await.clone())
}

#[tauri::command]
async fn save_settings(app: AppHandle, state: State<'_, Arc<AppState>>, settings: Settings) -> Result<(), String> {
    *state.settings.lock().await = settings.clone();
    if let Some(p) = settings_path(&app) {
        let _ = std::fs::write(p, serde_json::to_string(&settings).unwrap());
    }
    Ok(())
}

#[tauri::command]
async fn load_settings(app: AppHandle, state: State<'_, Arc<AppState>>) -> Result<Settings, String> {
    if let Some(p) = settings_path(&app) {
        if let Ok(txt) = std::fs::read_to_string(p) {
            if let Ok(s) = serde_json::from_str::<Settings>(&txt) {
                *state.settings.lock().await = s.clone();
                return Ok(s);
            }
        }
    }
    Ok(state.settings.lock().await.clone())
}

pub fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let logs: Arc<AsyncMutex<Vec<String>>> = Arc::new(AsyncMutex::new(Vec::new()));
            app.manage(Arc::new(AppState {
                auth: AsyncMutex::new(None),
                countries: AsyncMutex::new(Vec::new()),
                tunnel: AsyncMutex::new(None),
                logs,
                connected_since: AsyncMutex::new(None),
                edge_ip: AsyncMutex::new(None),
                settings: AsyncMutex::new(Settings::default()),
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            login, submit_2fa, complete_2fa, get_auth_state, logout,
            get_entitlement, fetch_countries, connect, disconnect,
            get_state, get_logs, save_settings, load_settings
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
