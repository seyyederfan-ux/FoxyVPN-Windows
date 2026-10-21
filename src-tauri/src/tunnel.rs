// H2 CONNECT tunnel (h2 crate) + local SOCKS5/HTTP proxy servers
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

pub fn now_stamp() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let s = d.as_secs();
    format!("[{:02}:{:02}:{:02}]", (s % 86400) / 3600, (s % 3600) / 60, s % 60)
}

fn tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

pub struct H2Upstream {
    pub send_request: Mutex<h2::client::SendRequest<bytes::Bytes>>,
    _handle: tokio::task::JoinHandle<()>,
}

impl H2Upstream {
    pub async fn connect(host: &str, port: u16) -> Result<Self, String> {
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await.map_err(|e| format!("TCP {addr}: {e}"))?;
        tcp.set_nodelay(true).ok();
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let tls = tls_connector().connect(server_name, tcp).await.map_err(|e| format!("TLS: {e}"))?;
        let (client, conn) = h2::client::handshake(tls).await.map_err(|e| format!("H2 handshake: {e}"))?;
        let handle = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(H2Upstream { send_request: Mutex::new(client), _handle: handle })
    }

    /// Open an HTTP/2 CONNECT stream to target and return the duplex stream.
    pub async fn open_stream(
        &self,
        bearer: &str,
        target_authority: &str,
    ) -> Result<Duplex, String> {
        let req = self.send_request.lock().await.clone();
        let mut ready = req.ready().await.map_err(|e| e.to_string())?;
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(target_authority)
            .header("proxy-authorization", format!("Bearer {bearer}"))
            .body(())
            .unwrap();
        let (response, send_stream) = ready.send_request(request, false).map_err(|e| e.to_string())?;
        let resp = response.await.map_err(|e| format!("CONNECT {target_authority}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("upstream rejected CONNECT: HTTP {}", resp.status()));
        }
        let recv = resp.into_body();
        Ok(Duplex { send: send_stream, recv })
    }
}

pub struct Duplex {
    send: h2::SendStream<bytes::Bytes>,
    recv: h2::RecvStream,
}

impl AsyncRead for Duplex {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            match self.recv.poll_data(cx) {
                std::task::Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    let take = len.min(buf.remaining());
                    buf.put_slice(&chunk[..take]);
                    if take < len {
                        // shouldn't happen (ReadBuf larger than chunk) but handle
                    }
                    let _ = self.recv.flow_control().release_capacity(len);
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Duplex {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.send.reserve_capacity(data.len());
        // poll capacity
        loop {
            match self.send.poll_capacity(cx) {
                std::task::Poll::Ready(Some(Ok(n))) if n > 0 => {
                    let n = n.min(data.len());
                    let chunk = bytes::Bytes::copy_from_slice(&data[..n]);
                    match self.send.send_data(chunk, false) {
                        Ok(()) => return std::task::Poll::Ready(Ok(n)),
                        Err(e) => return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e))),
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e)))
                }
                std::task::Poll::Ready(None) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "h2 stream closed")))
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
                _ => return std::task::Poll::Pending,
            }
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        let _ = self.send.send_data(bytes::Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

pub struct Tunnel {
    pub proxy_pass: Arc<Mutex<String>>,
    pub socks_port: u16,
    pub http_port: u16,
    pub edge_host: String,
    pub edge_port: u16,
    pub logs: Arc<Mutex<Vec<String>>>,
    stop: watch::Sender<bool>,
}

impl Tunnel {
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
}

async fn push_log(logs: &Arc<Mutex<Vec<String>>>, msg: &str) {
    let mut l = logs.lock().await;
    l.push(format!("{} {msg}", now_stamp()));
    if l.len() > 400 { l.drain(..200); }
}


pub async fn start_tunnel(
    edge_host: String,
    edge_port: u16,
    proxy_pass: String,
    socks_port: u16,
    http_port: u16,
    logs: Arc<Mutex<Vec<String>>>,
) -> Result<Tunnel, String> {
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let upstream = Arc::new(H2Upstream::connect(&edge_host, edge_port).await?);
    {
        let mut l = logs.lock().await;
        l.push(format!("{} HTTP/2 tunnel established to {edge_host}:{edge_port}", now_stamp()));
    }

    // SOCKS5
    let socks_listener = TcpListener::bind(("127.0.0.1", socks_port)).await
        .map_err(|e| format!("bind socks {socks_port}: {e}"))?;
    {
        let mut l = logs.lock().await;
        l.push(format!("{} local SOCKS5 proxy on 127.0.0.1:{socks_port}", now_stamp()));
    }

    // HTTP proxy (optional port 0 = disabled)
    let http_listener = if http_port > 0 {
        Some(TcpListener::bind(("127.0.0.1", http_port)).await
            .map_err(|e| format!("bind http {http_port}: {e}"))?)
    } else { None };

    let pass = Arc::new(Mutex::new(proxy_pass));

    let socks_task_pass = pass.clone();
    let socks_task_logs = logs.clone();
    let socks_upstream = upstream.clone();
    tokio::spawn(async move {
        loop {
            if *stop_rx.borrow() { break; }
            tokio::select! {
                _ = stop_rx.changed() => break,
                Ok((client, _peer)) = socks_listener.accept() => {
                    let up = socks_upstream.clone();
                    let pass = socks_task_pass.clone();
                    let logs = socks_task_logs.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks5(client, up, pass, logs).await {
                            let _ = e;
                        }
                    });
                }
                else => break,
            }
        }
    });

    if let Some(hl) = http_listener {
        let pass2 = pass.clone();
        let logs2 = logs.clone();
        let up2 = upstream.clone();
        let mut stop2 = stop_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop2.changed() => break,
                    Ok((client, _)) = hl.accept() => {
                        let up = up2.clone();
                        let pass = pass2.clone();
                        let logs = logs2.clone();
                        tokio::spawn(async move {
                            let _ = handle_http_proxy(client, up, pass, logs).await;
                        });
                    }
                    else => break,
                }
            }
        });
    }

    Ok(Tunnel {
        proxy_pass: pass,
        socks_port,
        http_port,
        edge_host,
        edge_port,
        logs,
        stop: stop_tx,
    })
}

async fn read_exact_or_err<T: AsyncRead + Unpin>(s: &mut T, buf: &mut [u8]) -> Result<(), String> {
    s.read_exact(buf).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn handle_socks5(
    mut client: TcpStream,
    upstream: Arc<H2Upstream>,
    pass: Arc<Mutex<String>>,
    logs: Arc<Mutex<Vec<String>>>,
) -> Result<(), String> {
    // greeting
    let mut hdr = [0u8; 2];
    read_exact_or_err(&mut client, &mut hdr).await?;
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    read_exact_or_err(&mut client, &mut methods).await?;
    client.write_all(&[0x05, 0x00]).await.map_err(|e| e.to_string())?; // no auth

    // request
    let mut head = [0u8; 4];
    read_exact_or_err(&mut client, &mut head).await?;
    let cmd = head[1];
    if cmd != 0x01 { return Err("only CONNECT supported".into()); }
    let (target, authority) = match head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            read_exact_or_err(&mut client, &mut ip).await?;
            let mut pb = [0u8; 2];
            read_exact_or_err(&mut client, &mut pb).await?;
            let port = u16::from_be_bytes(pb);
            let a = format!("{}.{}.{}.{}:{port}", ip[0], ip[1], ip[2], ip[3]);
            (a.clone(), a)
        }
        0x03 => {
            let mut l = [0u8; 1];
            read_exact_or_err(&mut client, &mut l).await?;
            let mut host = vec![0u8; l[0] as usize];
            read_exact_or_err(&mut client, &mut host).await?;
            let mut pb = [0u8; 2];
            read_exact_or_err(&mut client, &mut pb).await?;
            let port = u16::from_be_bytes(pb);
            let h = String::from_utf8(host).map_err(|_| "bad host")?;
            (format!("{h}:{port}"), format!("{h}:{port}"))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            read_exact_or_err(&mut client, &mut ip).await?;
            let mut pb = [0u8; 2];
            read_exact_or_err(&mut client, &mut pb).await?;
            let port = u16::from_be_bytes(pb);
            let a = format!("[::{}]:{port}", hex_short(&ip));
            (a.clone(), a)
        }
        _ => return Err("bad atyp".into()),
    };

    let bearer = pass.lock().await.clone();
    let stream = upstream.open_stream(&bearer, &authority).await?;
    client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.map_err(|e| e.to_string())?;
    push_log(&logs, &format!("stream opened -> {target}")).await;
    let (mut sr, mut sw) = tokio::io::split(stream);
    let (mut cr, mut cw) = client.into_split();
    let up = tokio::io::copy(&mut cr, &mut sw);
    let down = tokio::io::copy(&mut sr, &mut cw);
    let _ = tokio::join!(up, down);
    Ok(())
}

fn hex_short(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

async fn handle_http_proxy(
    mut client: TcpStream,
    upstream: Arc<H2Upstream>,
    pass: Arc<Mutex<String>>,
    logs: Arc<Mutex<Vec<String>>>,
) -> Result<(), String> {
    // Read request head (until \r\n\r\n)
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = client.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 { return Ok(()); }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 64 * 1024 { return Err("header too large".into()); }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let first = head.lines().next().unwrap_or_default().to_string();
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 { return Err("bad request".into()); }
    let target = parts[1].to_string();
    if !parts[0].eq_ignore_ascii_case("CONNECT") {
        // Plain HTTP proxying (forward absolute-URI GET/POST through tunnel)
        let authority = url::Url::parse(&target).ok()
            .and_then(|u| u.host_str().map(|h| format!("{}:{}", h, u.port_or_known_default().unwrap_or(80))))
            .ok_or("bad URL")?;
        let bearer = pass.lock().await.clone();
        let stream = upstream.open_stream(&bearer, &authority).await?;
        let (mut sr, mut sw) = tokio::io::split(stream);
        sw.write_all(buf.as_slice()).await.ok();
        let (mut cr, mut cw) = client.into_split();
        let _ = tokio::join!(
            tokio::io::copy(&mut cr, &mut sw),
            tokio::io::copy(&mut sr, &mut cw)
        );
        return Ok(());
    }
    // CONNECT
    let bearer = pass.lock().await.clone();
    let stream = upstream.open_stream(&bearer, &target).await?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.ok();
    push_log(&logs, &format!("CONNECT {target}")).await;
    let (mut sr, mut sw) = tokio::io::split(stream);
    let (mut cr, mut cw) = client.into_split();
    let _ = tokio::join!(
        tokio::io::copy(&mut cr, &mut sw),
        tokio::io::copy(&mut sr, &mut cw)
    );
    Ok(())
}
