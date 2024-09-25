use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::fs::File;
use std::io::{BufReader, Read};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use base64::{Engine as _, engine::general_purpose};
use std::env;


async fn handle_client(mut client_stream: tokio_rustls::server::TlsStream<TcpStream>, username: &str, password: &str) {
    let mut buffer = [0; 4096];
    let mut request = Vec::new();

    // Read the client's request
    loop {
        let n = client_stream.read(&mut buffer).await.unwrap();
        request.extend_from_slice(&buffer[..n]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // Parse the request
    let request_str = String::from_utf8_lossy(&request);
    let lines: Vec<&str> = request_str.lines().collect();
    if lines.is_empty() {
        return;
    }

    // Check for authentication
    let auth_header = lines.iter().find(|line| line.starts_with("Proxy-Authorization: Basic "));
    if let Some(auth_header) = auth_header {
        let auth_base64 = auth_header.trim_start_matches("Proxy-Authorization: Basic ");
        if let Ok(auth_decoded) = general_purpose::STANDARD.decode(auth_base64) {
            if let Ok(auth_str) = String::from_utf8(auth_decoded) {
                let auth_parts: Vec<&str> = auth_str.split(':').collect();
                if auth_parts.len() == 2 && auth_parts[0] == username && auth_parts[1] == password {
                    // 认证成功，继续处理代理请求
                    handle_proxy_request(client_stream, &lines).await;
                    return;
                }
            }
        }
    }


    // Authentication failed or not provided
    let response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n";
    client_stream.write_all(response.as_bytes()).await.unwrap();
}

async fn handle_proxy_request(mut client_stream: tokio_rustls::server::TlsStream<TcpStream>, request_lines: &[&str]) {
    let parts: Vec<&str> = request_lines[0].split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "CONNECT" {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client_stream.write_all(response.as_bytes()).await.unwrap();
        return;
    }

    // Extract host and port from the CONNECT request
    let host_port: Vec<&str> = parts[1].split(':').collect();
    if host_port.len() != 2 {
        let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        client_stream.write_all(response.as_bytes()).await.unwrap();
        return;
    }

    let host = host_port[0];
    let port = host_port[1];

    // Connect to the target server
    let mut server_stream = match TcpStream::connect(format!("{}:{}", host, port)).await {
        Ok(stream) => stream,
        Err(_) => {
            let response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            client_stream.write_all(response.as_bytes()).await.unwrap();
            return;
        }
    };

    // Send 200 OK to the client
    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    client_stream.write_all(response.as_bytes()).await.unwrap();

    // Start proxying data
    tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream).await.unwrap();
}

fn load_certs(path: &str) -> Vec<Certificate> {
    let mut file = File::open(path).expect("cannot open certificate file");
    let mut certs = vec![];
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).expect("cannot read certificate file");
    for cert in rustls_pemfile::certs(&mut BufReader::new(&bytes[..])).unwrap() {
        certs.push(Certificate(cert));
    }
    if certs.is_empty() {
        panic!("no certificates found in {}", path);
    }
    certs
}

fn load_keys(path: &str) -> PrivateKey {
    let mut file = File::open(path).expect("cannot open private key file");
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).expect("cannot read private key file");

    if let Ok(keys) = rustls_pemfile::ec_private_keys(&mut BufReader::new(&bytes[..])) {
        if !keys.is_empty() {
            return PrivateKey(keys[0].clone());
        }
    }

    panic!("no supported private key found in {}", path);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_path = "crt.crt";
    let key_path = "key.key";

    let certs = load_certs(cert_path);
    let key = load_keys(key_path);

    println!("Certificate and key loaded successfully");

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // 从命令行参数获取端口、用户名和密码
    let args: Vec<String> = env::args().collect();
    let port = if args.len() > 1 { args[1].parse::<u16>().unwrap_or(9443) } else { 9443 };
    let username = if args.len() > 2 { args[2].clone() } else { "default_user".to_string() };
    let password = if args.len() > 3 { args[3].clone() } else { "default_pass".to_string() };

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    println!("HTTPS proxy server listening on 0.0.0.0:{}", port);
    println!("Using username: {}", username);
    println!("Using password: {}", password);

    while let Ok((stream, _)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let username = username.clone();
        let password = password.clone();
        tokio::spawn(async move {
            if let Ok(stream) = acceptor.accept(stream).await {
                handle_client(stream, &username, &password).await;
            }
        });
    }

    Ok(())
}
