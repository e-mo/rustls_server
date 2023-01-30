use std::fs;
use std::sync::Arc;
use std::net;
use std::error::Error;
use std::io::{BufReader, Read, Write};
use std::collections::HashMap;

use rustls;
use rustls_pemfile;

use mio::{self, net::{TcpListener, TcpStream}};

const LISTENER: mio::Token = mio::Token(0);

struct OpenConnection {}

struct TlsServer {
    listener: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    listener_token: mio::Token,
}

impl TlsServer {
    fn new(listener: TcpListener,
           config: Arc<rustls::ServerConfig>,
           listener_token: mio::Token) 
            -> Self {

        TlsServer {
            listener,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: config,
            listener_token,
        }
    }
}

fn main() -> Result<(), Box<dyn Error>>  {

    let cert = load_cert("/home/emo/Certs/ss_cert");
    let priv_key = load_private_key("/home/emo/Certs/privkey.pem");
    let config = load_config(cert, priv_key);

    let addr: net::SocketAddr = "0.0.0.0:8616".parse().unwrap();
    let mut listener = TcpListener::bind(addr).expect("Failed to listen on port");
    let listener_token = mio::Token(0);

    let mut server = TlsServer::new(listener, config, listener_token);


    let poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut server.listener, server.listener_token, mio::Interest::READABLE)
        .unwrap();

    Ok(())
}

fn load_cert(path: &str) -> Vec<rustls::Certificate> {
    // Load Cert
    let mut reader = BufReader::new (
        fs::File::open(path)
            .expect("Failed to open certificate file")
    );

    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(path: &str) -> rustls::PrivateKey {
    // Load Private Key
    let mut reader = BufReader::new(
        fs::File::open(path)
            .expect("Failed to open private key file")
    );

    loop {
        match rustls_pemfile::read_one(&mut reader)
                .expect("Failed ot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) 
                    => break rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) 
                    => break rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::ECKey(key)) 
                    => break rustls::PrivateKey(key),
            _ => panic!("No valid key found in key .pem file"),
        }
    }
}

fn load_config(cert: Vec<rustls::Certificate>, priv_key: rustls::PrivateKey)
        -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, priv_key)
        .expect("Bad certificate/key")
    )
}
