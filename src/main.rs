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

struct ConnectionServer {
    listener: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
}

impl ConnectionServer {
    fn new(listener: TcpListener, config: Arc<rustls::ServerConfig>,) -> Self {
        ConnectionServer {
            listener,
            connections: HashMap::new(),
            next_id: 1,
            tls_config: config,
        }
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

    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        let mut poll = mio::Poll::new().unwrap();
        poll.registry()
            .register(&mut self.listener, LISTENER, mio::Interest::READABLE)
            .unwrap();


        println!("Listening...");

        let mut events = mio::Events::with_capacity(256);
        loop {
            poll.poll(&mut events, None).unwrap();

            for event in events.iter() {
                match event.token() {
                    LISTENER => {
                        println!("Connection HAZZAH!");
                    }
                    _ => return Ok(()),
                }
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>>  {
    let mut server = {
        let listener = {
            let addr: net::SocketAddr = "0.0.0.0:8616".parse().unwrap();
            TcpListener::bind(addr).expect("Failed to listen on port")
        };

        let config = {
            let cert = ConnectionServer::load_cert("/home/emo/Certs/ss_cert");
            let priv_key = ConnectionServer::load_private_key("/home/emo/Certs/privkey.pem");
            ConnectionServer::load_config(cert, priv_key)
        };

        ConnectionServer::new(listener, config)
    };

    server.start()
}

