use tokio::net::TcpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::{BytesMut, BufMut};
use std::net::{SocketAddr, IpAddr};
use std::env;

const CQL_VERSION: u8 = 0x04;
const OPCODE_STARTUP: u8 = 0x01;
const OPCODE_AUTH_RESPONSE: u8 = 0x0F;
const OPCODE_AUTHENTICATE: u8 = 0x03;
const OPCODE_READY: u8 = 0x02;
const OPCODE_ERROR: u8 = 0x00;
const OPCODE_AUTH_SUCCESS: u8 = 0x10;

async fn connect_and_auth(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    nr_shards: u16,
    this_shard: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip: IpAddr = host.parse()?;
    let remote_addr = SocketAddr::new(ip, port);
    let mut source_port = 40000;
    let mut stream;
    loop {
        if source_port % nr_shards == this_shard {
            let local_addr = SocketAddr::new(ip, source_port);
            let socket = TcpSocket::new_v4()?;
            // Set SO_REUSEADDR
            socket.set_reuseaddr(true)?;
            match socket.bind(local_addr) {
                Ok(_) => {
                    match socket.connect(remote_addr).await {
                        Ok(s) => {
                            stream = s;
                            break;
                        }
                        Err(e) => {
                            // If connect fails, try next port
                            source_port += 1;
                            continue;
                        }
                    }
                }
                Err(_) => {
                    // If bind fails, try next port
                    source_port += 1;
                    continue;
                }
            }
        } else {
            source_port += 1;
        }
    }

    // Send STARTUP
    let mut body = BytesMut::new();
    // [string map] with "CQL_VERSION": "3.0.0"
    body.put_u16(1); // map size
    body.put_u16(b"CQL_VERSION".len() as u16); // key len (11)
    body.put_slice(b"CQL_VERSION");
    body.put_u16(b"3.0.0".len() as u16); // value len (5)
    body.put_slice(b"3.0.0");

    let mut frame = BytesMut::new();
    frame.put_u8(CQL_VERSION); // version
    frame.put_u8(0); // flags
    frame.put_u16(0); // stream
    frame.put_u8(OPCODE_STARTUP); // opcode
    frame.put_u32(body.len() as u32); // length
    frame.extend_from_slice(&body);

    stream.write_all(&frame).await?;

    // Read response
    let mut header = [0u8; 9];
    stream.read_exact(&mut header).await?;
    let opcode = header[4];
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    let mut body = vec![0u8; length as usize];
    stream.read_exact(&mut body).await?;

    if opcode == OPCODE_AUTHENTICATE {
        // Send AUTH_RESPONSE (SASL: user + password)
        let token = format!("\x00{}\x00{}", user, password).into_bytes();
        let mut auth_body = BytesMut::new();
        auth_body.put_u32(token.len() as u32);
        auth_body.extend_from_slice(&token);

        let mut auth_frame = BytesMut::new();
        auth_frame.put_u8(CQL_VERSION);
        auth_frame.put_u8(0);
        auth_frame.put_u16(0);
        auth_frame.put_u8(OPCODE_AUTH_RESPONSE);
        auth_frame.put_u32(auth_body.len() as u32);
        auth_frame.extend_from_slice(&auth_body);

        stream.write_all(&auth_frame).await?;

        // Read response
        stream.read_exact(&mut header).await?;
        let opcode = header[4];
        let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        let mut body = vec![0u8; length as usize];
        stream.read_exact(&mut body).await?;

        if opcode == OPCODE_AUTH_SUCCESS {
            println!("Authenticated successfully!");
            return Ok(());
        } else if opcode == OPCODE_ERROR {
            return Err("Authentication error".into());
        }
    } else if opcode == OPCODE_READY {
        println!("No authentication required, connected!");
        return Ok(());
    } else if opcode == OPCODE_ERROR {
        return Err("Startup error".into());
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        println!("Usage: {} host port user password nr_shards this_shard", args[0]);
        return;
    }
    let host = &args[1];
    let port: u16 = args[2].parse().unwrap();
    let user = &args[3];
    let password = &args[4];
    let nr_shards: u16 = args[5].parse().unwrap();
    let this_shard: u16 = args[6].parse().unwrap();

    loop {
        match connect_and_auth(host, port, user, password, nr_shards, this_shard).await {
            Ok(_) => break,
            Err(_) => {
                // No backoff, immediate retry
            }
        }
    }
}
