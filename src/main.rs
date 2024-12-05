use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use ipnet::Ipv4Net;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportProtocol};
use pnet::transport::TransportChannelType::Layer4;
use pnet::util;
use rand::random;
use serde::Deserialize;
use tokio::sync::Semaphore;
use tokio::task;

const ICMP_TIMEOUT: Duration = Duration::from_secs(1);
const ICMP_SIZE: usize = 64;
const MAX_CONCURRENT_PINGS: usize = 100;

fn parse_cidr(cidr: &str) -> Result<Vec<String>, String> {
    if cidr.contains("/") {
        let net4 = Ipv4Net::from_str(cidr).map_err(|_| "CIDR 转换失败".to_string())?;
        let ips = net4.hosts().map(|it| it.to_string()).collect();
        Ok(ips)
    } else {
        Ok(vec![cidr.to_string()])
    }
}

fn create_icmp_packet<'a>(icmp_header: &'a mut [u8]) -> MutableEchoRequestPacket<'a> {
    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_header).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_identifier(random::<u16>());
    icmp_packet.set_sequence_number(1);
    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);
    icmp_packet
}

fn ping_ip(target_ip: &str) -> Result<bool> {
    let target_ip = Ipv4Addr::from_str(target_ip).unwrap();
    let protocol = Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = transport_channel(4096, protocol)?;
    let mut iter = icmp_packet_iter(&mut rx);


    for _ in 0..3 {
        let mut icmp_header: [u8; ICMP_SIZE] = [0; ICMP_SIZE];
        let icmp_packet = create_icmp_packet(&mut icmp_header);
        let start_time = Instant::now();
        tx.send_to(icmp_packet, target_ip.into())?;
        if let Ok((packet, addr)) = iter.next() {
            if addr == target_ip {
                if let Some(echo_reply) = EchoReplyPacket::new(packet.packet()) {
                    if echo_reply.get_icmp_type() == IcmpTypes::EchoReply {
                        let rtt = start_time.elapsed();
                        // println!("Ping {} success, RTT: {:?}", target_ip, rtt);
                        return Ok(true);
                    } else {
                        // 包类型和预期不一样
                        return Ok(false);
                    }
                } // 重试，读取包失败
            } else {
                // 数据包地址和发送地址不一致
                return Ok(false);
            }
        }
        //没有收到包,重试
    }
    // 3次重试都失败了
    Ok(false)
}

#[derive(Debug,Deserialize)]
struct ApplicationConfig {
    ips: Vec<String>,
}
#[tokio::main]
async fn main() -> Result<()> {
    let config_file = std::env::current_dir().unwrap().join("config.yaml");
    let config = config::Config::builder().add_source(config::File::from(config_file)).build()?;
    let config = config.try_deserialize::<ApplicationConfig>()?;
    let range :Vec<&String>= config.ips.iter().map(|it|it).collect();

    // let range = vec![
    //     "192.168.0.0/24",
    // ];


    let mut handles = Vec::new();
    for x in range {
        println!("正在处理：{}", x);
        let ips = parse_cidr(x).unwrap();
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_PINGS));
        for ip in ips {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let ip_clone = ip.clone();
            handles.push(task::spawn(async move {
                match ping_ip(&ip) {
                    Ok(result) => {
                        if result {
                            println!("{}: {}", ip_clone, result);
                        }
                    }
                    Err(err) => {
                        println!("{}", err);
                    }
                }
                drop(permit); // 释放信号量
            }));
        }
    }


    for handle in handles {
        handle.await?;
    }

    Ok(())
}
