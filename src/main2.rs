use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
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
use tokio::io::AsyncReadExt;

const ICMP_TIMEOUT: Duration = Duration::from_secs(1);

fn parse_cidr(cidr: &str) -> Result<Vec<String>, String> {
    let net4 = Ipv4Net::from_str(cidr).map_err(|_| "cidr转换失败".to_string())?;
    let ips = net4.hosts().map(|it| it.to_string()).collect();
    Ok(ips)
}
const ICMP_SIZE: usize = 64;


/**
 * 创建 icmp EchoRequest 数据包
 */
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
    // 将 rx 接收到的数据包传化为 iterator
    let mut iter = icmp_packet_iter(&mut rx);
    let mut i = 1;


    loop {
        if i > 3 { return Ok(false); }
        i = i + 1;
        let mut icmp_header: [u8; ICMP_SIZE] = [0; ICMP_SIZE];
        let icmp_packet = create_icmp_packet(&mut icmp_header);
        // println!("icmp_packet:{:?}",icmp_packet);
        let timer = Arc::new(RwLock::new(Instant::now()));
        // 发送 ICMP 数据包
        tx.send_to(icmp_packet, target_ip.into())?;
        match iter.next() {
            // 匹配 EchoReplyPacket 数据包
            Ok((packet, addr)) => match EchoReplyPacket::new(packet.packet()) {
                Some(echo_reply) => {
                    if packet.get_icmp_type() == IcmpTypes::EchoReply {
                        let start_time = timer.read().unwrap();
                        //let identifier = echo_reply.get_identifier();
                        //let sequence_number =  echo_reply.get_sequence_number();
                        let rtt = Instant::now().duration_since(*start_time);
                        // println!(
                        //     "ICMP EchoReply received from {:?}: {:?} , Time:{:?}",
                        //     addr,
                        //     packet.get_icmp_type(),
                        //     rtt
                        // );
                        return Ok(true);
                    } else {
                        // println!(
                        //     "ICMP type other than reply (0) received from {:?}: {:?}",
                        //     addr,
                        //     packet.get_icmp_type()
                        // );
                        return Ok(false);
                    }
                }
                None => {}
            },
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    let ips = parse_cidr("192.168.0.0/24").unwrap();
    for ip in &ips {
        if let Ok(result) = ping_ip(ip){
            println!("{}:{}",ip, result);
        }
    }
    Ok(())
}

