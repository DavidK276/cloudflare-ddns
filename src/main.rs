use clap::Parser;
use log::{debug, error, info, warn};
use rsdns::clients as dns;
use rsdns::{constants::Class, records::data::Aaaa, records::data::A};
use serde::Deserialize;
use serde_json::json;
use simplelog::{ColorChoice, CombinedLogger, LevelFilter, TermLogger, TerminalMode, WriteLogger};
use std::collections::HashMap;
use std::env::current_dir;
use std::fs;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

const API_ENDPOINT: &str = "https://api.cloudflare.com/client/v4/zones/";

#[derive(thiserror::Error, Debug)]
enum CfDdnsError {
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("parse error: {0}")]
    Parse(#[from] log::ParseLevelError),
    #[error("logger error: {0}")]
    Logger(#[from] log::SetLoggerError),
    #[error("http error: {0}")]
    Http(#[from] minreq::Error),
    #[error("dns error: {0}")]
    Dns(#[from] rsdns::Error),
}

#[derive(Parser)]
#[clap(author = "David Krchňavý", version, about = "Cloudflare DNS info updater", long_about = None)]
struct Zone {
    #[clap(short = 'z', long = "zone", value_parser)]
    name: String,
    #[clap(short = 'c', long = "config", value_parser, forbid_empty_values = true)]
    path: Option<String>,
}

#[derive(Deserialize, Debug)]
enum IPVersion {
    #[serde(rename = "A")]
    IPv4,
    #[serde(rename = "AAAA")]
    IPv6,
}
impl IPVersion {
    fn record_type(&self) -> String {
        match self {
            IPVersion::IPv4 => String::from("A"),
            IPVersion::IPv6 => String::from("AAAA"),
        }
    }
}

#[derive(Deserialize, Debug)]
struct CfResponse {
    result: Vec<serde_json::Value>,
    success: bool,
}

#[derive(Deserialize, Debug)]
struct CfZoneInfo {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct CfRecord {
    id: String,
    name: String,
    content: String,
    proxied: bool,
    ttl: i32,
}

#[derive(Deserialize, Debug)]
struct CfDnsConfigRecord {
    name: String,
    #[serde(rename = "type")]
    dns_type: IPVersion,
    proxied: bool,
    ttl: Option<i32>,
}

#[derive(Deserialize, Debug)]
struct CfDnsConfig {
    #[serde(rename = "cf_api_token")]
    api_token: String,
    #[serde(rename = "cf_records")]
    records: Vec<CfDnsConfigRecord>,
    log_level: String,
    resolving_method: String,
}

fn bearer_auth(api_token: &str) -> String {
    return format!("Bearer {}", api_token);
}

fn get_current_ip(version: IPVersion, method: &str) -> Result<IpAddr, CfDdnsError> {
    return match version {
        IPVersion::IPv4 => match method {
            "http" => {
                let res = minreq::get("https://ipv4.icanhazip.com").send()?;
                Ok(IpAddr::V4(
                    res.as_str()?.trim().to_string().parse().unwrap(),
                ))
            }
            "dns" => {
                let nameserver = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)), 53);
                let mut client =
                    dns::std::Client::new(dns::ClientConfig::with_nameserver(nameserver))?;
                let rrset = client.query_rrset::<A>("myip.opendns.com", Class::In)?;
                Ok(IpAddr::V4(rrset.rdata[0].address))
            }
            _ => panic!("Invalid resolving method in config"),
        },
        IPVersion::IPv6 => match method {
            "http" => {
                let res = minreq::get("https://ipv6.icanhazip.com").send()?;
                Ok(IpAddr::V6(
                    res.as_str()?.trim().to_string().parse().unwrap(),
                ))
            }
            "dns" => {
                let nameserver =
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(2620, 0, 0xccc, 0, 0, 0, 0, 2)), 53);
                let mut client =
                    dns::std::Client::new(dns::ClientConfig::with_nameserver(nameserver))?;
                let rrset =
                    client.query_rrset::<Aaaa>("resolver1.ipv6-sandbox.opendns.com", Class::In)?;
                Ok(IpAddr::V6(rrset.rdata[0].address))
            }
            _ => panic!("Invalid resolving method in config"),
        },
    };
}

type DnsRecords = (HashMap<String, CfRecord>, HashMap<String, CfRecord>);
fn get_zone_records(zone_uuid: &str, api_token: &str) -> Result<DnsRecords, CfDdnsError> {
    let url = format!("{}{}/dns_records", API_ENDPOINT, zone_uuid);
    let res_a = minreq::get(&url)
        .with_header("Authorization", bearer_auth(api_token))
        .with_param("type", "A")
        .send()?;
    let cf_res_a: CfResponse = serde_json::from_str(res_a.as_str()?)?;
    if !cf_res_a.success {
        panic!("Failed retrieving A zone records: {}", res_a.as_str()?);
    }
    let mut result_a: HashMap<String, CfRecord> = HashMap::new();
    for record_obj in cf_res_a.result {
        let record: CfRecord = serde_json::from_value(record_obj)?;
        result_a.insert(record.name.clone(), record);
    }

    let res_aaaa = minreq::get(url)
        .with_header("Authorization", bearer_auth(api_token))
        .with_param("type", "AAAA")
        .send()?;
    let cf_res_aaaa: CfResponse = serde_json::from_str(res_aaaa.as_str()?)?;
    if !cf_res_aaaa.success {
        panic!("Failed retrieving AAAA zone records: {}", res_aaaa.as_str()?);
    }
    let mut result_aaaa: HashMap<String, CfRecord> = HashMap::new();
    for record_obj in cf_res_aaaa.result {
        let record: CfRecord = serde_json::from_value(record_obj)?;
        result_aaaa.insert(record.name.clone(), record);
    }
    Ok((result_a, result_aaaa))
}

fn get_zone_info(zone_name: &str, api_token: &str) -> Result<CfZoneInfo, CfDdnsError> {
    let res = minreq::get(API_ENDPOINT)
        .with_header("Authorization", bearer_auth(api_token))
        .with_param("name", zone_name)
        .send()?;
    let cf_res: CfResponse = serde_json::from_str(res.as_str()?)?;
    if !cf_res.success {
        panic!("Failed retrieving zone info: {}", res.as_str()?);
    }
    let zone_obj = cf_res.result[0].to_owned();
    let zone_info: CfZoneInfo = serde_json::from_value(zone_obj)?;
    Ok(zone_info)
}

fn main() -> Result<(), CfDdnsError> {
    let cwd = current_dir()?;
    let zone = Zone::parse();
    let path = match zone.path {
        Some(value) => value,
        None => format!("{}/zones/{}.json", cwd.to_string_lossy(), zone.name),
    };
    let file_str = File::open(path)?;
    let config: CfDnsConfig = serde_json::from_reader(&file_str)?;

    let log_level: LevelFilter = LevelFilter::from_str(config.log_level.as_str())?;
    let mut logger_config = simplelog::ConfigBuilder::new();
    match logger_config.set_time_offset_to_local() {
        Ok(l) => l,
        Err(l) => l,
    };
    let log_dir_path = format!("{}/log", cwd.to_string_lossy());
    match fs::read_dir(&log_dir_path) {
        Ok(_) => (),
        Err(_) => fs::create_dir(format!("{}/log", cwd.to_string_lossy()))?,
    };
    let log_file_path = format!("{}/{}.log", log_dir_path, zone.name);
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path)?;
    CombinedLogger::init(vec![
        WriteLogger::new(log_level, logger_config.build(), log_file),
        TermLogger::new(
            log_level,
            logger_config.build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
    ])?;

    let zone_info = get_zone_info(&zone.name, &config.api_token)?;
    debug!("Zone {} info retrieved", zone_info.name);

    let (records_a, records_aaaa) = get_zone_records(&zone_info.id, &config.api_token)?;
    debug!(
        "Zone {} records retrieved, A: {}, AAAA: {}",
        zone_info.name,
        records_a.len(),
        records_aaaa.len()
    );

    let current_ipv4 = if !records_a.is_empty() {
        get_current_ip(IPVersion::IPv4, &config.resolving_method)?
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let current_ipv6 = if !records_aaaa.is_empty() {
        get_current_ip(IPVersion::IPv6, &config.resolving_method)?
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let mut updates = [0u16; 3];
    for config_record in config.records {
        let name: String = if config_record.name == "@" {
            String::from(&zone_info.name)
        } else {
            format!("{}.{}", config_record.name, zone_info.name)
        };
        let record = match config_record.dns_type {
            IPVersion::IPv4 => match records_a.get(&name) {
                Some(r) => r,
                None => {
                    warn!("Record {} with type A not found in zone, skipping", name);
                    updates[1] += 1;
                    continue;
                }
            },
            IPVersion::IPv6 => match records_aaaa.get(&name) {
                Some(r) => r,
                None => {
                    warn!("Record {} with type AAAA not found in zone, skipping", name);
                    updates[1] += 1;
                    continue;
                }
            },
        };
        let ttl = match config_record.ttl {
            Some(ttl) => {
                if config_record.proxied {
                    1
                } else if !(60..=86400).contains(&ttl) && ttl != 1 {
                    warn!(
                        "Update of record {} skipped due to bad TTL value",
                        record.name
                    );
                    continue;
                } else {
                    ttl
                }
            }
            None => record.ttl,
        };
        let (old_ip, new_ip) = match config_record.dns_type {
            IPVersion::IPv4 => (IpAddr::V4(record.content.parse().unwrap()), current_ipv4),
            IPVersion::IPv6 => (IpAddr::V6(record.content.parse().unwrap()), current_ipv6),
        };
        if old_ip == new_ip && record.ttl == ttl && record.proxied == config_record.proxied {
            debug!("Update of record {} not needed, skipping", record.name);
            updates[2] += 1;
            continue;
        }
        debug!("Updating record {} with content: {}", record.name, new_ip);
        let url = format!("{}{}/dns_records/{}", API_ENDPOINT, zone_info.id, record.id);
        let body = json!({
            "ttl": ttl,
            "name": name,
            "type": config_record.dns_type.record_type(),
            "content": new_ip,
            "proxied": config_record.proxied
        });
        let res = minreq::put(url)
            .with_header("Authorization", bearer_auth(&config.api_token))
            .with_json(&body)?
            .send()?;
        let cf_response: serde_json::Value = serde_json::from_str(res.as_str()?)?;
        match cf_response["success"].as_bool() {
            Some(success) => {
                if success {
                    debug!("Update successful");
                    updates[0] += 1;
                } else {
                    warn!(
                        "Update of record {} with content {} failed",
                        record.name, new_ip
                    );
                    updates[1] += 1;
                }
            }
            None => (),
        }
    }
    info!(
        "Updates finished, {} succeeded, {} failed, {} skipped",
        updates[0], updates[1], updates[2]
    );
    Ok(())
}
