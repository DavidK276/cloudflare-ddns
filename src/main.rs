use std::collections::HashMap;
use std::env::current_dir;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use clap::Parser;
use log::{debug, info, warn};
use rsdns::clients as dns;
use rsdns::{constants::Class, records::data::Aaaa, records::data::A};
use serde::Deserialize;
use serde_json::json;
use simplelog::{
    format_description, ColorChoice, CombinedLogger, LevelFilter, TermLogger, TerminalMode,
    WriteLogger,
};

const API_ENDPOINT: &str = "https://api.cloudflare.com/client/v4/zones/";
const HTTP_RESOLVER_IPV4: &str = "https://ipv4.icanhazip.com";
const HTTP_RESOLVER_IPV6: &str = "https://ipv6.icanhazip.com";
const DNS_RESOLVER_IPV4_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222));
const DNS_RESOLVER_IPV4_QUERY: &str = "myip.opendns.com";
const DNS_RESOLVER_IPV6_IP: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2620, 0, 0xccc, 0, 0, 0, 0, 0x2));
const DNS_RESOLVER_IPV6_QUERY: &str = "resolver1.ipv6-sandbox.opendns.com";

#[derive(Parser)]
#[clap(author = "David Krchňavý", version, about = "Cloudflare DNS info updater", long_about = None)]
struct ZoneArgs {
    #[clap(short = 'z', long = "zone", value_parser)]
    name: String,
    #[clap(short = 'c', long = "config", value_parser)]
    path: Option<String>,
}

#[derive(Deserialize, Debug)]
enum IPVersion {
    #[serde(rename = "A")]
    IPv4,
    #[serde(rename = "AAAA")]
    IPv6,
}

impl From<IPVersion> for String {
    fn from(value: IPVersion) -> Self {
        match value {
            IPVersion::IPv4 => String::from("A"),
            IPVersion::IPv6 => String::from("AAAA"),
        }
    }
}

#[derive(Deserialize, Debug)]
enum IPLookupMethod {
    #[serde(rename = "https")]
    Https,
    #[serde(rename = "dns")]
    Dns,
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
    resolving_method: IPLookupMethod,
}

fn bearer_auth(api_token: &str) -> String {
    format!("Bearer {}", api_token)
}

fn get_current_ip(version: IPVersion, method: &IPLookupMethod) -> Result<IpAddr, Box<dyn Error>> {
    match version {
        IPVersion::IPv4 => match method {
            IPLookupMethod::Https => {
                let res = minreq::get(HTTP_RESOLVER_IPV4).send()?;
                Ok(IpAddr::V4(res.as_str()?.trim().to_string().parse()?))
            }
            IPLookupMethod::Dns => {
                let nameserver = SocketAddr::new(DNS_RESOLVER_IPV4_IP, 53);
                let mut client =
                    dns::std::Client::new(dns::ClientConfig::with_nameserver(nameserver))?;
                let rrset = client.query_rrset::<A>(DNS_RESOLVER_IPV4_QUERY, Class::In)?;
                Ok(IpAddr::V4(rrset.rdata[0].address))
            }
        },
        IPVersion::IPv6 => match method {
            IPLookupMethod::Https => {
                let res = minreq::get(HTTP_RESOLVER_IPV6).send()?;
                Ok(IpAddr::V6(res.as_str()?.trim().to_string().parse()?))
            }
            IPLookupMethod::Dns => {
                let nameserver = SocketAddr::new(DNS_RESOLVER_IPV6_IP, 53);
                let mut client =
                    dns::std::Client::new(dns::ClientConfig::with_nameserver(nameserver))?;
                let rrset = client.query_rrset::<Aaaa>(DNS_RESOLVER_IPV6_QUERY, Class::In)?;
                Ok(IpAddr::V6(rrset.rdata[0].address))
            }
        },
    }
}

fn get_records_of_type(
    zone_uuid: &str,
    api_token: &str,
    dns_type: &str,
) -> Result<HashMap<String, CfRecord>, Box<dyn Error>> {
    let url = format!("{}{}/dns_records", API_ENDPOINT, zone_uuid);
    let response = minreq::get(&url)
        .with_header("Authorization", bearer_auth(api_token))
        .with_param("type", dns_type)
        .send()?;
    let cf_res_a: CfResponse = serde_json::from_str(response.as_str()?)?;
    if !cf_res_a.success {
        panic!("Failed retrieving A zone records: {}", response.as_str()?);
    }
    let mut result: HashMap<String, CfRecord> = HashMap::new();
    result.reserve(cf_res_a.result.len());
    for record_obj in cf_res_a.result {
        let record: CfRecord = serde_json::from_value(record_obj)?;
        result.insert(record.name.clone(), record);
    }
    Ok(result)
}

fn get_zone_info(zone_name: &str, api_token: &str) -> Result<CfZoneInfo, Box<dyn Error>> {
    let res = minreq::get(API_ENDPOINT)
        .with_header("Authorization", bearer_auth(api_token))
        .with_param("name", zone_name)
        .send()?;
    let cf_res: CfResponse = serde_json::from_str(res.as_str()?)?;
    if !cf_res.success {
        panic!("Failed retrieving zone info: {}", res.as_str()?);
    }
    let zone_obj = cf_res.result[0].clone();
    let zone_info: CfZoneInfo = serde_json::from_value(zone_obj)?;
    Ok(zone_info)
}

fn logger_init(log_level: &str, cwd: &str, zone_name: &str) -> Result<(), Box<dyn Error>> {
    let log_level = LevelFilter::from_str(log_level)?;
    let mut logger_config = simplelog::ConfigBuilder::new();
    logger_config.set_time_format_custom(format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
    ));
    match logger_config.set_time_offset_to_local() {
        Ok(l) => l,
        Err(l) => l,
    };
    let log_dir_path = format!("{}/log", &cwd);
    match fs::read_dir(&log_dir_path) {
        Ok(_) => (),
        Err(_) => fs::create_dir(format!("{}/log", &cwd))?,
    };
    let log_file_path = format!("{}/{}.log", log_dir_path, zone_name);
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
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cwd = current_dir()?.to_string_lossy().to_string();
    let zone = ZoneArgs::parse();
    let path = match zone.path {
        Some(value) => value,
        None => format!("{}/zones/{}.json", &cwd, zone.name),
    };
    let file_str = File::open(path)?;
    let config: CfDnsConfig = serde_json::from_reader(&file_str)?;

    logger_init(config.log_level.as_str(), cwd.as_str(), zone.name.as_str())?;

    let zone_info = get_zone_info(&zone.name, &config.api_token)?;
    debug!("Zone {} info retrieved", zone_info.name);
    let records_a = get_records_of_type(&zone_info.id, &config.api_token, "A")?;
    let records_aaaa = get_records_of_type(&zone_info.id, &config.api_token, "AAAA")?;
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
        let record_opt = match config_record.dns_type {
            IPVersion::IPv4 => records_a.get(&name),
            IPVersion::IPv6 => records_aaaa.get(&name),
        };
        let record = match record_opt {
            Some(r) => r,
            None => {
                warn!(
                    "Record {} with type {} not found in zone, skipping",
                    name,
                    String::from(config_record.dns_type)
                );
                updates[1] += 1;
                continue;
            }
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
            IPVersion::IPv4 => (IpAddr::V4(record.content.parse()?), current_ipv4),
            IPVersion::IPv6 => (IpAddr::V6(record.content.parse()?), current_ipv6),
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
            "type": String::from(config_record.dns_type),
            "content": new_ip,
            "proxied": config_record.proxied
        });
        let res = minreq::put(url)
            .with_header("Authorization", bearer_auth(&config.api_token))
            .with_json(&body)?
            .send()?;
        let cf_response: serde_json::Value = serde_json::from_str(res.as_str()?)?;
        if let Some(success) = cf_response["success"].as_bool() {
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
    }
    info!(
        "Updates finished, {} succeeded, {} failed, {} skipped",
        updates[0], updates[1], updates[2]
    );
    Ok(())
}
