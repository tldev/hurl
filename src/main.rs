#[macro_use] extern crate clap;
extern crate curl;
extern crate base64;
extern crate openssl;
extern crate data_encoding;

use std::str;
use std::io::{stdout, Write};
use std::env;
use clap::{App};
use curl::easy::{Easy, List};
use std::path::Path;
use std::collections::BTreeMap;
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use openssl::sign::{Signer};
use openssl::pkey::PKey;
use std::time::SystemTime;
use data_encoding::HEXUPPER;

#[cfg(feature = "yaml")]
fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let url = matches.value_of("url").unwrap();
    let request = matches.value_of("request").unwrap_or("GET");


    let mut easy = Easy::new();
    easy.url(url).unwrap();
    easy.write_function(|data| {
        stdout().write_all(data).unwrap();
        Ok(data.len())
    }).unwrap();

    if matches.is_present("location") {
        easy.follow_location(true);
    }

    if matches.is_present("partner") {
        let partner = matches.value_of("partner").unwrap().to_string();
        let result = sign_request(easy, &partner, &url, &request);
        match result {
            Ok(()) => (),
            Err(s) => println!("{}", s)
        }
    }

    // easy.perform().unwrap();

    // println!("{}", easy.response_code().unwrap()); 
}

fn sign_request<'a>(mut easy: Easy, partner: &'a str, url: &str, method: &str) -> Result<(), &'a str> {
    let sig = "";
    let folder = repos_folder()?;
    let config_path = find_config_path(folder, partner)?;
    let config_contents = read_config(config_path)?;
    let parsed_yaml = parse_yaml(config_contents)?;
    let b64_key = extract_b64_key(parsed_yaml, partner)?;
    let pem_key = decode_b64(&b64_key)?;
    let rsa_pkey = build_rsa_pkey(&pem_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &rsa_pkey).unwrap();

    let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    let unix = match current_time {
        Ok(unix) => unix.as_secs(),
        Err(_) => 0
    };
    let data = format!("{}\n{}\n{}\n{}\n{}", partner, url, method.to_lowercase(), unix, "");
    println!("{}", data);
    signer.update(data.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let sig_ref: &[u8] = &signature; // c: &[u8]
    
    let mut list = List::new();
    list.append(&format!("HDY-PARTNER-ID: {}", partner)).unwrap();
    list.append(&format!("HDY-TIMESTAMP: {}", unix)).unwrap();
    list.append(&format!("HDY-SIGNATURE: {}", HEXUPPER.encode(sig_ref))).unwrap();
    println!("{:?}", HEXUPPER.encode(sig_ref));
    easy.http_headers(list).unwrap();



    // base64(rsa_sha256(PARTNER_ID + "\n" + URL + "\n" + HTTP_METHOD + "\n" + TIMESTAMP + "\n" + PAYLOAD))

    return Ok(());
}

fn build_rsa_pkey(pem_key: &[u8]) -> Result<PKey<openssl::pkey::Private>, &'static str> {
    let rsa_private_key = Rsa::private_key_from_pem(pem_key);
    return match rsa_private_key {
        Err(_) => Err("Failed to parse decoded b64 key"),
        Ok(rsa_private_key) => match PKey::from_rsa(rsa_private_key) {
            Err(_) => Err("Failed to convert pem to rsa private key"),
            Ok(rsa_pkey) => Ok(rsa_pkey)
        }
    }
}

fn decode_b64(b64_str: &str) -> Result<Vec<u8>, &'static str> {
    let decoded = base64::decode(b64_str);
    return match decoded {
        Ok(decoded) => Ok(decoded),
        Err(_) => Err("Unable to decode b64 key")
    }
}

fn extract_b64_key(config: BTreeMap<String, String>, partner: &str) -> Result<String, &'static str> {
    let potential_key = private_key_yaml_key(partner);
    let b64key = config.get(&potential_key);
    return match b64key {
        Some(b64key) => Ok(b64key.to_string()),
        None => Err("Unable to find private key within yaml")
    }
}

fn private_key_yaml_key(partner: &str) -> String {
    return format!("{}_RSA_PRIVATE_KEY", partner.to_uppercase());
}

fn parse_yaml(yaml: String) -> Result<BTreeMap<String, String>, &'static str> {
    let hash_map: Result<BTreeMap<String, String>, serde_yaml::Error> = serde_yaml::from_str(&yaml);
    return match hash_map {
        Ok(hash_map) => Ok(hash_map),
        Err(_) => Err("Unabled to parse yml")
    }
}

fn read_config(path: String) -> Result<String, &'static str> {
    let contents = std::fs::read_to_string(path);
    return match contents {
        Ok(contents) => Ok(contents),
        Err(_) => Err("Failed to read config file")
    }
}

fn repos_folder() -> Result<String, &'static str> {
    if let Ok(path) = env::var("HANDYDEV_ROOT") { 
        let repos_folder = format!("{}/repos", path);
        if Path::new(&repos_folder).exists() {
            return Ok(repos_folder);
        } else {
            return Err("Repo folder not");
        }
    } else {
        return Err("HANDYDEV_ROOT not found in ENV");
    }
}

fn find_config_path(repo_folder_path: String, partner: &str) -> Result<String, &str> {
    let config_path = "config/application.yml";
    let option1 = format!("{}/{}/{}", repo_folder_path, partner, config_path);
    let option2 = format!("{}/service-{}-backend/{}", repo_folder_path, partner, config_path);
    let option3 = format!("{}/service-{}-frontend/{}", repo_folder_path, partner, config_path);
    let options = [option1, option2, option3];
    let path = options.iter().find(|&p| Path::new(p).exists());

    return match path {
        Some(path) => Ok(path.to_string()),
        None => Err("Config path not found!")
    }
}

#[cfg(not(feature = "yaml"))]
fn main() {
    // As stated above, if clap is not compiled with the YAML feature, it is disabled.
    println!("YAML feature is disabled.");
    println!("Pass --features yaml to cargo when trying this example.");
}
