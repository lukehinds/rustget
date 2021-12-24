use base64::{decode};
use serde::{Serialize, Deserialize};
// use openssl::ec::*;
use openssl::nid::Nid;
// use openssl::symm::{decrypt as aes_decrypt, Cipher};
use openssl::{
    ec::EcGroup, ec::EcKey
};
use std::fs::File;
use std::io::{Write};
use openssl::symm::Cipher;

#[derive(Serialize, Deserialize)]
struct Content {
    name: String,
    path: String,
    sha: String,
    size: u64,
    url: String,
    html_url: String,
    git_url: String,
    download_url: String,
    #[serde(rename = "type")]
    type_: String,
    content: String,
    encoding: String,
    _links: Links,
}

#[derive(Serialize, Deserialize)]
struct Links {
    #[serde(rename = "self")]
    self_: String,
    git: String,
    html: String,
}

fn contents(script: &str) -> Result<Content, ureq::Error> {
    let url: String = format!("https://api.github.com/repos/lukehinds/acme/contents/{}", script);

    let jresponse: Content = ureq::get(&url)
        .set("accept", "application/json")
        .call()?
        .into_json()?;
    Ok(jresponse)
}

fn main() {
    let script = "install.sh";
    let content = contents(script);
    // print out content name
    let base_64 = content.unwrap().content.clone();
    // print base_file (need to trim off new line)
    println!("{}", base_64.trim());
    // decode base64 of base_64
    let decoded = &decode(base_64.trim()).unwrap();
    // print out decoded base64 as string
    println!("{}", String::from_utf8(decoded.clone()).unwrap());

    // key generation

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    let private_key = EcKey::generate(&group).unwrap();

    let public_key = private_key.public_key();

    let ec_pub_key = EcKey::from_public_key(&group, &public_key).unwrap();

    let public_key_pem = &ec_pub_key.public_key_to_pem().unwrap();
    let pub_pem: String = String::from_utf8(public_key_pem.clone()).unwrap();
    println!("{}", pub_pem);

    let private_key_pem = &private_key.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), b"foobar").unwrap();

    let mut pkey = File::create("sget.key")
                       .expect("unable to create file");
    pkey.write_all(String::from_utf8(private_key_pem.clone()).unwrap().as_bytes()).expect("unable to write");

    let mut pubkey = File::create("sget.pub")
                       .expect("unable to create file");
    pubkey.write_all( String::from_utf8(public_key_pem.clone()).unwrap().as_bytes()).expect("unable to write");
}


// Sigstore relies on NIST P-256
// NIST P-256 is a Weierstrass curve specified in FIPS 186-4: Digital Signature Standard (DSS):
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
// Also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)

// openssl dgst -sha1 -sign sget.key examples.txt > signature

// openssl dgst -sha1 -verify sget.pub -signature signature examples.txt

// change to PEM format
// https://github.com/Pierozi/rust-civic-sip/blob/a055763947884044cb828f7c05731a00c6c3af75/src/crypto.rs
