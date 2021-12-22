
use serde::{Serialize, Deserialize};
use base64::{decode};
use p256::{
    ecdsa::{SigningKey, signature::Signer, VerifyingKey, signature::Verifier},
};
use p256::PublicKey;
use rand_core::OsRng; // requires 'getrandom' feature

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
    // match content {
    //     Ok(c) => {
    //         println!("{}", c.name);
    //     },
    //     Err(e) => {
    //         println!("{}", e);
    //     }
    // }
    // print out content name
    let base_64 = content.unwrap().content.clone();
    // print base_file (need to trim off new line)
    println!("{}", base_64.trim());
    // decode base64 of base_64
    let decoded = &decode(base_64.trim()).unwrap();
    // print out decoded base64 as string
    println!("{}", String::from_utf8(decoded.clone()).unwrap());

    let signing_key = SigningKey::random(&mut OsRng); // Serialize with `::to_bytes()`
    let signature = signing_key.sign(base_64.trim().as_bytes());

    let verify_key = VerifyingKey::from(&signing_key); // Serialize with `::to_encoded_point()`
    assert!(verify_key.verify(base_64.trim().as_bytes(), &signature).is_ok());
}