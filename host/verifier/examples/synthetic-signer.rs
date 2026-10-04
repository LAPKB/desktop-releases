//! Test-only synthetic signer. It creates a fresh in-memory key on every run,
//! accepts only bounded hex test payloads, and never reads or writes key files.
use minisign::{sign, KeyPair};
use std::io::{self, BufRead, Cursor, Write};

const MAX_FIXTURE_BYTES: usize = 1024 * 1024;

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || value.len() > MAX_FIXTURE_BYTES * 2 {
        return Err("invalid fixture payload length".into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        bytes.push(
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid fixture payload encoding")?,
        );
    }
    Ok(bytes)
}

fn hex_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pair = KeyPair::generate_unencrypted_keypair()?;
    let public = String::from(pair.pk.to_box()?).trim_end().to_owned();
    let mut lines = public.lines();
    let comment = lines.next().ok_or("missing public key comment")?;
    let encoded_key = lines.next().ok_or("missing public key bytes")?;
    println!("PUBKEY\t{comment}\t{encoded_key}");
    io::stdout().flush()?;

    for line in io::stdin().lock().lines() {
        let line = line?;
        if line == "QUIT" {
            break;
        }
        let payload = match hex_decode(&line) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("synthetic signer: {error}");
                std::process::exit(2);
            }
        };
        let signature = sign(
            None,
            &pair.sk,
            Cursor::new(payload),
            Some("timestamp:0\tfile:synthetic-fixture"),
            Some("synthetic fixture"),
        )?
        .into_string();
        println!("SIG\t{}", hex_encode(signature.as_bytes()));
        io::stdout().flush()?;
    }
    Ok(())
}
