use minisign_verify::{PublicKey, Signature};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;

const MAX_KEY_BYTES: usize = 4096;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const CHUNK_BYTES: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0x20000;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
const O_NOFOLLOW: i32 = 0x100;

fn fail(message: &str) -> ExitCode {
    eprintln!("lapkb-release-verifier: {message}");
    ExitCode::FAILURE
}

fn verify_with_key_text(
    key_text: &str,
    signature_path: &Path,
    payload_path: &Path,
) -> Result<(), &'static str> {
    if key_text.len() > MAX_KEY_BYTES {
        return Err("configured public key is oversized");
    }
    let public_key = PublicKey::decode(key_text).map_err(|_| "configured public key is invalid")?;

    let (mut signature_file, sig_metadata) =
        open_regular(signature_path, MAX_SIGNATURE_BYTES, true)?;
    let mut signature_bytes = Vec::new();
    signature_file
        .by_ref()
        .take(MAX_SIGNATURE_BYTES + 1)
        .read_to_end(&mut signature_bytes)
        .map_err(|_| "signature is unreadable")?;
    if signature_bytes.len() as u64 != sig_metadata.len() {
        return Err("signature changed while reading");
    }
    let signature_text =
        String::from_utf8(signature_bytes).map_err(|_| "signature is not UTF-8")?;
    let signature =
        Signature::decode(&signature_text).map_err(|_| "signature encoding is invalid")?;

    let (mut file, payload_metadata) = open_regular(payload_path, MAX_PAYLOAD_BYTES, true)?;
    let mut verifier = public_key
        .verify_stream(&signature)
        .map_err(|_| "signature key or algorithm is not accepted")?;
    let mut buffer = [0u8; CHUNK_BYTES];
    let mut bytes = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|_| "payload read failed")?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or("payload size overflow")?;
        if bytes > MAX_PAYLOAD_BYTES || bytes > payload_metadata.len() {
            return Err("payload changed or exceeds its size limit");
        }
        verifier.update(&buffer[..count]);
    }
    if bytes != payload_metadata.len() {
        return Err("payload changed while verifying");
    }
    verifier
        .finalize()
        .map_err(|_| "signature verification failed")
}

fn open_regular(
    path: &Path,
    maximum: u64,
    nonempty: bool,
) -> Result<(File, fs::Metadata), &'static str> {
    let before = fs::symlink_metadata(path).map_err(|_| "input file is unavailable")?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() > maximum
        || (nonempty && before.len() == 0)
    {
        return Err("input is not a bounded, unlinked regular file");
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(O_NOFOLLOW);
    let file = options.open(path).map_err(|_| "input file is unreadable")?;
    let opened = file
        .metadata()
        .map_err(|_| "input metadata is unavailable")?;
    if !opened.is_file()
        || opened.nlink() != 1
        || (opened.dev(), opened.ino(), opened.len()) != (before.dev(), before.ino(), before.len())
    {
        return Err("input changed while opening");
    }
    Ok((file, before))
}

fn verify(signature_path: &Path, payload_path: &Path) -> Result<(), &'static str> {
    let mut key_text = String::new();
    io::stdin()
        .take((MAX_KEY_BYTES + 1) as u64)
        .read_to_string(&mut key_text)
        .map_err(|_| "could not read configured public key")?;
    verify_with_key_text(&key_text, signature_path, payload_path)
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 4 || args[1] != "verify" {
        return fail("usage: lapkb-release-verifier verify <signature-file> <payload-file>");
    }
    match verify(Path::new(&args[2]), Path::new(&args[3])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => fail(message),
    }
}

#[cfg(test)]
mod tests {
    use super::verify_with_key_text;
    use minisign::{sign, KeyPair};
    use std::fs;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn verifies_real_synthetic_tauri_signature_and_rejects_tampering() {
        let pair = KeyPair::generate_unencrypted_keypair().expect("synthetic key generation");
        let public_key = String::from(pair.pk.to_box().expect("public key"));
        let payload = b"temporary synthetic publisher fixture";
        let signature = sign(
            None,
            &pair.sk,
            Cursor::new(payload),
            Some("timestamp:0\tfile:synthetic-test"),
            Some("synthetic fixture"),
        )
        .expect("synthetic signature")
        .into_string();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lapkb-verifier-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("private temporary test directory");
        let signature_path = directory.join("fixture.minisig");
        let payload_path = directory.join("fixture.bin");
        fs::write(&signature_path, signature).expect("signature fixture");
        fs::write(&payload_path, payload).expect("payload fixture");
        assert!(verify_with_key_text(&public_key, &signature_path, &payload_path).is_ok());
        fs::write(&payload_path, b"tampered synthetic fixture").expect("tampered payload");
        assert!(verify_with_key_text(&public_key, &signature_path, &payload_path).is_err());
        fs::remove_dir_all(directory).expect("remove synthetic fixture");
    }
}
