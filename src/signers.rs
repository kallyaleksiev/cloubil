//! Module holding types that help sign parts
//! of requests

use hmac::{Mac, SimpleHmac};
use sha2::Sha256;
use std::error::Error;

type HmacSha256 = SimpleHmac<Sha256>;

/// Sign a message (`data_bytes`) using a given signing key.
/// This is essentially an HMAC with SHA256 with the given key.
/// This procedure is the specific for AWS.
pub(crate) fn aws_sign(key_bytes: &[u8], data_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut hasher = HmacSha256::new_from_slice(key_bytes)?;
    hasher.update(data_bytes);

    let final_bytes = hasher.finalize().into_bytes();

    Ok(final_bytes.to_vec())
}

/// The AWS way of obtaining a message signing-key from some strings
/// of information. The `key` here is usually the secret signing key
/// of the client which is mashed along with other information to
/// obtain a signing key, which is subsequently used in the request.
pub(crate) fn aws_get_signature_key(
    key: &str,
    date_stamp: &str,
    region_name: &str,
    service_name: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let aws4_req_str = String::from("aws4_request");
    let init_key = format!("AWS4{}", key);

    let date_key = aws_sign(&init_key.as_bytes(), date_stamp.as_bytes())?;

    let region_key = aws_sign(&date_key, region_name.as_bytes())?;

    let service_key = aws_sign(&region_key, service_name.as_bytes())?;

    let signing_key = aws_sign(&service_key, &aws4_req_str.as_bytes())?;

    Ok(signing_key)
}
