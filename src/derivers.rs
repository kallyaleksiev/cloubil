//! Module which defines types that hold arguments
//! for requests to clouds and parse those arguments
//! to obtain needed derivatives, e.g. authorisation
//! headers
use crate::signers;
use crate::headers::AWSHeaders;

use dirs;
use hex;

use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;

use chrono::Local;

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

/// Type that defines what arguments are needed to
/// to coomunicate with a given cloud
pub trait CloudArgs {}

/// Arguments for requests to AWS
#[derive(Debug, PartialEq, Eq)]
pub struct AWSArgs {
    pub access_key: String,
    pub secret_access_key: String,
    pub service: String,
    pub method: String,
    pub region: String,
    pub host: String,
    pub canonical_uri: String,
    pub payload: String,
}
impl CloudArgs for AWSArgs {}

/// Type that defines an (authentication)
/// configuration for a cloud
pub trait Config {}

/// AWS-specific config
#[derive(Serialize, Deserialize)]
pub struct AWSConfig {
    access_key: String,
    secret_access_key: String,
}
impl Config for AWSConfig {}

impl AWSArgs {
    /// Constructs arguments for a billing
    pub fn billing_for_period(start: &str, end: &str) -> AWSArgs {
        // some arguments are known
        let service = String::from("ce");
        let method = String::from("POST");
        let region = String::from("us-east-1");
        let host = String::from("ce.us-east-1.amazonaws.com");
        let canonical_uri = String::from("/");

        // take these from a file -- for now panic
        // if the file read is unsuccessfull
        let mut config_path = dirs::home_dir().or(Some(PathBuf::from("~"))).unwrap();
        config_path.push(".cloubil");
        config_path.push("config");
        config_path.set_extension("json");

        let file = File::open(config_path).expect("Unexpected error opening config file");
        let buffer = BufReader::new(file);

        let config: AWSConfig =
            serde_json::from_reader(buffer).expect("Unexpected error reading json config");

        // TODO: Introduce a stable billing payload type to 
        // remove the following JSON shenanigans and check 
        // start and time inputs to make sure they are in 
        // the correct format 
        let payload_str = format!(
            r#"
        {{
            "TimePeriod": {{
                "Start": "{start}",
                "End": "{end}"
            }},
            "Granularity": "MONTHLY",
            "Metrics": [
                "AmortizedCost"
            ]
        }}"#,
            start = start,
            end = end
        );
        let payload_json: Value = serde_json::from_str(&payload_str)
            .expect("JSON shenanigans failed to parse String to JSON...");
        let payload = serde_json::to_string(&payload_json)
            .expect("JSON shenanigans failed to parse JSON to String...");

        return AWSArgs {
            access_key: config.access_key,
            secret_access_key: config.secret_access_key,
            service,
            method,
            region,
            host,
            canonical_uri,
            payload
        }
    }
}

/// Type that is able to derive an cloud-specific headers
/// from its arguments (as a String)
pub trait HeaderDeriver {
    type ArgType: CloudArgs;

    fn get_headers(&self, args: &Self::ArgType) -> Result<AWSHeaders, Box<dyn std::error::Error>>;
}

/// This struct parses arguments specific for AWS
pub struct AWSArgsParser;

impl AWSArgsParser {
    pub fn new() -> AWSArgsParser {
        AWSArgsParser {}
    }
}

impl HeaderDeriver for AWSArgsParser {
    type ArgType = AWSArgs;

    fn get_headers(&self, args: &Self::ArgType) -> Result<AWSHeaders, Box<dyn std::error::Error>> {
        assert_eq!(
            args.service, "ce",
            "Only `ce` service is available for AWS requests"
        );

        const ALGORITHM: &str = "AWS4-HMAC-SHA256";
        const AMZ_FMT: &str = "%Y%m%dT%H%M%SZ";
        const STANDARD_FMT: &str = "%Y%m%d";
        const CANONICAL_QUERYSTRING: &str = "";
        const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
        const SIGNED_HEADERS: &str = "content-length;content-type;host;x-amz-date";
        const ACCEPT: &str = "*/*";
        const AMZ_TARGET: &str = "AWSInsightsIndexService.GetCostAndUsage";
 
        let t = Local::now();
        let amz_date = t.format(AMZ_FMT).to_string();
        let date_stamp = t.format(STANDARD_FMT).to_string();

        let content_length: usize = args.payload.len();

        let mut hasher = Sha256::new();
        hasher.update(args.payload.as_bytes());
        let payload_hash: Vec<u8> = hasher.finalize().to_vec();
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            &date_stamp, &args.region, &args.service
        );
        let canonical_headers = format!(
            "content-length:{}\ncontent-type:{}\nhost:{}\nx-amz-date:{}\n",
            &content_length, CONTENT_TYPE, &args.host, &amz_date
        );

        let payload_hash_str = hex::encode(&payload_hash);
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            &args.method,
            &args.canonical_uri,
            CANONICAL_QUERYSTRING,
            &canonical_headers,
            SIGNED_HEADERS,
            &payload_hash_str
        );

        let mut hasher = Sha256::new();
        hasher.update(&canonical_request.as_bytes());
        let canonical_request_hashed = hasher.finalize().to_vec();
        let canonical_req_hashed_str = hex::encode(&canonical_request_hashed);

        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            &ALGORITHM, &amz_date, &credential_scope, &canonical_req_hashed_str
        );

        let signing_key = signers::aws_get_signature_key(
            &args.secret_access_key,
            &date_stamp,
            &args.region,
            &args.service,
        )?;

        let signature = signers::aws_sign(&signing_key, string_to_sign.as_bytes())?;
        let signature_str = hex::encode(&signature);

        let authorization_header = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            ALGORITHM, &args.access_key, &credential_scope, SIGNED_HEADERS, &signature_str
        );

        Ok(
            AWSHeaders {
                accept: String::from(ACCEPT),
                authhorization: authorization_header,
                content_length: content_length,
                content_type: String::from(CONTENT_TYPE),
                host: String::from(&args.host),
                amz_date: String::from(amz_date),
                amz_target: String::from(AMZ_TARGET)
            }
        )
    }
}
