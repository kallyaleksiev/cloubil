//! This module contains the headers needed to properly send requests

use reqwest::header::HeaderName;

/// standard non-cloud specific headers
pub use reqwest::header::{ACCEPT, AUTHORIZATION,HOST, CONTENT_LENGTH,CONTENT_TYPE};

/// AWS-needed headers

/// Date in format `%Y%m%dT%H%M%SZ`
pub const X_AMZ_DATE: HeaderName = HeaderName::from_static("x-amz-date");

/// Some services require this header as part of their defined interface
pub const X_AMZ_TARGET: HeaderName = HeaderName::from_static("x-amz-target");


/// Quick and dirty container for conventionally-typed 
/// AWS-needed headers (which owns its values)
#[derive(Debug, PartialEq, Eq)]
pub struct AWSHeaders {
    pub accept: String,
    pub authhorization: String, 
    pub content_length: usize,
    pub content_type: String,
    pub host: String, 
    pub amz_date: String, 
    pub amz_target: String
}