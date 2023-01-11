mod derivers;
mod headers;
mod signers;

use derivers::{AWSArgs, AWSArgsParser, HeaderDeriver};
use headers::*;

use reqwest;

use serde_json;
use serde_json::Value;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CLIArgs {
    /// The start date for billing period in the format YYYY-mm-dd
    #[arg(long)]
    start: String, 

    /// The end date for billing period in the format YYYY-mm-dd
    #[arg(long)]
    end: String 
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = CLIArgs::parse();

    let args = AWSArgs::billing_for_period(&cli_args.start, &cli_args.end);

    let awsparser = AWSArgsParser::new();

    let aws_headers = awsparser.get_headers(&args)?;

    let url = format!("https://{}", &args.host);
    let client = reqwest::blocking::Client::new();

    let resp = client
        .post(url)
        .header(ACCEPT, &aws_headers.accept)
        .header(AUTHORIZATION, &aws_headers.authhorization)
        .header(CONTENT_LENGTH, aws_headers.content_length)
        .header(CONTENT_TYPE, &aws_headers.content_type)
        .header(HOST, &aws_headers.host)
        .header(X_AMZ_DATE, &aws_headers.amz_date)
        .header(X_AMZ_TARGET, &aws_headers.amz_target)
        .body(args.payload)
        .send()?;

    let resp_text = resp.text()?;
    let parsed_resp_json: Value = serde_json::from_str(&resp_text)?;
    // TODO: Strongly type and control this 
    let cost = parsed_resp_json["ResultsByTime"][0]["Total"]["AmortizedCost"]["Amount"].as_str().unwrap_or("n/a");
    
    println!("Total cost in queried period is ${cost}",
    cost=cost
);

    Ok(())
}
