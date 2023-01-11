# cloubil

Tool to check cloud billing quickly and easily, rather than having to use tedious and limited CLIs or UIs. The long-term vision is for it to be a convenient, portable, highly configurable and capable tool that can help you get useful insights about your cloud billing.

Requests authentication mechanisms are written from scratch, e.g. for AWS signing using [AWS4-HMAC-SHA256](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html). 

Currently supports cost for a given period in AWS. 

To use: 

1. Run `cargo build` to build tool. 

2. Create a file `.cloubil/config.json` in your home directory holding credentials (access_key and secret_access_key) for a valid IAM role that has access to your billing.

3. Run for example `cloubil --start 2023-01-01 --end 2023-02-01` to get your current monthly AWS cost.
