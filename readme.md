# AWS Secrets Manager Snowflake Rotation Lambda

![status](https://github.com/vitalibo/secrets-manager-snowflake-rotation/actions/workflows/ci.yaml/badge.svg)

This repository provides an AWS Lambda function that automates the rotation of Snowflake credentials in AWS
Secrets Manager. It handles the rotation of RSA key pairs used for Snowflake authentication, making it easier to
maintain security compliance and implement credential rotation policies. Solution leverages Snowflake's support for
multiple active keys to enable **zero-downtime rotation**. Snowflake allows associating up to two public keys with a
single user through the `RSA_PUBLIC_KEY` and `RSA_PUBLIC_KEY_2` parameters for the ALTER USER command. This feature is
designed specifically to allow for uninterrupted credential rotation.

### Usage

To deploy lambda function, run the following command:

```bash
make deploy name='snowflake-keypair-rotation' \
            bucket='s3://codebase-us-east-1/prod/snowflake-keypair-rotation/1.0.0' \
            profile='my-profile'
```

Create a master secret in AWS Secrets Manager with the following format:

```json
{
  "account": "<snowflake account>",
  "user": "<master user>",
  "private_key": "<base64 encoded private key>",
  "public_key": "<base64 encoded public key>"
}
```

Create a secret for the user whose credentials you want to rotate:

```json
{
  "account": "<snowflake account>",
  "user": "<master user>",
  "private_key": "<base64 encoded private key>",
  "public_key": "<base64 encoded public key>",
  "masterarn": "<arn or id of the master secret>"
}
```

In AWS Secrets Manager, select the secret you want to rotate and choose **Rotate**. Enable automatic rotation
and set the rotation schedule according to your requirements. Select lambda rotation function created in
the previous step. Save the changes.
