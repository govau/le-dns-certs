# `route53renewer`

Simple tool to fetch and renew certificates.

Designed to be called from within a Concourse pipeline.

Usage:

```bash
go install github.com/govau/le-dns-certs/cmd/route53renewer

# Set these, or will default to AWS instance metadata if not set.
# Needs the following permissions:
# route53:ChangeResourceRecordSets - on the hosted zone ID
# route53:GetChange - on *
# s3:ListBucket - on the bucket
# s3:* - on items in the bucket
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=yyy

# Region for both your zone and buckets:
export AWS_REGION=ap-southeast-2

# Email address to register with Let's Encrypt
export LE_EMAIL=user@example.com

# Private key to access Let's Encrypt
export LE_PRIVATE_KEY="$(openssl genrsa 2048)"

# This is the hostname that you want a certificate now
export FQDN_FOR_CERT=host.example.com

# The route53 hosted zone ID in which the TXT record will be created
export ROUTE53_ZONEID=xxxx

# These are set by default, but can be overridden:
export LE_URL=https://acme-v01.api.letsencrypt.org/directory
export LE_DAYS_BEFORE_TO_RENEW=32
export S3_OBJECT="${FQDN_FOR_CERT}.crt"

# Finally, simply run the tool:
route53renewer
```

## What happens when run?

It will read the certificate file from the S3 bucket.

If it doesn't exist, or if the certificate is set to expire within `LE_DAYS_BEFORE_TO_RENEW`, then it will attempt to renew a certificate with Let's Encrypt by using the DNS challenge.

If successful, it will write a new file to the S3 bucket.

It will not tidy up the TXT record afterwards.
