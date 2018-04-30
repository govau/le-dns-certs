package main

import (
	"golang.org/x/crypto/acme"
)

type config struct {
	ACME acmeConf

	// AWSRegion applies to both route53 and bucket calls
	AWSRegion string

	// TTLDays is the number of days before expiry to renew certs
	TTLDays int

	// Domains is a map of hostname to route53 / bucket info
	Domains map[string]*domainConf
}

type acmeConf struct {
	URL        string
	Email      string
	PrivateKey string

	// private
	client     *acme.Client
	registered bool
}

type domainConf struct {
	// ZoneID is the route53 zone
	ZoneID string

	// Bucket is the S3 bucket name
	Bucket string

	// Object that will contain key, cert and intermediates - all PEM encoded
	Object string
}
