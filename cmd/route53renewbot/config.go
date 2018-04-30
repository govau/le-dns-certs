package main

import (
	"time"

	"golang.org/x/crypto/acme"
)

type config struct {
	ACME struct {
		URL        string `yaml:"url"`
		Email      string `yaml:"email"`
		PrivateKey string `yaml:"private_key"`

		// private
		client     *acme.Client
		registered bool
	} `yaml:"acme"`

	// AWSRegion applies to both route53 and bucket calls
	AWSRegion string `yaml:"region"`

	// TTLDays is the number of days before expiry to renew certs
	TTLDays int `yaml:"days_before"`

	// Domains is a map of hostname to route53 / bucket info
	Domains map[string]*domainConf `yaml:"hosts"`
}

type domainConf struct {
	// ZoneID is the route53 zone
	ZoneID string `yaml:"zone_id"`

	// Bucket is the S3 bucket name
	Bucket string `yaml:"bucket"`

	// Object that will contain key, cert and intermediates - all PEM encoded
	Object string `yaml:"object"`

	// Private - will read object and renew if needed at this time.
	ttl time.Time
}
