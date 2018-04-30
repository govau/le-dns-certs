package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"golang.org/x/crypto/acme"
	"gopkg.in/yaml.v2"
)

// fetchCertAndReturnExpiry - will return the first leaf certificate NotValidAfter date.
// If the cert file does not exists, then it will return the epoch time with no error.
// Any other error will be returned
func (c *config) fetchCertAndReturnExpiry(hostrec *domainConf, s3client *s3.S3) (time.Time, error) {
	certObj, err := s3client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(hostrec.Bucket),
		Key:    aws.String(hostrec.Object),
	})
	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok {
			if aerr.Code() == s3.ErrCodeNoSuchKey {
				return time.Time{}, nil
			}
		}
		return time.Time{}, err
	}

	defer certObj.Body.Close()

	bb, err := ioutil.ReadAll(certObj.Body)
	if err != nil {
		return time.Time{}, err
	}

	return getTTLOfLeafFromChain(bb)
}

func getTTLOfLeafFromChain(bb []byte) (time.Time, error) {
	var block *pem.Block
	for {
		block, bb = pem.Decode(bb)
		if block == nil {
			return time.Time{}, errors.New("no leaf cert found in cert file")
		}

		if block.Type != "CERTIFICATE" {
			// skip, we also include private keys in same file
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}

		if cert.IsCA {
			// skip, we only care abot leaves
			continue
		}

		return cert.NotAfter, nil
	}
}

// getCertFromLetsEncrypt will do a DNS challenge to get a cert
func (c *config) getCertFromLetsEncrypt(hostname string, hostrec *domainConf, route53client *route53.Route53) ([]byte, error) {
	// First, register our key if not already done
	if !c.ACME.registered {
		log.Println("Always try to register on startup, who cares if we already have...")
		_, err := c.ACME.client.Register(context.Background(), &acme.Account{
			Contact: []string{"mailto:" + c.ACME.Email},
		}, acme.AcceptTOS)
		if err != nil {
			log.Println("Error registering with LE - we've likely already done so, so ignoring:", err)
		}

		// no point re-doing each time
		c.ACME.registered = true
	}

	// Now, initiate DNS challenge
	authz, err := c.ACME.client.Authorize(context.Background(), hostname)
	if err != nil {
		return nil, err
	}

	// We can skip this if we already have an authorization
	if authz.Status != acme.StatusValid {
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return nil, errors.New("no supported challenge type found")
		}

		val, err := c.ACME.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, err
		}

		// Return TXT record
		changeResult, err := route53client.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
			HostedZoneId: aws.String(hostrec.ZoneID),
			ChangeBatch: &route53.ChangeBatch{
				Changes: []*route53.Change{
					&route53.Change{
						Action: aws.String("UPSERT"),
						ResourceRecordSet: &route53.ResourceRecordSet{
							Name: aws.String(fmt.Sprintf("_acme-challenge.%s.", hostname)),
							TTL:  aws.Int64(15),
							Type: aws.String("TXT"),
							ResourceRecords: []*route53.ResourceRecord{
								&route53.ResourceRecord{
									Value: aws.String(val),
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			return nil, err
		}
		err = route53client.WaitUntilResourceRecordSetsChanged(&route53.GetChangeInput{
			Id: changeResult.ChangeInfo.Id,
		})
		if err != nil {
			return nil, err
		}

		_, err = c.ACME.client.Accept(context.Background(), chal)
		if err != nil {
			return nil, err
		}

		log.Println("waiting authorization...")
		_, err = c.ACME.client.WaitAuthorization(context.Background(), authz.URI)
		if err != nil {
			return nil, err
		}
	}

	// OK, time to issue cert
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
	}, pkey)
	if err != nil {
		return nil, err
	}

	log.Println("creating cert...")

	ders, _, err := c.ACME.client.CreateCert(context.Background(), csr, 0, true)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}

	err = pem.Encode(buf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pkey),
	})
	if err != nil {
		return nil, err
	}
	for _, der := range ders {
		err = pem.Encode(buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (c *config) writeCertToS3(data []byte, hostrec *domainConf, s3client *s3.S3) error {
	result, err := s3manager.NewUploaderWithClient(s3client).Upload(&s3manager.UploadInput{
		Bucket:               aws.String(hostrec.Bucket),
		Key:                  aws.String(hostrec.Object),
		Body:                 bytes.NewReader(data),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return err
	}
	log.Printf("Cert successfully uploaded to: %s (version %s)\n", result.Location, stringval(result.VersionID))

	return nil
}

func stringval(s *string) string {
	if s == nil {
		return "n/a"
	}
	return *s
}

// updateCertIfNeeded checks to see if the cert is in the bucket, and if not, or if expired,
// then will attempt to renew
func (c *config) updateCertIfNeeded(hostname string, hostrec *domainConf) error {
	sess, err := session.NewSession(aws.NewConfig().WithRegion(c.AWSRegion))
	if err != nil {
		return err
	}

	// See if we have an existing cert, and if so fetch it's TTL
	s3client := s3.New(sess)
	certTTL, err := c.fetchCertAndReturnExpiry(hostrec, s3client)
	if err != nil {
		return err
	}

	// If the cert is valid after now + our duration
	if time.Now().Add(time.Duration(c.TTLDays) * 24 * time.Hour).Before(certTTL) {
		// Then reset our internal TTL and return early
		hostrec.ttl = certTTL.Add(-time.Duration(c.TTLDays) * 24 * time.Hour)
		return nil
	}

	// Fetch new cert
	certData, err := c.getCertFromLetsEncrypt(hostname, hostrec, route53.New(sess))
	if err != nil {
		return err
	}

	// Persist cert
	err = c.writeCertToS3(certData, hostrec, s3client)
	if err != nil {
		return err
	}

	// get TTL as we'll reset it next - and we'll use this also as a basic error check
	leafEnd, err := getTTLOfLeafFromChain(certData)
	if err != nil {
		return err
	}

	// Don't come back for a while
	hostrec.ttl = leafEnd.Add(-time.Duration(c.TTLDays) * 24 * time.Hour)

	// Done and happy
	return nil
}

func run(configPath string) error {
	if configPath == "" {
		return errors.New("must specify a config path")
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	var c config
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return err
	}

	// Parse ACME key early
	block, _ := pem.Decode([]byte(c.ACME.PrivateKey))
	if block == nil {
		return errors.New("no private key found in pem")
	}
	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		return errors.New("invalid private key found in pem for acme")
	}
	acmeKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	c.ACME.client = &acme.Client{
		Key:          acmeKey,
		DirectoryURL: c.ACME.URL,
	}

	// Start daemon
	for {
		for hostname, hostrec := range c.Domains {
			// Should always execute on first run
			if time.Now().After(hostrec.ttl) {
				err = c.updateCertIfNeeded(hostname, hostrec)
				if err != nil {
					log.Printf("error updating cert for %s - sleeping and will try again tomorrow: %s\n", hostname, err)
				}
			}
		}

		// Try again tomorrow
		time.Sleep(time.Hour * 24)
	}
}

func main() {
	var configPath string

	flag.StringVar(&configPath, "config", "", "Path to config file - required")
	flag.Parse()

	log.Fatal(run(configPath))
}
