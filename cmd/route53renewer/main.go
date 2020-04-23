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
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"golang.org/x/crypto/acme"
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
func (c *config) getCertFromLetsEncrypt(hostnames []string, hostrec *domainConf, route53client *route53.Route53) ([]byte, error) {
	// First, register our key if not already done
	if !c.ACME.registered {
		log.Println("always try to register our key and email address with Let's Encrypt...")
		_, err := c.ACME.client.CreateAccount(context.Background(), &acme.Account{
			Contact:     []string{"mailto:" + c.ACME.Email},
			TermsAgreed: true,
		})
		if err != nil {
			log.Println("error registering with Let's Encrypt (this is expected) - ignoring: ", err)
		}

		// no point re-doing each time
		c.ACME.registered = true
	}

	// Now, initiate DNS challenge
	log.Println("checking authorization...")
	order, err := c.ACME.client.CreateOrder(context.Background(), acme.NewOrder(hostnames...))
	if err != nil {
		return nil, err
	}

	// We can skip this if we already have an authorization
	if order.Status != acme.StatusValid {
		for authzIdx, domainAuth := range order.Authorizations {
			log.Println(fmt.Sprintf("we need to re-authorize for this domain: %s", string(order.Identifiers[authzIdx].Value)))
			ac, err := c.ACME.client.GetAuthorization(context.Background(), domainAuth)
			if err != nil {
				return nil, err
			}
			if ac.Status != acme.StatusValid {
				var chal *acme.Challenge
				for _, c := range ac.Challenges {
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
				txtDomain := fmt.Sprintf("_acme-challenge.%s.", strings.Replace(hostrec.AuthorizationDomain, "*.", "", 1))
				log.Println(fmt.Sprintf("setting TXT record at %s in route53 to authorize for %s", txtDomain, order.Identifiers[authzIdx].Value))
				changeResult, err := route53client.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
					HostedZoneId: aws.String(hostrec.ZoneID),
					ChangeBatch: &route53.ChangeBatch{
						Changes: []*route53.Change{
							&route53.Change{
								Action: aws.String("UPSERT"),
								ResourceRecordSet: &route53.ResourceRecordSet{
									Name: aws.String(txtDomain),
									TTL:  aws.Int64(15),
									Type: aws.String("TXT"),
									ResourceRecords: []*route53.ResourceRecord{
										&route53.ResourceRecord{
											Value: aws.String(fmt.Sprintf(`"%s"`, val)),
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
				log.Println("waiting on route53 change to be complete...")
				err = route53client.WaitUntilResourceRecordSetsChanged(&route53.GetChangeInput{
					Id: changeResult.ChangeInfo.Id,
				})
				if err != nil {
					return nil, err
				}

				log.Println("accepting Let's Encrypt challenge")
				_, err = c.ACME.client.AcceptChallenge(context.Background(), chal)
				if err != nil {
					return nil, err
				}

				log.Println("waiting authorization...")
				_, err = c.ACME.client.WaitAuthorization(context.Background(), domainAuth)
				if err != nil {
					authError := err.(acme.AuthorizationError).Authorization.Challenges[0].Error
					log.Println(authError)
					return nil, err
				}
			}
		}
	}

	log.Println("generating key for certificate...")
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	log.Println("generating certificate signing request...")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		DNSNames: hostnames,
	}, pkey)
	if err != nil {
		return nil, err
	}

	log.Println("requesting certificate...")
	ders, err := c.ACME.client.FinalizeOrder(context.Background(), order.FinalizeURL, csr)
	if err != nil {
		return nil, err
	}

	log.Println("received. marshaling result...")
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
	log.Println("writing to S3...")
	result, err := s3manager.NewUploaderWithClient(s3client).Upload(&s3manager.UploadInput{
		Bucket:               aws.String(hostrec.Bucket),
		Key:                  aws.String(hostrec.Object),
		Body:                 bytes.NewReader(data),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return err
	}
	log.Printf("cert successfully uploaded to: %s (version %s)\n", result.Location, stringval(result.VersionID))

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
func (c *config) updateCertIfNeeded(hostnames []string, hostrec *domainConf) error {
	sess, err := session.NewSession(aws.NewConfig().WithRegion(c.AWSRegion))
	if err != nil {
		return err
	}

	log.Printf("checking for existing certificate for %s...\n", strings.Join(hostnames, ","))
	s3client := s3.New(sess)
	certTTL, err := c.fetchCertAndReturnExpiry(hostrec, s3client)
	if err != nil {
		return err
	}

	log.Printf("expiration date: %s\n", certTTL.Format(time.RFC3339))

	// If the cert is valid after now + our duration
	if time.Now().Add(time.Duration(c.TTLDays) * 24 * time.Hour).Before(certTTL) {
		log.Println("no renewal needed")
		return nil
	}

	log.Println("attempting to refresh certificate from Let's Encrypt")
	certData, err := c.getCertFromLetsEncrypt(hostnames, hostrec, route53.New(sess))
	if err != nil {
		return err
	}

	// Persist cert
	err = c.writeCertToS3(certData, hostrec, s3client)
	if err != nil {
		return err
	}

	// Done and happy
	return nil
}

func (c *config) runOnce() error {
	var retErr error
	for hostname, hostrec := range c.Domains {
		err := c.updateCertIfNeeded(strings.Split(hostname, ","), hostrec)
		if err != nil {
			log.Printf("error updating cert for %s: %s\n", hostname, err)
			retErr = errors.New("at least one failed")
		}
	}
	return retErr
}

func readConf() (*config, error) {
	c := &config{
		ACME: acmeConf{
			URL:        envWithDefault("LE_URL", "https://acme-v02.api.letsencrypt.org/directory"),
			Email:      mustGetEnv("LE_EMAIL_ADDRESS"),
			PrivateKey: mustGetEnvOrEnvFile("LE_PRIVATE_KEY", "LE_PRIVATE_KEY_FILE"),
		},
		AWSRegion: mustGetEnv("AWS_REGION"),
		TTLDays:   mustConvertInt(envWithDefault("LE_DAYS_BEFORE_TO_RENEW", "32")),
		Domains: map[string]*domainConf{
			mustGetEnv("FQDN_FOR_CERT"): &domainConf{
				Bucket: mustGetEnv("S3_BUCKET"),
				Object: envWithDefault("S3_OBJECT", fmt.Sprintf("%s.crt", strings.Replace(mustGetEnv("FQDN_FOR_CERT"), "*", "star", -1))),
				ZoneID: mustGetEnv("ROUTE53_ZONEID"),
				AuthorizationDomain: envWithDefault("FQDN_FOR_AUTH", mustGetEnv("FQDN_FOR_CERT")),
			},
		},
	}

	block, _ := pem.Decode([]byte(c.ACME.PrivateKey))
	if block == nil {
		return nil, errors.New("no private key found in pem")
	}
	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		return nil, errors.New("invalid private key found in pem for acme")
	}
	acmeKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	c.ACME.client = &acme.Client{
		Key:          acmeKey,
		DirectoryURL: c.ACME.URL,
	}

	return c, nil
}

func mustConvertInt(s string) int {
	rv, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return rv
}

func envWithDefault(name, defVal string) string {
	rv := os.Getenv(name)
	if len(rv) == 0 {
		return defVal
	}
	return rv
}

func mustGetEnv(name string) string {
	rv := os.Getenv(name)
	if len(rv) == 0 {
		panic("must set env variable: " + name)
	}
	return rv
}

// get the contents of a envvar or file from env var file path
func mustGetEnvOrEnvFile(envname string, envfile string) string {
	rv := os.Getenv(envfile)
	if len(rv) == 0 {
		return mustGetEnv(envname)
	}
	b, err := ioutil.ReadFile(rv) // just pass the file name
	if err != nil {
		panic(err)
	}

	return string(b)
}

func main() {
	conf, err := readConf()
	if err != nil {
		log.Fatal(err)
	}

	err = conf.runOnce()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("completed successfully")
}
