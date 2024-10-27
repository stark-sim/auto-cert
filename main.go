package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/registration"
	"log"
	"os"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	// new privateKey means new user
	// if it's the first time, generate a privateKey
	var privateKey crypto.PrivateKey
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// if you have privateKey file already, use it
	privateKeyFilePath := "/home/stark/.lego/accounts/acme-v02.api.letsencrypt.org/gooda159753@163.com/keys/gooda159753@163.com.key"
	if _, err = os.Stat(privateKeyFilePath); err != nil {
		if os.IsNotExist(err) {
			log.Println(privateKeyFilePath + " does not exist")
		}
	} else {
		log.Println(privateKeyFilePath + " exists")
		privateKeyFileBytes, err := os.ReadFile(privateKeyFilePath)
		if err != nil {
			log.Fatal(err)
		}
		privateKey, err = certcrypto.ParsePEMPrivateKey(privateKeyFileBytes)
		if err != nil {
			log.Fatal(err)
		}
	}

	// build acme client
	myUser := MyUser{
		Email: "you@example.com",
		key:   privateKey,
	}
	config := lego.NewConfig(&myUser)
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// choose your DNS provider
	cfg := alidns.NewDefaultConfig()
	cfg.APIKey = "you-access-key"
	cfg.SecretKey = "your-secret-key"
	p, err := alidns.NewDNSProviderConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Challenge.SetDNS01Provider(p)
	if err != nil {
		log.Fatal(err)
	}

	// new user doesn't need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg
	request := certificate.ObtainRequest{
		Domains:    []string{"www.example.com"},
		Bundle:     true,
		PrivateKey: privateKey,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%#v\n", certificates)
	err = os.WriteFile("PrivateKey", certificates.PrivateKey, os.ModePerm)
	if err != nil {
		log.Print(err)
	}
	err = os.WriteFile("Certificate", certificates.Certificate, os.ModePerm)
	if err != nil {
		log.Print(err)
	}
	err = os.WriteFile("IssuerCertificate", certificates.IssuerCertificate, os.ModePerm)
	if err != nil {
		log.Print(err)
	}
	err = os.WriteFile("CSR", certificates.CSR, os.ModePerm)
	if err != nil {
		log.Print(err)
	}
}
