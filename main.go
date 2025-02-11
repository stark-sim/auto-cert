package main

import (
	"auto-cert/config"
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

	fmt.Printf("%+v", config.Config)

	// new privateKey means new user
	// if it's the first time, generate a privateKey
	var privateKey crypto.PrivateKey
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// if you have privateKey file already, use it
	//privateKeyFilePath := "/home/stark/.lego/accounts/acme-v02.api.letsencrypt.org/foo@bar.com/keys/foo@bar.com.key"
	//if _, err = os.Stat(privateKeyFilePath); err != nil {
	//	if os.IsNotExist(err) {
	//		log.Println(privateKeyFilePath + " does not exist")
	//	}
	//} else {
	//	log.Println(privateKeyFilePath + " exists")
	//	privateKeyFileBytes, err := os.ReadFile(privateKeyFilePath)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	privateKey, err = certcrypto.ParsePEMPrivateKey(privateKeyFileBytes)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//}

	// 直接复制文件中的私钥
	//var privateKeyFileBytes []byte
	//privateKeyFileBytes = []byte("-----BEGIN EC PRTE KEY-----\nMHcCAQEEIKcX2Pkw/UoObxxxQ7ugO+dFedMyWbal20ohxjeHRg0ToAoGCCqGSM49\nAwEHoUQDQgAEB/f+AboCZI")
	//privateKey, err = certcrypto.ParsePEMPrivateKey(privateKeyFileBytes)
	//if err != nil {
	//	log.Fatal(err)
	//}

	// build acme client
	myUser := MyUser{
		Email: "foo@bar.com",
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

	// old user use registration from same old privateKey
	//reg, err := client.Registration.ResolveAccountByKey()
	//if err != nil {
	//	log.Fatal(err)
	//}
	myUser.Registration = reg
	request := certificate.ObtainRequest{
		Domains: []string{"gitlab.starksim.com"},
		Bundle:  true,
		// 这里是证书的 key，不是用户的 key，可以手动提供，但肯定不能提供跟用户的 key 一样
		//PrivateKey: privateKey,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}
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
