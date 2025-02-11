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
	"github.com/sirupsen/logrus"
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
func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {

	// 获取密钥，或文件不存在，则按 lego 的默认路径创建一个新密钥
	// 一个密钥在 acme Let's Encrypt 处代表着一个用户
	var privateKeyPath string
	if config.Config.Lego.PrivateKeyPath == "" {
		// 使用默认路径
		privateKeyPath = fmt.Sprintf(".lego/accounts/acme-v02.api.letsencrypt.org/%s/keys/%s.key", config.Config.Lego.Email, config.Config.Lego.Email)
	} else {
		privateKeyPath = config.Config.Lego.PrivateKeyPath
	}

	var privateKey crypto.PrivateKey
	var isNewPrivateKey bool
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		isNewPrivateKey = true
		// 如果找不到私钥文件，走新建逻辑
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			logrus.Fatal(err)
		}
	} else {
		privateKeyFileBytes, err := os.ReadFile(privateKeyPath)
		if err != nil {
			logrus.Fatal(err)
		}
		privateKey, err = certcrypto.ParsePEMPrivateKey(privateKeyFileBytes)
		if err != nil {
			logrus.Fatal(err)
		}
	}

	// 构造出用户身份
	myUser := MyUser{
		Email: config.Config.Lego.Email,
		key:   privateKey,
	}

	legoConfig := lego.NewConfig(&myUser)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		logrus.Fatal(err)
	}

	// choose your DNS provider
	cfg := alidns.NewDefaultConfig()
	cfg.APIKey = config.Config.Aliyun.AccessKey
	cfg.SecretKey = config.Config.Aliyun.SecretKey
	p, err := alidns.NewDNSProviderConfig(cfg)
	if err != nil {
		logrus.Fatal(err)
	}
	err = client.Challenge.SetDNS01Provider(p)
	if err != nil {
		logrus.Fatal(err)
	}

	// 获取注册信息
	var reg *registration.Resource
	if isNewPrivateKey {
		// 新用户才需要注册 (new user need to register)
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			logrus.Fatal(err)
		}
	} else {
		// old user use registration from same old privateKey
		reg, err = client.Registration.ResolveAccountByKey()
		if err != nil {
			logrus.Fatal(err)
		}
	}
	// 补全用户身份的最后一个组件
	myUser.Registration = reg
	request := certificate.ObtainRequest{
		Domains: config.Config.Lego.Domains,
		Bundle:  true,
		// 这里是证书的 key，不是用户的 key，可以手动提供，但肯定不能提供跟用户的 key 一样
		//PrivateKey: otherPrivateKey,
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
