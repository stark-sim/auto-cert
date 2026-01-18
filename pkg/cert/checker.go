package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertInfo 证书信息
type CertInfo struct {
	NotBefore  time.Time
	NotAfter   time.Time
	DaysLeft   int
	NeedsRenew bool
}

// CheckCertificate 检查证书是否需要续期
func CheckCertificate(certPath string, renewBeforeDays int) (*CertInfo, error) {
	// 读取证书文件
	data, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			// 证书文件不存在，需要获取新证书
			return &CertInfo{NeedsRenew: true}, nil
		}
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	// 解析证书
	cert, err := ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// 计算剩余天数
	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	needsRenew := daysLeft <= renewBeforeDays

	return &CertInfo{
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		DaysLeft:   daysLeft,
		NeedsRenew: needsRenew,
	}, nil
}

// ParseCertificate 解析证书数据
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	// 解析 PEM 格式
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// 解析 x509 证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse x509 certificate: %w", err)
	}

	return cert, nil
}

// IsCertificateExpired 检查证书是否已过期
func IsCertificateExpired(certPath string) (bool, error) {
	info, err := CheckCertificate(certPath, 0)
	if err != nil {
		return false, err
	}

	return info.NotAfter.Before(time.Now()), nil
}
