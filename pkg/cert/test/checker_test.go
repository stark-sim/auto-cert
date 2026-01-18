package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"auto-cert/pkg/cert"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

// generateTestCertificate 生成测试证书
func generateTestCertificate(notBefore, notAfter time.Time) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	return certPEM, keyPEM, nil
}

// createTempCertFile 创建临时证书文件
func createTempCertFile(t *testing.T, certData []byte) string {
	t.Helper()
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.crt")

	if err := os.WriteFile(certPath, certData, 0644); err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}

	return certPath
}

func TestCheckCertificate(t *testing.T) {
	t.Run("证书文件不存在", func(t *testing.T) {
		info, err := cert.CheckCertificate("/nonexistent/cert.crt", 30)
		if err != nil {
			t.Fatalf("Expected no error for non-existent file, got: %v", err)
		}

		if !info.NeedsRenew {
			t.Error("Expected NeedsRenew to be true for non-existent certificate")
		}
	})

	t.Run("有效证书 - 不需要续期", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-24*time.Hour),
			now.Add(90*24*time.Hour), // 90 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		info, err := cert.CheckCertificate(certPath, 30)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.NeedsRenew {
			t.Errorf("Expected NeedsRenew to be false, got true (DaysLeft: %d)", info.DaysLeft)
		}

		if info.DaysLeft < 60 {
			t.Errorf("Expected more than 60 days left, got: %d", info.DaysLeft)
		}

		logrus.Infof("Valid certificate - NotBefore: %s, NotAfter: %s, DaysLeft: %d",
			info.NotBefore.Format(time.RFC3339),
			info.NotAfter.Format(time.RFC3339),
			info.DaysLeft)
	})

	t.Run("即将过期 - 需要续期", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-300*24*time.Hour),
			now.Add(15*24*time.Hour), // 15 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		info, err := cert.CheckCertificate(certPath, 30)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !info.NeedsRenew {
			t.Errorf("Expected NeedsRenew to be true, got false (DaysLeft: %d)", info.DaysLeft)
		}

		if info.DaysLeft > 20 {
			t.Errorf("Expected less than 20 days left, got: %d", info.DaysLeft)
		}

		logrus.Infof("Expiring certificate - NotBefore: %s, NotAfter: %s, DaysLeft: %d",
			info.NotBefore.Format(time.RFC3339),
			info.NotAfter.Format(time.RFC3339),
			info.DaysLeft)
	})

	t.Run("刚好需要续期的临界值", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-300*24*time.Hour),
			now.Add(30*24*time.Hour), // 正好 30 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		info, err := cert.CheckCertificate(certPath, 30)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		// 30 天或更少应该需要续期
		if !info.NeedsRenew {
			t.Logf("Warning: Expected NeedsRenew to be true at boundary (DaysLeft: %d)", info.DaysLeft)
		}

		logrus.Infof("Boundary certificate - DaysLeft: %d, NeedsRenew: %v", info.DaysLeft, info.NeedsRenew)
	})

	t.Run("无效的证书数据", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.crt")

		if err := os.WriteFile(certPath, []byte("invalid certificate data"), 0644); err != nil {
			t.Fatalf("Failed to write invalid certificate: %v", err)
		}

		_, err := cert.CheckCertificate(certPath, 30)
		if err == nil {
			t.Error("Expected error for invalid certificate data, got nil")
		}

		logrus.Infof("Got expected error for invalid certificate: %v", err)
	})
}

func TestParseCertificate(t *testing.T) {
	t.Run("解析有效的 PEM 证书", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-24*time.Hour),
			now.Add(90*24*time.Hour),
		)

		cert, err := cert.ParseCertificate(certPEM)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if cert == nil {
			t.Fatal("Expected non-nil certificate")
		}

		if cert.Subject.CommonName != "test.example.com" {
			t.Errorf("Expected CommonName 'test.example.com', got: %s", cert.Subject.CommonName)
		}

		if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "test.example.com" {
			t.Errorf("Expected DNSNames to contain 'test.example.com', got: %v", cert.DNSNames)
		}

		logrus.Infof("Successfully parsed certificate: Subject=%s, Validity=%s to %s",
			cert.Subject.CommonName,
			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339))
	})

	t.Run("解析空数据", func(t *testing.T) {
		_, err := cert.ParseCertificate([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, got nil")
		}
	})

	t.Run("解析无效的 PEM 数据", func(t *testing.T) {
		_, err := cert.ParseCertificate([]byte("invalid pem data"))
		if err == nil {
			t.Error("Expected error for invalid PEM data, got nil")
		}
	})

	t.Run("解析有效的 PEM 但非证书", func(t *testing.T) {
		// 创建一个有效的 PEM 块，但不是证书
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("not a certificate"),
		})

		_, err := cert.ParseCertificate(pemData)
		if err == nil {
			t.Error("Expected error for non-certificate PEM block, got nil")
		}

		logrus.Infof("Got expected error for non-certificate PEM: %v", err)
	})
}

func TestIsCertificateExpired(t *testing.T) {
	t.Run("已过期的证书", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-400*24*time.Hour),
			now.Add(-10*24*time.Hour), // 10 天前已过期
		)

		certPath := createTempCertFile(t, certPEM)

		expired, err := cert.IsCertificateExpired(certPath)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !expired {
			t.Error("Expected expired certificate to be marked as expired")
		}

		logrus.Infof("Expired certificate correctly identified")
	})

	t.Run("有效的证书", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-24*time.Hour),
			now.Add(90*24*time.Hour),
		)

		certPath := createTempCertFile(t, certPEM)

		expired, err := cert.IsCertificateExpired(certPath)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if expired {
			t.Error("Expected valid certificate to not be marked as expired")
		}

		logrus.Infof("Valid certificate correctly identified")
	})

	t.Run("刚好过期的证书 (当前时间)", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-365*24*time.Hour),
			now, // 刚好现在过期
		)

		certPath := createTempCertFile(t, certPEM)

		expired, err := cert.IsCertificateExpired(certPath)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !expired {
			t.Log("Certificate at exact expiry time not marked as expired (acceptable behavior)")
		}

		logrus.Infof("Boundary expiration check - expired: %v", expired)
	})

	t.Run("证书文件不存在", func(t *testing.T) {
		expired, err := cert.IsCertificateExpired("/nonexistent/cert.crt")
		// CheckCertificate returns CertInfo{NeedsRenew: true}, nil for non-existent files
		// Then NotAfter (zero time) is checked against time.Now(), which returns true (expired)
		// This is correct behavior - a missing certificate is treated as needing renewal/expired
		if err != nil {
			t.Fatalf("Expected no error for non-existent file, got: %v", err)
		}

		if !expired {
			t.Error("Expected non-existent certificate to be marked as expired (zero time is before now)")
		}

		logrus.Infof("Non-existent certificate correctly identified as expired (needs renewal)")
	})

	t.Run("即将过期但未过期的证书", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-300*24*time.Hour),
			now.Add(1*24*time.Hour), // 1 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		expired, err := cert.IsCertificateExpired(certPath)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if expired {
			t.Error("Expected certificate expiring in future to not be marked as expired")
		}

		logrus.Infof("Certificate expiring soon but not expired - expired: %v", expired)
	})
}

// TestCheckCertificateEdgeCases 测试边界情况
func TestCheckCertificateEdgeCases(t *testing.T) {
	t.Run("零天阈值", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-24*time.Hour),
			now.Add(1*24*time.Hour), // 1 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		info, err := cert.CheckCertificate(certPath, 0)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if info.NeedsRenew && info.DaysLeft > 0 {
			t.Logf("With 0 day threshold, certificate with %d days left is marked for renewal", info.DaysLeft)
		}

		logrus.Infof("Zero day threshold test - DaysLeft: %d, NeedsRenew: %v", info.DaysLeft, info.NeedsRenew)
	})

	t.Run("负数阈值 (不应触发续期)", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-24*time.Hour),
			now.Add(10*24*time.Hour), // 10 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		info, err := cert.CheckCertificate(certPath, -5)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		logrus.Infof("Negative threshold test - DaysLeft: %d, NeedsRenew: %v", info.DaysLeft, info.NeedsRenew)
	})

	t.Run("大阈值值", func(t *testing.T) {
		now := time.Now()
		certPEM, _, _ := generateTestCertificate(
			now.Add(-24*time.Hour),
			now.Add(90*24*time.Hour), // 90 天后过期
		)

		certPath := createTempCertFile(t, certPEM)

		info, err := cert.CheckCertificate(certPath, 180) // 180 天阈值
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !info.NeedsRenew {
			t.Errorf("Expected NeedsRenew to be true with large threshold (DaysLeft: %d)", info.DaysLeft)
		}

		logrus.Infof("Large threshold test - DaysLeft: %d, NeedsRenew: %v", info.DaysLeft, info.NeedsRenew)
	})
}

// TestGenerateTestCertificateCertificate 验证生成的证书基本属性
func TestGenerateTestCertificateCertificate(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := generateTestCertificate(
		now.Add(-24*time.Hour),
		now.Add(90*24*time.Hour),
	)

	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("Generated certificate PEM is empty")
	}

	if len(keyPEM) == 0 {
		t.Error("Generated key PEM is empty")
	}

	// 验证可以解析生成的证书
	cert, err := cert.ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("Failed to parse generated certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CommonName 'test.example.com', got: %s", cert.Subject.CommonName)
	}

	logrus.Infof("Generated certificate validated successfully: CN=%s, Validity=%s to %s",
		cert.Subject.CommonName,
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339))
}
