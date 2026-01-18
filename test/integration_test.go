package test

import (
	"auto-cert/config"
	"auto-cert/pkg/cert"
	"auto-cert/pkg/deployer"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Use a package-level init to set SkipInit before config package imports
func init() {
	os.Setenv("AUTO_CERT_SKIP_INIT", "true")
}

const (
	testDir      = "/tmp/stockholm-test"
	certDir      = testDir + "/certificates"
	servicesDir  = testDir + "/services"
	configPath   = testDir + "/config.yaml"
	testDomain1  = "test.example.com"
	testDomain2  = "gitlab.example.com"
	testDomain3  = "harbor.example.com"
)

// Helper function to clean up test directory
func cleanupTestDir() error {
	return os.RemoveAll(testDir)
}

// Helper function to set up test directory
func setupTestDir() error {
	if err := cleanupTestDir(); err != nil {
		return err
	}
	dirs := []string{
		testDir,
		certDir,
		servicesDir + "/nginx/ssl",
		servicesDir + "/gitlab/ssl",
		servicesDir + "/harbor/ssl",
		servicesDir + "/dify/ssl",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return nil
}

// Helper function to create a test certificate
func createTestCertificate(domain string, daysValid int) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(daysValid*24) * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

// Helper function to create test config
func createTestConfig() error {
	configContent := fmt.Sprintf(`lego:
  email: test@example.com
  domains:
    - %s
    - %s
    - %s
  private_key_path:
  crt_save_dir: %s

aliyun:
  access_key: test_key
  secret_key: test_secret

check:
  renew_before_days: 30

services:
  - name: nginx
    enabled: true
    domain: %s
    targets:
      - cert_path: %s/nginx/ssl/%s.crt
        key_path: %s/nginx/ssl/%s.key
    reload_command: echo "nginx reloaded"
    backup: true

  - name: gitlab
    enabled: true
    domain: %s
    targets:
      - cert_path: %s/gitlab/ssl/%s.crt
        key_path: %s/gitlab/ssl/%s.key
    reload_command: echo "gitlab reloaded"
    backup: true

  - name: harbor
    enabled: false
    domain: %s
    targets:
      - cert_path: %s/harbor/ssl/%s.crt
        key_path: %s/harbor/ssl/%s.key
    reload_command: echo "harbor reloaded"
    backup: true

  - name: dify
    enabled: true
    domain: %s
    targets:
      - cert_path: %s/dify/ssl/dify.crt
        key_path: %s/dify/ssl/dify.key
    reload_command: echo "dify reloaded"
    backup: false
`,
		testDomain1, testDomain2, testDomain3, certDir,
		testDomain1, servicesDir, testDomain1, servicesDir, testDomain1,
		testDomain2, servicesDir, testDomain2, servicesDir, testDomain2,
		testDomain3, servicesDir, testDomain3, servicesDir, testDomain3,
		testDomain1, servicesDir, servicesDir,
	)

	return os.WriteFile(configPath, []byte(configContent), 0644)
}

// Helper function to save test certificates
func saveTestCertificates() error {
	domains := []string{testDomain1, testDomain2, testDomain3}
	for _, domain := range domains {
		certPEM, keyPEM, err := createTestCertificate(domain, 90)
		if err != nil {
			return err
		}
		certFile := filepath.Join(certDir, domain+".crt")
		keyFile := filepath.Join(certDir, domain+".key")
		if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			return err
		}
	}
	return nil
}

// TestFullFlow tests the complete certificate check and deployment flow
func TestFullFlow(t *testing.T) {
	if err := setupTestDir(); err != nil {
		t.Fatalf("Failed to setup test directory: %v", err)
	}
	defer cleanupTestDir()

	if err := createTestConfig(); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg, err := config.LoadConfigWithoutInit(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	t.Log("Config loaded successfully")
	t.Logf("Lego domains: %v", cfg.Lego.Domains)
	t.Logf("Services count: %d", len(cfg.Services))

	// Step 1: Create and save test certificates
	if err := saveTestCertificates(); err != nil {
		t.Fatalf("Failed to save test certificates: %v", err)
	}
	t.Log("Test certificates created")

	// Step 2: Verify certificate files exist
	for _, domain := range []string{testDomain1, testDomain2, testDomain3} {
		certFile := filepath.Join(certDir, domain+".crt")
		keyFile := filepath.Join(certDir, domain+".key")
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			t.Errorf("Certificate file not found: %s", certFile)
		}
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			t.Errorf("Key file not found: %s", keyFile)
		}
	}

	// Step 3: Check certificate validity
	certInfo, err := cert.CheckCertificate(filepath.Join(certDir, testDomain1+".crt"), cfg.Check.RenewBeforeDays)
	if err != nil {
		t.Fatalf("Failed to check certificate: %v", err)
	}
	t.Logf("Certificate info: NotBefore=%s, NotAfter=%s, DaysLeft=%d, NeedsRenew=%v",
		certInfo.NotBefore.Format(time.RFC3339),
		certInfo.NotAfter.Format(time.RFC3339),
		certInfo.DaysLeft,
		certInfo.NeedsRenew)

	if certInfo.DaysLeft <= 0 || certInfo.DaysLeft > 90 {
		t.Errorf("Unexpected days left: %d", certInfo.DaysLeft)
	}

	// Step 4: Collect deploy targets for enabled services
	var deployTargets []deployer.DeployTarget
	var reloadCmds []string
	var backupNeeded bool

	for _, service := range cfg.Services {
		if !service.Enabled {
			t.Logf("Service %s is disabled, skipping", service.Name)
			continue
		}

		t.Logf("Processing enabled service: %s", service.Name)

		// Match domain
		if service.Domain != "" && service.Domain != testDomain1 {
			t.Logf("Service %s domain %s does not match %s, skipping", service.Name, service.Domain, testDomain1)
			continue
		}

		for _, target := range service.Targets {
			if target.CertPath != "" && target.KeyPath != "" {
				deployTargets = append(deployTargets, deployer.DeployTarget{
					CertPath: target.CertPath,
					KeyPath:  target.KeyPath,
				})
			}
		}

		if service.ReloadCmd != "" {
			reloadCmds = append(reloadCmds, service.ReloadCmd)
		}

		if service.Backup {
			backupNeeded = true
		}
	}

	t.Logf("Found %d deploy targets for %s", len(deployTargets), testDomain1)
	if len(deployTargets) == 0 {
		t.Fatal("No deploy targets found")
	}

	// Step 5: Validate targets
	if err := deployer.ValidateTargets(deployTargets); err != nil {
		t.Fatalf("Failed to validate targets: %v", err)
	}
	t.Log("Targets validated")

	// Step 6: Read certificate data
	certData, err := os.ReadFile(filepath.Join(certDir, testDomain1+".crt"))
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}
	keyData, err := os.ReadFile(filepath.Join(certDir, testDomain1+".key"))
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}

	// Step 7: Deploy certificates
	results, err := deployer.Deploy(certData, keyData, deployTargets, backupNeeded)
	if err != nil {
		t.Fatalf("Failed to deploy: %v", err)
	}

	t.Logf("Deployment results:")
	for _, result := range results {
		if result.Success {
			t.Logf("  Deployed to: %s (cert) / %s (key)", result.Target.CertPath, result.Target.KeyPath)
			if backupNeeded && result.BackupCert != "" {
				t.Logf("    Backup created: %s, %s", result.BackupCert, result.BackupKey)
			}
		} else {
			t.Errorf("  Failed to deploy to %s: %v", result.Target.CertPath, result.Error)
		}
	}

	// Step 8: Verify deployed files
	for _, target := range deployTargets {
		if _, err := os.Stat(target.CertPath); os.IsNotExist(err) {
			t.Errorf("Deployed cert file not found: %s", target.CertPath)
		}
		if _, err := os.Stat(target.KeyPath); os.IsNotExist(err) {
			t.Errorf("Deployed key file not found: %s", target.KeyPath)
		}
	}

	// Step 9: Verify backup files were created
	if backupNeeded {
		for _, result := range results {
			if result.BackupCert != "" {
				if _, err := os.Stat(result.BackupCert); os.IsNotExist(err) {
					t.Errorf("Backup cert file not found: %s", result.BackupCert)
				}
			}
			if result.BackupKey != "" {
				if _, err := os.Stat(result.BackupKey); os.IsNotExist(err) {
					t.Errorf("Backup key file not found: %s", result.BackupKey)
				}
			}
		}
	}

	t.Log("Full flow test passed successfully")
}

// TestDomainMatching tests domain matching logic
func TestDomainMatching(t *testing.T) {
	if err := setupTestDir(); err != nil {
		t.Fatalf("Failed to setup test directory: %v", err)
	}
	defer cleanupTestDir()

	if err := createTestConfig(); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg, err := config.LoadConfigWithoutInit(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	testCases := []struct {
		name             string
		domain           string
		expectedServices int
	}{
		{
			name:             "Match first domain",
			domain:           testDomain1,
			expectedServices: 2, // nginx and dify both use testDomain1 (nginx explicitly, dify implicitly as default)
		},
		{
			name:             "Match second domain",
			domain:           testDomain2,
			expectedServices: 1, // only gitlab
		},
		{
			name:             "Match third domain",
			domain:           testDomain3,
			expectedServices: 0, // harbor is disabled
		},
		{
			name:             "No match",
			domain:           "nonexistent.example.com",
			expectedServices: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var matchedServices int
			for _, service := range cfg.Services {
				if !service.Enabled {
					continue
				}
				if service.Domain == "" || service.Domain == tc.domain {
					matchedServices++
					t.Logf("Service %s matched domain %s (service.Domain=%s)", service.Name, tc.domain, service.Domain)
				}
			}
			if matchedServices != tc.expectedServices {
				t.Errorf("Expected %d matched services, got %d", tc.expectedServices, matchedServices)
			}
		})
	}
}

// TestServiceEnabledDisabled tests service enable/disable functionality
func TestServiceEnabledDisabled(t *testing.T) {
	if err := setupTestDir(); err != nil {
		t.Fatalf("Failed to setup test directory: %v", err)
	}
	defer cleanupTestDir()

	if err := createTestConfig(); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg, err := config.LoadConfigWithoutInit(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Count enabled and disabled services
	enabledCount := 0
	disabledCount := 0
	var disabledServiceNames []string

	for _, service := range cfg.Services {
		if service.Enabled {
			enabledCount++
			t.Logf("Enabled service: %s", service.Name)
		} else {
			disabledCount++
			disabledServiceNames = append(disabledServiceNames, service.Name)
			t.Logf("Disabled service: %s", service.Name)
		}
	}

	if enabledCount != 3 {
		t.Errorf("Expected 3 enabled services, got %d", enabledCount)
	}

	if disabledCount != 1 {
		t.Errorf("Expected 1 disabled service, got %d", disabledCount)
	}

	if len(disabledServiceNames) != 1 || disabledServiceNames[0] != "harbor" {
		t.Errorf("Expected harbor to be disabled, got: %v", disabledServiceNames)
	}

	// Test that disabled services are not included in deployment
	if err := saveTestCertificates(); err != nil {
		t.Fatalf("Failed to save test certificates: %v", err)
	}

	certData, err := os.ReadFile(filepath.Join(certDir, testDomain3+".crt"))
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}
	keyData, err := os.ReadFile(filepath.Join(certDir, testDomain3+".key"))
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}

	// Collect targets for harbor (disabled service)
	var harborTargets []deployer.DeployTarget
	for _, service := range cfg.Services {
		if service.Name == "harbor" && !service.Enabled {
			for _, target := range service.Targets {
				if target.CertPath != "" && target.KeyPath != "" {
					harborTargets = append(harborTargets, deployer.DeployTarget{
						CertPath: target.CertPath,
						KeyPath:  target.KeyPath,
					})
				}
			}
		}
	}

	// Deploy to harbor targets (should succeed since deployer doesn't check enabled status)
	if len(harborTargets) > 0 {
		_, err := deployer.Deploy(certData, keyData, harborTargets, true)
		if err != nil {
			t.Errorf("Failed to deploy to harbor targets: %v", err)
		}
	}

	// Verify that when only deploying enabled services, harbor is skipped
	var enabledTargets []deployer.DeployTarget
	for _, service := range cfg.Services {
		if !service.Enabled {
			continue
		}
		for _, target := range service.Targets {
			if target.CertPath != "" && target.KeyPath != "" {
				enabledTargets = append(enabledTargets, deployer.DeployTarget{
					CertPath: target.CertPath,
					KeyPath:  target.KeyPath,
				})
			}
		}
	}

	// Verify none of the enabled targets are harbor paths
	for _, target := range enabledTargets {
		if strings.Contains(target.CertPath, "harbor") || strings.Contains(target.KeyPath, "harbor") {
			t.Errorf("Found harbor path in enabled targets: %s", target.CertPath)
		}
	}

	t.Log("Service enabled/disabled test passed successfully")
}

// TestCertificateExpiration tests certificate expiration checking
func TestCertificateExpiration(t *testing.T) {
	if err := setupTestDir(); err != nil {
		t.Fatalf("Failed to setup test directory: %v", err)
	}
	defer cleanupTestDir()

	testCases := []struct {
		name         string
		daysValid    int
		threshold    int
		needsRenew   bool
	}{
		{
			name:       "Valid certificate (90 days)",
			daysValid:  90,
			threshold:  30,
			needsRenew: false,
		},
		{
			name:       "Expiring soon (25 days)",
			daysValid:  25,
			threshold:  30,
			needsRenew: true,
		},
		{
			name:       "Expired (-5 days)",
			daysValid:  -5,
			threshold:  30,
			needsRenew: true,
		},
		{
			name:       "Exactly at threshold (30 days)",
			daysValid:  30,
			threshold:  30,
			needsRenew: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, _, err := createTestCertificate("test.example.com", tc.daysValid)
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}

			certFile := filepath.Join(certDir, "test-cert.crt")
			if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
				t.Fatalf("Failed to write certificate: %v", err)
			}

			info, err := cert.CheckCertificate(certFile, tc.threshold)
			if err != nil {
				t.Fatalf("Failed to check certificate: %v", err)
			}

			if info.NeedsRenew != tc.needsRenew {
				t.Errorf("Expected NeedsRenew=%v, got %v (DaysLeft=%d, threshold=%d)",
					tc.needsRenew, info.NeedsRenew, info.DaysLeft, tc.threshold)
			}

			t.Logf("Certificate: DaysLeft=%d, NeedsRenew=%v", info.DaysLeft, info.NeedsRenew)
		})
	}
}

// TestBackupFunctionality tests backup functionality
func TestBackupFunctionality(t *testing.T) {
	if err := setupTestDir(); err != nil {
		t.Fatalf("Failed to setup test directory: %v", err)
	}
	defer cleanupTestDir()

	// Create original files
	origCert := filepath.Join(servicesDir, "nginx/ssl/original.crt")
	origKey := filepath.Join(servicesDir, "nginx/ssl/original.key")

	certContent := []byte("-----BEGIN CERTIFICATE-----\noriginal cert\n-----END CERTIFICATE-----")
	keyContent := []byte("-----BEGIN PRIVATE KEY-----\noriginal key\n-----END PRIVATE KEY-----")

	if err := os.WriteFile(origCert, certContent, 0644); err != nil {
		t.Fatalf("Failed to write original cert: %v", err)
	}
	if err := os.WriteFile(origKey, keyContent, 0600); err != nil {
		t.Fatalf("Failed to write original key: %v", err)
	}

	// Test deployment with backup
	newCert := []byte("-----BEGIN CERTIFICATE-----\nnew cert\n-----END CERTIFICATE-----")
	newKey := []byte("-----BEGIN PRIVATE KEY-----\nnew key\n-----END PRIVATE KEY-----")

	targets := []deployer.DeployTarget{
		{CertPath: origCert, KeyPath: origKey},
	}

	results, err := deployer.Deploy(newCert, newKey, targets, true)
	if err != nil {
		t.Fatalf("Failed to deploy: %v", err)
	}

	// Verify backup files were created
	for _, result := range results {
		if result.Success {
			if result.BackupCert == "" || result.BackupKey == "" {
				t.Error("Backup files should have been created")
			} else {
				t.Logf("Backup cert: %s", result.BackupCert)
				t.Logf("Backup key: %s", result.BackupKey)

				// Verify backup content
				backupCertContent, err := os.ReadFile(result.BackupCert)
				if err != nil {
					t.Fatalf("Failed to read backup cert: %v", err)
				}
				if string(backupCertContent) != string(certContent) {
					t.Error("Backup cert content doesn't match original")
				}

				backupKeyContent, err := os.ReadFile(result.BackupKey)
				if err != nil {
					t.Fatalf("Failed to read backup key: %v", err)
				}
				if string(backupKeyContent) != string(keyContent) {
					t.Error("Backup key content doesn't match original")
				}
			}
		}
	}

	// Verify files were updated
	currentCert, err := os.ReadFile(origCert)
	if err != nil {
		t.Fatalf("Failed to read current cert: %v", err)
	}
	if string(currentCert) != string(newCert) {
		t.Error("Cert file was not updated")
	}

	currentKey, err := os.ReadFile(origKey)
	if err != nil {
		t.Fatalf("Failed to read current key: %v", err)
	}
	if string(currentKey) != string(newKey) {
		t.Error("Key file was not updated")
	}

	t.Log("Backup functionality test passed successfully")
}

// TestReloadCommandExecution tests reload command execution
func TestReloadCommandExecution(t *testing.T) {
	testCases := []struct {
		name      string
		cmd       string
		shouldErr bool
	}{
		{
			name:      "Simple echo command",
			cmd:       "echo 'test reload'",
			shouldErr: false,
		},
		{
			name:      "Command with arguments",
			cmd:       "echo 'nginx' 'reload'",
			shouldErr: false,
		},
		{
			name:      "Non-existent command",
			cmd:       "nonexistent_command_12345",
			shouldErr: true,
		},
		{
			name:      "Empty command",
			cmd:       "",
			shouldErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := deployer.ExecuteReload(tc.cmd)
			if tc.shouldErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.shouldErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}

	t.Log("Reload command execution test passed successfully")
}

// TestMultiServiceDeployment tests deployment to multiple services
func TestMultiServiceDeployment(t *testing.T) {
	if err := setupTestDir(); err != nil {
		t.Fatalf("Failed to setup test directory: %v", err)
	}
	defer cleanupTestDir()

	if err := createTestConfig(); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	cfg, err := config.LoadConfigWithoutInit(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if err := saveTestCertificates(); err != nil {
		t.Fatalf("Failed to save test certificates: %v", err)
	}

	// Collect all deploy targets for all enabled services
	var allTargets []deployer.DeployTarget
	serviceTargetMap := make(map[string][]deployer.DeployTarget)

	for _, service := range cfg.Services {
		if !service.Enabled {
			continue
		}

		for _, target := range service.Targets {
			if target.CertPath != "" && target.KeyPath != "" {
				deployTarget := deployer.DeployTarget{
					CertPath: target.CertPath,
					KeyPath:  target.KeyPath,
				}
				allTargets = append(allTargets, deployTarget)
				serviceTargetMap[service.Name] = append(serviceTargetMap[service.Name], deployTarget)
			}
		}
	}

	t.Logf("Total deploy targets: %d", len(allTargets))

	// Create existing certificate files for backup testing
	// This ensures backups will be created when deploying
	originalCertContent := []byte("-----BEGIN CERTIFICATE-----\noriginal cert\n-----END CERTIFICATE-----")
	originalKeyContent := []byte("-----BEGIN PRIVATE KEY-----\noriginal key\n-----END PRIVATE KEY-----")

	for _, target := range allTargets {
		// Create parent directories if needed
		if err := os.MkdirAll(filepath.Dir(target.CertPath), 0755); err != nil {
			t.Fatalf("Failed to create cert directory: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(target.KeyPath), 0755); err != nil {
			t.Fatalf("Failed to create key directory: %v", err)
		}
		// Create original files
		if err := os.WriteFile(target.CertPath, originalCertContent, 0644); err != nil {
			t.Fatalf("Failed to write original cert: %v", err)
		}
		if err := os.WriteFile(target.KeyPath, originalKeyContent, 0600); err != nil {
			t.Fatalf("Failed to write original key: %v", err)
		}
	}

	// Read test certificate data
	certData, err := os.ReadFile(filepath.Join(certDir, testDomain1+".crt"))
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}
	keyData, err := os.ReadFile(filepath.Join(certDir, testDomain1+".key"))
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}

	// Deploy all targets
	results, err := deployer.Deploy(certData, keyData, allTargets, true)
	if err != nil {
		t.Fatalf("Failed to deploy: %v", err)
	}

	// Count successful and failed deployments
	successCount := 0
	failedCount := 0
	for _, result := range results {
		if result.Success {
			successCount++
		} else {
			failedCount++
		}
	}

	t.Logf("Deployment results: %d successful, %d failed", successCount, failedCount)

	if failedCount > 0 {
		t.Errorf("Expected all deployments to succeed, but %d failed", failedCount)
	}

	// Verify all files were created
	for _, target := range allTargets {
		if _, err := os.Stat(target.CertPath); os.IsNotExist(err) {
			t.Errorf("Cert file not deployed: %s", target.CertPath)
		}
		if _, err := os.Stat(target.KeyPath); os.IsNotExist(err) {
			t.Errorf("Key file not deployed: %s", target.KeyPath)
		}
	}

	// Verify backup files exist for targets with backup enabled
	for service, targets := range serviceTargetMap {
		var backupEnabled bool
		for _, svc := range cfg.Services {
			if svc.Name == service {
				backupEnabled = svc.Backup
				break
			}
		}

		if backupEnabled {
			for _, target := range targets {
				// Check if backup files exist (with timestamp suffix)
				dir := filepath.Dir(target.CertPath)
				entries, _ := os.ReadDir(dir)
				foundCertBackup := false
				foundKeyBackup := false
				for _, entry := range entries {
					name := entry.Name()
					if !entry.IsDir() {
						if strings.HasPrefix(name, filepath.Base(target.CertPath)+".backup.") {
							foundCertBackup = true
						}
						if strings.HasPrefix(name, filepath.Base(target.KeyPath)+".backup.") {
							foundKeyBackup = true
						}
					}
				}

				if !foundCertBackup {
					t.Errorf("Backup cert not found for service %s", service)
				}
				if !foundKeyBackup {
					t.Errorf("Backup key not found for service %s", service)
				}
			}
		}
	}

	t.Log("Multi-service deployment test passed successfully")
}
