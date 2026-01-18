package deployer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DeployTarget 部署目标
type DeployTarget struct {
	CertPath string
	KeyPath  string
}

// DeployResult 部署结果
type DeployResult struct {
	Target    DeployTarget
	BackupKey string
	BackupCert string
	Success   bool
	Error     error
}

// Deploy 部署证书到指定目标
func Deploy(cert []byte, key []byte, targets []DeployTarget, backup bool) ([]DeployResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no deploy targets specified")
	}

	results := make([]DeployResult, 0, len(targets))
	var hasError bool

	for _, target := range targets {
		result := DeployResult{Target: target}

		// 验证路径
		if target.CertPath == "" || target.KeyPath == "" {
			result.Error = fmt.Errorf("cert_path or key_path is empty")
			result.Success = false
			results = append(results, result)
			hasError = true
			continue
		}

		// 创建目录
		if err := CreateDirs(filepath.Dir(target.CertPath), filepath.Dir(target.KeyPath)); err != nil {
			result.Error = fmt.Errorf("create directories: %w", err)
			result.Success = false
			results = append(results, result)
			hasError = true
			continue
		}

		// 备份现有文件
		if backup {
			backupCertPath, backupKeyPath, err := BackupFiles(target.CertPath, target.KeyPath)
			if err != nil {
				result.Error = fmt.Errorf("backup files: %w", err)
				result.Success = false
				results = append(results, result)
				hasError = true
				continue
			}
			result.BackupCert = backupCertPath
			result.BackupKey = backupKeyPath
		}

		// 写入证书文件
		if err := WriteFileWithPerm(target.CertPath, cert, 0644); err != nil {
			result.Error = fmt.Errorf("write cert file: %w", err)
			result.Success = false
			results = append(results, result)
			hasError = true
			continue
		}

		// 写入私钥文件（更严格的权限）
		if err := WriteFileWithPerm(target.KeyPath, key, 0600); err != nil {
			result.Error = fmt.Errorf("write key file: %w", err)
			result.Success = false
			results = append(results, result)
			hasError = true
			continue
		}

		result.Success = true
		results = append(results, result)
	}

	if hasError {
		return results, fmt.Errorf("some deployments failed")
	}

	return results, nil
}

// CreateDirs 创建目录
func CreateDirs(paths ...string) error {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("create directory %s: %w", path, err)
		}
	}
	return nil
}

// WriteFileWithPerm 写入文件并设置权限
func WriteFileWithPerm(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	return nil
}

// BackupFiles 备份文件
func BackupFiles(certPath, keyPath string) (string, string, error) {
	var backupCertPath, backupKeyPath string

	if _, err := os.Stat(certPath); err == nil {
		backupCertPath = fmt.Sprintf("%s.backup.%d", certPath, getCurrentTimestamp())
		if err := copyFile(certPath, backupCertPath); err != nil {
			return "", "", fmt.Errorf("backup cert: %w", err)
		}
	}

	if _, err := os.Stat(keyPath); err == nil {
		backupKeyPath = fmt.Sprintf("%s.backup.%d", keyPath, getCurrentTimestamp())
		if err := copyFile(keyPath, backupKeyPath); err != nil {
			return "", "", fmt.Errorf("backup key: %w", err)
		}
	}

	return backupCertPath, backupKeyPath, nil
}

// RestoreFromBackup 从备份恢复
func RestoreFromBackup(backupCertPath, backupKeyPath, certPath, keyPath string) error {
	if backupCertPath != "" {
		if err := copyFile(backupCertPath, certPath); err != nil {
			return fmt.Errorf("restore cert: %w", err)
		}
	}

	if backupKeyPath != "" {
		if err := copyFile(backupKeyPath, keyPath); err != nil {
			return fmt.Errorf("restore key: %w", err)
		}
	}

	return nil
}

// ExecuteReload 执行服务重载命令
func ExecuteReload(cmd string) error {
	if cmd == "" {
		return nil
	}

	// 分割命令和参数
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil
	}

	var execCmd *exec.Cmd
	if len(parts) > 1 {
		execCmd = exec.Command(parts[0], parts[1:]...)
	} else {
		execCmd = exec.Command(parts[0])
	}

	// 设置工作目录
	execCmd.Dir = "/"

	// 执行命令
	output, err := execCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("execute reload command '%s': %w, output: %s", cmd, err, string(output))
	}

	return nil
}

// ValidateTargets 验证部署目标配置
func ValidateTargets(targets []DeployTarget) error {
	for i, target := range targets {
		if target.CertPath == "" {
			return fmt.Errorf("target[%d]: cert_path is required", i)
		}
		if target.KeyPath == "" {
			return fmt.Errorf("target[%d]: key_path is required", i)
		}

		// 检查是否为绝对路径或相对路径
		if !filepath.IsAbs(target.CertPath) {
			// 相对路径，使用当前工作目录
			if cwd, err := os.Getwd(); err == nil {
				target.CertPath = filepath.Join(cwd, target.CertPath)
			}
		}
		if !filepath.IsAbs(target.KeyPath) {
			if cwd, err := os.Getwd(); err == nil {
				target.KeyPath = filepath.Join(cwd, target.KeyPath)
			}
		}

		// 检查路径是否可写（如果文件已存在）
		if dir := filepath.Dir(target.CertPath); dir != "" {
			if _, err := os.Stat(dir); err == nil {
				// 目录存在，检查是否可写
				testFile := filepath.Join(dir, ".write_test")
				if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
					os.Remove(testFile)
				} else {
					return fmt.Errorf("target[%d]: cert directory is not writable: %s", i, dir)
				}
			}
		}

		if dir := filepath.Dir(target.KeyPath); dir != "" && dir != filepath.Dir(target.CertPath) {
			if _, err := os.Stat(dir); err == nil {
				testFile := filepath.Join(dir, ".write_test")
				if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
					os.Remove(testFile)
				} else {
					return fmt.Errorf("target[%d]: key directory is not writable: %s", i, dir)
				}
			}
		}
	}

	return nil
}

// ValidateReloadCmd 验证重载命令
func ValidateReloadCmd(cmd string) error {
	if cmd == "" {
		return nil
	}

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty reload command")
	}

	// 检查命令是否存在
	_, err := exec.LookPath(parts[0])
	if err != nil {
		return fmt.Errorf("reload command not found: %s", parts[0])
	}

	return nil
}

// getCurrentTimestamp 获取当前时间戳
func getCurrentTimestamp() int64 {
	return time.Now().Unix()
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return err
	}

	return nil
}
