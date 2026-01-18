package backup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BackupInfo 备份信息
type BackupInfo struct {
	OriginalPath string
	BackupPath   string
	Timestamp    time.Time
}

// Backup 备份文件
// 返回备份文件的路径列表
func Backup(paths ...string) ([]BackupInfo, error) {
	var backups []BackupInfo
	now := time.Now()

	for _, path := range paths {
		// 检查文件是否存在
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// 文件不存在，无需备份
			continue
		}

		// 构造备份路径
		backupPath := fmt.Sprintf("%s.backup.%d", path, now.Unix())

		// 创建备份目录
		if err := os.MkdirAll(filepath.Dir(backupPath), 0755); err != nil {
			return nil, fmt.Errorf("create backup directory for %s: %w", backupPath, err)
		}

		// 复制文件
		if err := copyFile(path, backupPath); err != nil {
			return nil, fmt.Errorf("backup file %s to %s: %w", path, backupPath, err)
		}

		backups = append(backups, BackupInfo{
			OriginalPath: path,
			BackupPath:   backupPath,
			Timestamp:    now,
		})
	}

	return backups, nil
}

// Rollback 从备份文件恢复
func Rollback(backups []BackupInfo) error {
	for _, info := range backups {
		// 检查备份文件是否存在
		if _, err := os.Stat(info.BackupPath); os.IsNotExist(err) {
			return fmt.Errorf("backup file not found: %s", info.BackupPath)
		}

		// 确保目标目录存在
		if err := os.MkdirAll(filepath.Dir(info.OriginalPath), 0755); err != nil {
			return fmt.Errorf("create directory for %s: %w", info.OriginalPath, err)
		}

		// 恢复文件
		if err := copyFile(info.BackupPath, info.OriginalPath); err != nil {
			return fmt.Errorf("restore %s from %s: %w", info.OriginalPath, info.BackupPath, err)
		}
	}

	return nil
}

// CleanupBackups 清理旧备份文件，保留最新的 maxKept 个
func CleanupBackups(backupDir string, maxKept int) error {
	if maxKept <= 0 {
		return nil
	}

	// 读取目录下的所有文件
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read backup directory: %w", err)
	}

	// 收集所有备份文件
	var backupFiles []struct {
		path      string
		timestamp int64
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.Contains(name, ".key.backup.") && !strings.Contains(name, ".crt.backup.") {
			continue
		}

		// 从文件名中提取时间戳
		parts := strings.Split(name, ".backup.")
		if len(parts) < 2 {
			continue
		}

		timestamp, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
		if err != nil {
			continue
		}

		backupFiles = append(backupFiles, struct {
			path      string
			timestamp int64
		}{
			path:      filepath.Join(backupDir, name),
			timestamp: timestamp,
		})
	}

	// 按时间戳排序（旧到新）
	sort.Slice(backupFiles, func(i, j int) bool {
		return backupFiles[i].timestamp < backupFiles[j].timestamp
	})

	// 删除多余的备份
	if len(backupFiles) > maxKept {
		for _, bf := range backupFiles[:len(backupFiles)-maxKept] {
			if err := os.Remove(bf.path); err != nil {
				return fmt.Errorf("remove old backup %s: %w", bf.path, err)
			}
		}
	}

	return nil
}

// FindLatestBackup 查找指定文件路径的最新备份
func FindLatestBackup(originalPath string) (string, error) {
	// 查找所有备份文件
	dir := filepath.Dir(originalPath)
	base := filepath.Base(originalPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read directory: %w", err)
	}

	var latestBackup string
	var latestTimestamp int64

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, base+".backup.") {
			continue
		}

		// 提取时间戳
		parts := strings.Split(name, ".backup.")
		if len(parts) < 2 {
			continue
		}

		timestamp, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
		if err != nil {
			continue
		}

		if timestamp > latestTimestamp {
			latestTimestamp = timestamp
			latestBackup = filepath.Join(dir, name)
		}
	}

	if latestBackup == "" {
		return "", fmt.Errorf("no backup found for %s", originalPath)
	}

	return latestBackup, nil
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}
