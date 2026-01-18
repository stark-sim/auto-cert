package backup_test

import (
	"auto-cert/pkg/backup"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBackup 测试文件备份功能
func TestBackup(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-backup")
	defer os.RemoveAll(testDir)

	// 创建测试文件
	testFile := filepath.Join(testDir, "test.txt")
	originalContent := "original content"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}
	if err := os.WriteFile(testFile, []byte(originalContent), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// 执行备份
	backups, err := backup.Backup(testFile)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 验证返回的备份信息
	if len(backups) != 1 {
		t.Errorf("expected 1 backup, got %d", len(backups))
	}
	if backups[0].OriginalPath != testFile {
		t.Errorf("expected original path %s, got %s", testFile, backups[0].OriginalPath)
	}
	if !strings.Contains(backups[0].BackupPath, ".backup.") {
		t.Errorf("backup path should contain .backup., got %s", backups[0].BackupPath)
	}

	// 验证备份文件是否存在
	if _, err := os.Stat(backups[0].BackupPath); os.IsNotExist(err) {
		t.Errorf("backup file does not exist: %s", backups[0].BackupPath)
	}

	// 验证备份文件内容
	backupContent, err := os.ReadFile(backups[0].BackupPath)
	if err != nil {
		t.Fatalf("failed to read backup file: %v", err)
	}
	if string(backupContent) != originalContent {
		t.Errorf("backup content mismatch: expected %s, got %s", originalContent, string(backupContent))
	}
}

// TestBackupNonExistentFile 测试文件不存在时备份的行为
func TestBackupNonExistentFile(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-nonexistent")
	defer os.RemoveAll(testDir)

	// 不存在的文件
	nonExistentFile := filepath.Join(testDir, "nonexistent.txt")

	// 执行备份
	backups, err := backup.Backup(nonExistentFile)
	if err != nil {
		t.Fatalf("Backup() should not fail for non-existent file: %v", err)
	}

	// 应该没有备份信息
	if len(backups) != 0 {
		t.Errorf("expected 0 backups for non-existent file, got %d", len(backups))
	}
}

// TestBackupMultipleFiles 测试备份多个文件
func TestBackupMultipleFiles(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-multiple")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建多个测试文件
	file1 := filepath.Join(testDir, "file1.txt")
	file2 := filepath.Join(testDir, "file2.txt")
	file3 := filepath.Join(testDir, "file3.txt")

	for _, f := range []string{file1, file2, file3} {
		if err := os.WriteFile(f, []byte("content"), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", f, err)
		}
	}

	// 执行备份
	backups, err := backup.Backup(file1, file2, file3)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 验证返回的备份信息
	if len(backups) != 3 {
		t.Errorf("expected 3 backups, got %d", len(backups))
	}

	// 验证每个备份文件都存在
	for _, b := range backups {
		if _, err := os.Stat(b.BackupPath); os.IsNotExist(err) {
			t.Errorf("backup file does not exist: %s", b.BackupPath)
		}
	}
}

// TestBackupTimestampNaming 测试备份文件使用时间戳命名
func TestBackupTimestampNaming(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-timestamp")
	defer os.RemoveAll(testDir)

	// 创建测试文件
	testFile := filepath.Join(testDir, "test.crt")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}
	if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// 执行备份
	backups, err := backup.Backup(testFile)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 验证备份文件名包含时间戳
	backupFilename := filepath.Base(backups[0].BackupPath)
	if !strings.Contains(backupFilename, ".backup.") {
		t.Errorf("backup filename should contain .backup., got %s", backupFilename)
	}

	// 从文件名中提取时间戳
	parts := strings.Split(backupFilename, ".backup.")
	if len(parts) < 2 {
		t.Fatalf("unable to extract timestamp from filename: %s", backupFilename)
	}

	// 验证时间戳格式
	timestampStr := parts[len(parts)-1]
	var timestamp int64
	if _, err := fmt.Sscanf(timestampStr, "%d", &timestamp); err != nil {
		t.Fatalf("invalid timestamp format: %s", timestampStr)
	}

	// 验证时间戳是一个有效的 Unix 时间戳（不应该太旧或太未来）
	timestampTime := time.Unix(timestamp, 0)
	now := time.Now()
	// 允许的时间范围：过去 1 分钟到未来 1 分钟
	minTime := now.Add(-1 * time.Minute)
	maxTime := now.Add(1 * time.Minute)

	if timestampTime.Before(minTime) || timestampTime.After(maxTime) {
		t.Errorf("timestamp %v is not within reasonable range [%v, %v]", timestampTime, minTime, maxTime)
	}
}

// TestRollback 测试文件回滚功能
func TestRollback(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-rollback")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建测试文件
	testFile := filepath.Join(testDir, "test.txt")
	originalContent := "original content"
	modifiedContent := "modified content"

	if err := os.WriteFile(testFile, []byte(originalContent), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// 执行备份
	backups, err := backup.Backup(testFile)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 修改原始文件
	if err := os.WriteFile(testFile, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// 验证文件已被修改
	currentContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if string(currentContent) != modifiedContent {
		t.Errorf("file content should be modified, got %s", string(currentContent))
	}

	// 执行回滚
	if err := backup.Rollback(backups); err != nil {
		t.Fatalf("Rollback() failed: %v", err)
	}

	// 验证文件已恢复
	restoredContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read test file after rollback: %v", err)
	}
	if string(restoredContent) != originalContent {
		t.Errorf("file content should be restored to original, expected %s, got %s", originalContent, string(restoredContent))
	}
}

// TestRollbackNonExistentBackup 测试备份文件不存在时的回滚
func TestRollbackNonExistentBackup(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-rollback-nonexistent")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建一个不存在的备份信息
	backups := []backup.BackupInfo{
		{
			OriginalPath: filepath.Join(testDir, "test.txt"),
			BackupPath:   filepath.Join(testDir, "test.txt.backup.1234567890"),
		},
	}

	// 执行回滚，应该失败
	err := backup.Rollback(backups)
	if err == nil {
		t.Error("Rollback() should fail for non-existent backup file")
	}
	if !strings.Contains(err.Error(), "backup file not found") {
		t.Errorf("expected 'backup file not found' error, got: %v", err)
	}
}

// TestRollbackMultipleFiles 测试回滚多个文件
func TestRollbackMultipleFiles(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-rollback-multiple")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建多个测试文件
	file1 := filepath.Join(testDir, "file1.txt")
	file2 := filepath.Join(testDir, "file2.txt")
	originalContent := "original"
	modifiedContent := "modified"

	for _, f := range []string{file1, file2} {
		if err := os.WriteFile(f, []byte(originalContent), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", f, err)
		}
	}

	// 执行备份
	backups, err := backup.Backup(file1, file2)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 修改原始文件
	for _, f := range []string{file1, file2} {
		if err := os.WriteFile(f, []byte(modifiedContent), 0644); err != nil {
			t.Fatalf("failed to modify test file %s: %v", f, err)
		}
	}

	// 执行回滚
	if err := backup.Rollback(backups); err != nil {
		t.Fatalf("Rollback() failed: %v", err)
	}

	// 验证所有文件已恢复
	for _, f := range []string{file1, file2} {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read test file %s after rollback: %v", f, err)
		}
		if string(content) != originalContent {
			t.Errorf("file %s content should be restored, expected %s, got %s", f, originalContent, string(content))
		}
	}
}

// TestRollbackCreatesDirectory 测试回滚时创建不存在的目录
func TestRollbackCreatesDirectory(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-rollback-dir")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建备份文件（目标目录不存在）
	backupFile := filepath.Join(testDir, "backup.txt.backup.1234567890")
	targetFile := filepath.Join(testDir, "subdir", "target.txt")

	// 创建备份文件
	if err := os.WriteFile(backupFile, []byte("backup content"), 0644); err != nil {
		t.Fatalf("failed to create backup file: %v", err)
	}

	// 执行回滚
	backups := []backup.BackupInfo{
		{
			OriginalPath: targetFile,
			BackupPath:   backupFile,
		},
	}
	if err := backup.Rollback(backups); err != nil {
		t.Fatalf("Rollback() failed: %v", err)
	}

	// 验证文件已恢复
	content, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed to read target file: %v", err)
	}
	if string(content) != "backup content" {
		t.Errorf("target file content mismatch, expected %s, got %s", "backup content", string(content))
	}
}

// TestCleanupBackups 测试旧备份清理功能
func TestCleanupBackups(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-cleanup")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建多个备份文件（注意：CleanupBackups 只处理 .key.backup. 或 .crt.backup. 结尾的文件）
	baseTime := time.Now().Unix()
	for i := 0; i < 5; i++ {
		timestamp := baseTime + int64(i*100)
		backupFile := filepath.Join(testDir, "test.key.backup."+strconv.FormatInt(timestamp, 10))
		if err := os.WriteFile(backupFile, []byte("backup content"), 0644); err != nil {
			t.Fatalf("failed to create backup file %s: %v", backupFile, err)
		}
	}

	// 创建一个非备份文件，应该被保留
	regularFile := filepath.Join(testDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("regular content"), 0644); err != nil {
		t.Fatalf("failed to create regular file: %v", err)
	}

	// 清理，保留最新的 2 个
	if err := backup.CleanupBackups(testDir, 2); err != nil {
		t.Fatalf("CleanupBackups() failed: %v", err)
	}

	// 验证只保留了 2 个备份文件
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	var backupCount int
	var regularFileExists bool
	for _, f := range files {
		if strings.Contains(f.Name(), ".key.backup.") || strings.Contains(f.Name(), ".crt.backup.") {
			backupCount++
		}
		if f.Name() == "regular.txt" {
			regularFileExists = true
		}
	}

	if backupCount != 2 {
		t.Errorf("expected 2 backup files after cleanup, got %d", backupCount)
	}
	if !regularFileExists {
		t.Error("regular file should not be deleted")
	}
}

// TestCleanupBackupsMaxKeptZero 测试 maxKept 为 0 时不删除任何备份
func TestCleanupBackupsMaxKeptZero(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-cleanup-zero")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建多个备份文件
	baseTime := time.Now().Unix()
	for i := 0; i < 5; i++ {
		timestamp := baseTime + int64(i*100)
		backupFile := filepath.Join(testDir, "test.crt.backup."+strconv.FormatInt(timestamp, 10))
		if err := os.WriteFile(backupFile, []byte("backup content"), 0644); err != nil {
			t.Fatalf("failed to create backup file %s: %v", backupFile, err)
		}
	}

	// 清理，maxKept 为 0，不删除任何备份
	if err := backup.CleanupBackups(testDir, 0); err != nil {
		t.Fatalf("CleanupBackups() failed: %v", err)
	}

	// 验证所有备份文件都还在
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	if len(files) != 5 {
		t.Errorf("expected 5 backup files when maxKept is 0, got %d", len(files))
	}
}

// TestCleanupBackupsNonExistentDirectory 测试目录不存在时的清理行为
func TestCleanupBackupsNonExistentDirectory(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-cleanup-nonexistent")

	// 目录不存在，应该返回 nil
	if err := backup.CleanupBackups(testDir, 5); err != nil {
		t.Errorf("CleanupBackups() should return nil for non-existent directory, got: %v", err)
	}
}

// TestCleanupBackupsKeepsNewest 测试保留最新的备份
func TestCleanupBackupsKeepsNewest(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-cleanup-newest")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建多个备份文件，时间戳从旧到新
	baseTime := time.Now().Unix()
	var newestBackup string
	for i := 0; i < 10; i++ {
		timestamp := baseTime + int64(i*100)
		backupFile := filepath.Join(testDir, "test.key.backup."+strconv.FormatInt(timestamp, 10))
		if err := os.WriteFile(backupFile, []byte("backup content"), 0644); err != nil {
			t.Fatalf("failed to create backup file %s: %v", backupFile, err)
		}
		newestBackup = backupFile
	}

	// 清理，保留最新的 3 个
	if err := backup.CleanupBackups(testDir, 3); err != nil {
		t.Fatalf("CleanupBackups() failed: %v", err)
	}

	// 验证最新的备份被保留
	if _, err := os.Stat(newestBackup); os.IsNotExist(err) {
		t.Errorf("newest backup should be kept: %s", newestBackup)
	}

	// 验证只有 3 个备份文件
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	var backupCount int
	for _, f := range files {
		if strings.Contains(f.Name(), ".key.backup.") || strings.Contains(f.Name(), ".crt.backup.") {
			backupCount++
		}
	}

	if backupCount != 3 {
		t.Errorf("expected 3 backup files, got %d", backupCount)
	}
}

// TestCleanupBackupsMixedExtensions 测试混合扩展名的备份清理
func TestCleanupBackupsMixedExtensions(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-cleanup-mixed")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建不同扩展名的备份文件（只有 .key.backup. 和 .crt.backup. 会被清理）
	baseTime := time.Now().Unix()
	backupFiles := []string{
		"test1.key.backup." + strconv.FormatInt(baseTime, 10),
		"test2.crt.backup." + strconv.FormatInt(baseTime+100, 10),
		"test3.key.backup." + strconv.FormatInt(baseTime+200, 10),
		"test4.crt.backup." + strconv.FormatInt(baseTime+300, 10),
	}

	for _, bf := range backupFiles {
		backupFile := filepath.Join(testDir, bf)
		if err := os.WriteFile(backupFile, []byte("backup content"), 0644); err != nil {
			t.Fatalf("failed to create backup file %s: %v", backupFile, err)
		}
	}

	// 清理，保留最新的 2 个
	if err := backup.CleanupBackups(testDir, 2); err != nil {
		t.Fatalf("CleanupBackups() failed: %v", err)
	}

	// 验证只保留了 2 个备份文件
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	var backupCount int
	for _, f := range files {
		if strings.Contains(f.Name(), ".key.backup.") || strings.Contains(f.Name(), ".crt.backup.") {
			backupCount++
		}
	}

	if backupCount != 2 {
		t.Errorf("expected 2 backup files after cleanup, got %d", backupCount)
	}
}

// TestFindLatestBackup 测试查找最新备份功能
func TestFindLatestBackup(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-find-latest")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建原始文件
	originalFile := filepath.Join(testDir, "test.txt")
	if err := os.WriteFile(originalFile, []byte("original content"), 0644); err != nil {
		t.Fatalf("failed to create original file: %v", err)
	}

	// 执行备份
	backups, err := backup.Backup(originalFile)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 查找最新备份
	latestBackup, err := backup.FindLatestBackup(originalFile)
	if err != nil {
		t.Fatalf("FindLatestBackup() failed: %v", err)
	}

	// 验证找到的备份路径
	if latestBackup != backups[0].BackupPath {
		t.Errorf("expected backup path %s, got %s", backups[0].BackupPath, latestBackup)
	}

	// 验证备份文件存在
	if _, err := os.Stat(latestBackup); os.IsNotExist(err) {
		t.Errorf("latest backup file does not exist: %s", latestBackup)
	}
}

// TestFindLatestBackupMultipleBackups 测试有多个备份时查找最新的
func TestFindLatestBackupMultipleBackups(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-find-latest-multiple")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建原始文件
	originalFile := filepath.Join(testDir, "test.txt")
	if err := os.WriteFile(originalFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create original file: %v", err)
	}

	// 执行多次备份
	var backups []backup.BackupInfo
	for i := 0; i < 3; i++ {
		time.Sleep(10 * time.Millisecond) // 确保时间戳不同
		b, err := backup.Backup(originalFile)
		if err != nil {
			t.Fatalf("Backup() failed: %v", err)
		}
		backups = append(backups, b...)
	}

	// 查找最新备份
	latestBackup, err := backup.FindLatestBackup(originalFile)
	if err != nil {
		t.Fatalf("FindLatestBackup() failed: %v", err)
	}

	// 验证找到的是最新的备份（最后一个创建的）
	expectedBackup := backups[len(backups)-1].BackupPath
	if latestBackup != expectedBackup {
		t.Errorf("expected latest backup path %s, got %s", expectedBackup, latestBackup)
	}
}

// TestFindLatestBackupNoBackups 测试没有备份时的行为
func TestFindLatestBackupNoBackups(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-find-latest-none")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建原始文件，但不备份
	originalFile := filepath.Join(testDir, "test.txt")
	if err := os.WriteFile(originalFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create original file: %v", err)
	}

	// 查找备份，应该失败
	_, err := backup.FindLatestBackup(originalFile)
	if err == nil {
		t.Error("FindLatestBackup() should fail when no backup exists")
	}
	if !strings.Contains(err.Error(), "no backup found") {
		t.Errorf("expected 'no backup found' error, got: %v", err)
	}
}

// TestFindLatestBackupNonExistentDirectory 测试目录不存在时的查找
func TestFindLatestBackupNonExistentDirectory(t *testing.T) {
	testFile := filepath.Join(os.TempDir(), "nonexistent", "test.txt")

	// 查找备份，应该失败
	_, err := backup.FindLatestBackup(testFile)
	if err == nil {
		t.Error("FindLatestBackup() should fail when directory does not exist")
	}
	if !strings.Contains(err.Error(), "read directory") {
		t.Errorf("expected 'read directory' error, got: %v", err)
	}
}

// TestFindLatestBackupIgnoresOtherFiles 测试忽略非备份文件
func TestFindLatestBackupIgnoresOtherFiles(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-find-latest-ignore")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建原始文件
	originalFile := filepath.Join(testDir, "test.txt")
	if err := os.WriteFile(originalFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create original file: %v", err)
	}

	// 执行备份
	backups, err := backup.Backup(originalFile)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 创建一些其他文件，名称类似但不是备份
	otherFiles := []string{
		"test.txt.other",
		"test.backup.txt",
		"test.txt.old",
	}
	for _, of := range otherFiles {
		otherFile := filepath.Join(testDir, of)
		if err := os.WriteFile(otherFile, []byte("other content"), 0644); err != nil {
			t.Fatalf("failed to create other file %s: %v", otherFile, err)
		}
	}

	// 查找最新备份
	latestBackup, err := backup.FindLatestBackup(originalFile)
	if err != nil {
		t.Fatalf("FindLatestBackup() failed: %v", err)
	}

	// 验证找到的是真正的备份文件
	if latestBackup != backups[0].BackupPath {
		t.Errorf("expected backup path %s, got %s", backups[0].BackupPath, latestBackup)
	}
}

// TestIntegrationBackupRollbackCleanup 集成测试：备份 -> 修改 -> 回滚 -> 清理
func TestIntegrationBackupRollbackCleanup(t *testing.T) {
	testDir := filepath.Join(os.TempDir(), "backup-test-integration")
	defer os.RemoveAll(testDir)

	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("failed to create test directory: %v", err)
	}

	// 创建测试文件
	testFile := filepath.Join(testDir, "cert.key")
	originalContent := "-----BEGIN PRIVATE KEY-----\noriginal\n-----END PRIVATE KEY-----"
	modifiedContent := "-----BEGIN PRIVATE KEY-----\nmodified\n-----END PRIVATE KEY-----"

	if err := os.WriteFile(testFile, []byte(originalContent), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// 1. 执行备份
	backups, err := backup.Backup(testFile)
	if err != nil {
		t.Fatalf("Backup() failed: %v", err)
	}

	// 验证备份文件存在
	if _, err := os.Stat(backups[0].BackupPath); os.IsNotExist(err) {
		t.Fatalf("backup file does not exist: %s", backups[0].BackupPath)
	}

	// 2. 修改原始文件
	if err := os.WriteFile(testFile, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// 3. 验证文件已被修改
	currentContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if string(currentContent) != modifiedContent {
		t.Errorf("file content should be modified, got %s", string(currentContent))
	}

	// 4. 执行回滚
	if err := backup.Rollback(backups); err != nil {
		t.Fatalf("Rollback() failed: %v", err)
	}

	// 5. 验证文件已恢复
	restoredContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read test file after rollback: %v", err)
	}
	if string(restoredContent) != originalContent {
		t.Errorf("file content should be restored, expected %s, got %s", originalContent, string(restoredContent))
	}

	// 6. 创建更多备份以测试清理（注意：CleanupBackups 只处理 .key.backup. 和 .crt.backup.）
	for i := 0; i < 5; i++ {
		time.Sleep(1 * time.Second) // 确保时间戳不同（秒级）
		_, err := backup.Backup(testFile)
		if err != nil {
			t.Fatalf("Backup() failed: %v", err)
		}
	}

	// 7. 清理，保留最新的 2 个
	if err := backup.CleanupBackups(testDir, 2); err != nil {
		t.Fatalf("CleanupBackups() failed: %v", err)
	}

	// 8. 验证只有 2 个备份文件
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("failed to read directory: %v", err)
	}

	var backupCount int
	for _, f := range files {
		if strings.Contains(f.Name(), ".key.backup.") || strings.Contains(f.Name(), ".crt.backup.") {
			backupCount++
		}
	}

	if backupCount != 2 {
		t.Errorf("expected 2 backup files after cleanup, got %d", backupCount)
	}

	// 9. 验证可以找到最新备份
	latestBackup, err := backup.FindLatestBackup(testFile)
	if err != nil {
		t.Fatalf("FindLatestBackup() failed: %v", err)
	}

	if _, err := os.Stat(latestBackup); os.IsNotExist(err) {
		t.Errorf("latest backup file does not exist: %s", latestBackup)
	}
}
