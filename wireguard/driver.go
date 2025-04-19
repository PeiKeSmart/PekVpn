package wireguard

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

// LoadWintunDriver 尝试加载Wintun驱动
func LoadWintunDriver() error {
	// 只在Windows平台上执行
	if runtime.GOOS != "windows" {
		return nil
	}

	// 检查wintun.dll是否已经存在于系统路径中
	// 如果存在，不需要做任何事情
	if checkWintunExists() {
		log.Println("Wintun驱动已存在于系统中")
		return nil
	}

	// 尝试从不同位置加载wintun.dll
	dllPaths := findWintunDll()
	if len(dllPaths) == 0 {
		return fmt.Errorf("找不到wintun.dll文件，请从https://www.wintun.net/下载并放置在程序目录下")
	}

	// 尝试复制DLL文件到当前目录
	err := copyWintunDll(dllPaths[0])
	if err != nil {
		return fmt.Errorf("复制wintun.dll失败: %v", err)
	}

	log.Println("已加载Wintun驱动")
	return nil
}

// checkWintunExists 检查wintun.dll是否已经存在于系统路径中
func checkWintunExists() bool {
	// 检查当前目录
	if _, err := os.Stat("wintun.dll"); err == nil {
		return true
	}

	// 检查系统目录
	systemDir := os.Getenv("SystemRoot") + "\\System32"
	if _, err := os.Stat(filepath.Join(systemDir, "wintun.dll")); err == nil {
		return true
	}

	return false
}

// findWintunDll 查找wintun.dll文件
func findWintunDll() []string {
	var paths []string

	// 检查驱动目录
	arch := runtime.GOARCH
	var archDir string
	switch arch {
	case "amd64":
		archDir = "amd64"
	case "386":
		archDir = "x86"
	case "arm64":
		archDir = "arm64"
	default:
		archDir = "amd64" // 默认使用amd64
	}

	// 检查特定架构目录
	driverPath := filepath.Join("drivers", "wintun", archDir, "wintun.dll")
	if _, err := os.Stat(driverPath); err == nil {
		paths = append(paths, driverPath)
	}

	// 检查通用驱动目录
	driverPath = filepath.Join("drivers", "wintun", "wintun.dll")
	if _, err := os.Stat(driverPath); err == nil {
		paths = append(paths, driverPath)
	}

	// 检查当前目录的上级目录
	parentDir := ".."
	driverPath = filepath.Join(parentDir, "wintun.dll")
	if _, err := os.Stat(driverPath); err == nil {
		paths = append(paths, driverPath)
	}

	return paths
}

// copyWintunDll 复制wintun.dll文件到当前目录
func copyWintunDll(srcPath string) error {
	// 读取源文件
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	// 写入目标文件
	return os.WriteFile("wintun.dll", data, 0644)
}
