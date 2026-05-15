//go:build windows

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ming79486/knock-proxy/internal/config"
	"github.com/ming79486/libknock/knock"
	"golang.org/x/sys/windows"
)

func printPlatformClientDoctor(rt config.ClientRuntime) {
	if rt.KnockMethod != "tcp-syn" {
		if isWindowsAdministrator() {
			fmt.Println("[OK] running as administrator")
		} else {
			fmt.Println("[WARN] not running as administrator")
		}
		if err := knock.CheckClientSupport(rt.KnockMethod); err != nil {
			fmt.Printf("[WARN] %v\n", err)
		} else {
			fmt.Printf("[OK] client knock method available: %s\n", rt.KnockMethod)
		}
		return
	}
	if path, ok := findWindowsDLL("WinDivert.dll"); ok {
		fmt.Printf("[OK] WinDivert.dll found: %s\n", path)
	} else {
		fmt.Println("[WARN] WinDivert.dll not found")
	}
	if isWindowsAdministrator() {
		fmt.Println("[OK] running as administrator")
	} else {
		fmt.Println("[WARN] not running as administrator")
	}
	if path, ok := findWindowsDLL("Packet.dll"); ok {
		fmt.Printf("[OK] Npcap Packet.dll found: %s\n", path)
	} else {
		fmt.Println("[WARN] Npcap not found")
	}
	if err := knock.CheckClientSupport(rt.KnockMethod); err != nil {
		fmt.Printf("[WARN] %v\n", err)
	} else {
		fmt.Println("[OK] tcp-syn packet injection available")
	}
}

func isWindowsAdministrator() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func findWindowsDLL(name string) (string, bool) {
	exeDir := filepath.Dir(os.Args[0])
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	dirs := []string{
		".",
		exeDir,
		filepath.Join(exeDir, "WinDivert"),
		filepath.Join(exeDir, "windivert"),
		filepath.Join(systemRoot, "System32", "Npcap"),
		filepath.Join(systemRoot, "System32"),
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if strings.TrimSpace(dir) != "" {
			dirs = append(dirs, dir)
		}
	}
	seen := map[string]bool{}
	for _, dir := range dirs {
		if dir == "" || seen[strings.ToLower(dir)] {
			continue
		}
		seen[strings.ToLower(dir)] = true
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}
