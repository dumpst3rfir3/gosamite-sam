# GoSAMite-SAM

![](gosamite-sam.jpg)

This tool was developed for purple/red team purposes. GoSAMite-SAM attempts to programmatically save a copy of the `SAM` and `SYSTEM` registry hives using Win32 API calls (`RegSaveKeyExW`, etc.).

This ensures that you are properly testing whether security controls are capable of detecting the _behavior_ of saving the `SAM`/etc. hives, rather than just, for example, the `reg save...` commands.

**UPDATE MAY 2026:** GoSAMite-SAM was greatly simplified to just use a few simple Win32 API calls to enable `SeBackupPrivilege` and open/save the registry hives. Additionally, since testing showed that the Go version was consistently flagged by EDR, a simple C version was also created (yoCmite-SAM). As of May 2026, this version did not get flagged by at least one EDR product. Also note that both versions of the tool no longer dump SECURITY for simplicity/evasion purposes (additional, noisy steps are required).

## Usage

### GoSAMite-SAM

Just build and run. For example:

```
# Building on Linux:
GOOS=windows go build --trimpath --buildvcs=false --ldflags="-s -w" .

# Then running on Windows:
.\gosamite-sam.exe
```

**NOTE:** This tool should be run as admin.

### yoCmite-SAM

Just build and run. For example:

```
# Building on Linux:
x86_64-w64-mingw32-gcc yoCmiteSam.c -o yoCmiteSam.exe -ladvapi32 -static-libgcc

# Then running on Windows:
.\yoCmiteSam.exe
```

**NOTE:** This tool should be run as admin.