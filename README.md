# GoSAMite-SAM

![](gosamite-sam.jpg)

This tool was developed for purple/red team purposes. GoSAMite-SAM attempts to programmatically save a copy of the `SAM`, `SYSTEM`, and `SECURITY` registry hives (by default) using `NtSaveKey`. It can also be used to save a copy of any subset of these hives, in any order. Additionally, there is an option to attempt to programmatically copy these files from a volume shadow copy instead of the registry (a volume shadow copy will be created if one does not already exist).

This ensures that you are properly testing whether security controls are capable of detecting the _behavior_ of saving the `SAM`/etc. hives, rather than just, for example, the `reg save...` commands.

## Usage

**NOTE:** This tool should be run as admin.

After building, just running `gosamite-sam` (either as admin, or with `SEBackupPrivilege`) will attempt to save the `SECURITY`, `SYSTEM`, and `SAM` registry hives (in that order) in `C:\Windows\Temp\`. No cleanup of saved files will be performed. See the usage below for additional options:

```
Usage:
gosamite-sam [hives] [vsc] [clean]

Options:
hives (can be any subset in any order):
    SYSTEM
    SECURITY
    SAM
(Default: All 3, in the above order)
vsc: use volume shadow copy instead of registry
clean: automatically remove any saved files after a 10 sec sleep
(copied files will be saved in C:\Windows\Temp)
```

**NOTE:** when using the `vsc` option, if a new volume shadow copy is created (i.e., if there were none already on the target system), the tool will attempt to delete the volume shadow copy once it is done copying files. There is a good chance these deletion will trigger a detection or block from AV/EDR, since this resembles commonly-observed ransomware behavior. Manual cleanup of the volume shadow copy may be required.

**NOTE:** Including the `SECURITY` registry hive (which is done by default) will greatly increase the likelihood of detection/blocking due to the requirements for saving the `SECURITY` hive. Unlike the permissions for `SAM`/`SYSTEM`, which only require the `SEBackupPrivilege` privilege for saving, the ACL for the `SECURITY` hive does NOT allow READ access to local admins by default. However, local admins have 'Write DAC' access, so they can just give themselves READ access to `SECURITY` - which is what this code does if the `SECURITY` hive is included. However, this change in permissions is often detected as suspicious behavior.
* The code automatically reverts the permissions to what they were before gosamite-sam was executed, but sometimes, if there is a detection, the tool will get blocked and quarantined before it could finish executing. Therefore, **it is important to check the permissions of `SECURITY` before and after execution to make sure they are properly restored.**