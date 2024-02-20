# GoSAMite-SAM

![](gosamite-sam.jpg)

This tool was developed for purple/red team purposes. GoSAMite-SAM attempts to programmatically save a copy of the `SAM` and `SYSTEM` hives (and optionally the `SECURITY` hive) using `NtSaveKey`. This ensures that you are properly testing whether security controls are capable of detecting the _behavior_ of saving the `SAM`/etc. hives, rather than just, for example, the `reg save...` commands.

## Usage

After building, just running `gosamite-sam` (either as admin, or with `SEBackupPrivilege`) will attempt to save the `SAM` and `SYSTEM` hives in `C:\Windows\Temp\`.

Running `gosamite-sam -security` (which must be run as admin) will also attempt to save the `SECURITY` hive, in addition to `SAM`/`SYSTEM`. **NOTE:** adding this option will greatly increase the likelihood of detection/blocking due to the requirements for saving the `SECURITY` hive. Unlike the permissions for `SAM`/`SYSTEM`, which only requires the `SEBackupPrivilege` privlege for saving, the ACL for the `SECURITY` hive does NOT allow READ access to local admins by default. However, local admins have 'Write DAC' access, so they can just give themselves READ access to `SECURITY` - which is what this code does if the `-security` option is passed. However, this change in permissions is often detected as suspicious behavior.
* The code automatically reverts the permissions to what they were before gosamite-sam was executed, but sometimes, if there is a detection, the tool will get blocked and quarantined before it could finish executing. Therefore, **it is important to check the permissions of `SECURITY` before and after execution to make sure they are properly restored.**

Adding the `-cleanup` option (e.g., `gosamite-sam -security -cleanup`) will make the tool automatically delete the saved copies of the hives (in `C:\Windows\Temp`, by default) after a 10 second sleep.
