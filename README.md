![Alt text](https://raw.githubusercontent.com/robwillisinfo/Invoke-RPCMap/main/Invoke-RPCMap-Edit.png "Invoke-RPCMap")

# Invoke-RPCMap
Invoke-RPCMap is a PowerShell tool designed to enumerate local and remote RPC services/ports through the RPC Endpoint Mapper service. This can be particularly valuable in scenarios where a connection to a remote port is established, but the service is masked by a generic process like `svchost.exe`.

The script offers the following functionalities:
- Creates a local log file.
- Connects to the RPC Endpoint Mapper service to retrieve a list of ports/UUIDs.
- Compares the returned UUIDs against a predefined list to identify the service name.
- Prints the mapping results.
- Optionally tests if the identified ports are reachable on the target host(s).
- Processes multiple hosts sequentially if provided.
- Optionally opens the log file upon completion.
- Test if the identified ports are reachable on the target host(s). (optional)

The inspiration and core logic of this script were adapted from [this Microsoft scripting blog post](https://devblogs.microsoft.com/scripting/testing-rpc-ports-with-powershell-and-yes-its-as-much-fun-as-it-sounds/).

## Examples

- **Basic usage (scan localhost):**
  ```powershell
  PS> .\Invoke-RPCMap.ps1
  ```

- **Scan multiple hosts:**
  ```ps1
  PS> .\Invoke-RPCMap.ps1 -t localhost,host1,192.168.1.50
  ```
  or
  ```ps1
  PS> .\Invoke-RPCMap.ps1 -TargetHosts localhost,host1,192.168.1.50
  ```

- **Open the log file in notepad upon completion:**
  ```ps1
  PS> .\Invoke-RPCMap.ps1 -t localhost,host1,192.168.1.50 -OpenLog
  ```
  or
  ```ps1
  PS> .\Invoke-RPCMap.ps1 -Target localhost,host1,192.168.1.50 -Log
  ```

- **Test port reachability on the target host(s):**
  ```ps1
  PS> .\Invoke-RPCMap.ps1 -t 192.168.1.50 -Reachable
  ```
  or
  ```ps1
  PS> .\Invoke-RPCMap.ps1 -Target 192.168.1.50 -r
  ```

- **Automatically retrieve the IPv4 address of the Ethernet interface and scan it for RPC services**
  ```ps1
  (Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress | .\Invoke-RPCMap.ps1
  ```

## More Information
You can view the full documentation for this module with:
```ps1
PS> Get-Help .\Invoke-RPCMap.ps1 -Full
```

## Note
This script assumes that you have the appropriate execution policy set to run scripts on your system. If you encounter execution policy restrictions, consult the PowerShell documentation or consider using `-ExecutionPolicy Bypass`. Ensure that you understand the security implications before altering the execution policy.

## Author
[Rob Willis](https://github.com/robwillisinfo) @b1t_r0t </br>
Blog: [robwillis.info](https://robwillis.info)

## Contributors
- [DJ Stomp](https://github.com/DJStompZone) @DJStompZone </br>
  Discord: [discord.stomp.zone](https://discord.stomp.zone)
