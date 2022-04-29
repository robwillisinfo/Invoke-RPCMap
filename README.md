![Alt text](https://raw.githubusercontent.com/robwillisinfo/Invoke-RPCMap/main/Invoke-RPCMap-Edit.png "Invoke-RPCMap")

# Invoke-RPCMap
Invoke-RPCMap can be used to enumerate local and remote RPC services/ports via the RPC Endpoint Mapper service.

This information can useful during an investigation where a connection to a remote port is known, but 
the service is running under a generic process like svchost.exe.

This script will do the following:
- Create a local log file
- Connect to the RPC Endpoint Mapper service and retreive a list of ports/uuids
- Compare the returned uuids to the list in the script to identify the service name
- Print the results
- Map the next host if multiple hosts are provided
- Open the log file (optional)

The core of this script was sourced from the following script:
https://devblogs.microsoft.com/scripting/testing-rpc-ports-with-powershell-and-yes-its-as-much-fun-as-it-sounds/

# Examples
Basic usage (will scan local host):

C:\PS> PowerShell.exe -ExecutionPolicy Bypass .\Invoke-RPCMap.ps1

Add -targetHosts or -t (alias) to scan multiple hosts:

C:\PS> PowerShell.exe -ExecutionPolicy Bypass .\Invoke-RPCMap.ps1 -t localhost,host1,192.168.1.50

C:\PS> PowerShell.exe -ExecutionPolicy Bypass .\Invoke-RPCMap.ps1 -targetHosts localhost,host1,192.168.1.50

Add -openLog or -o (alias) to open the log file in notepad when the script has completed:

C:\PS> PowerShell.exe -ExecutionPolicy Bypass .\Invoke-RPCMap.ps1 -t localhost,host1,192.168.1.50 -o

C:\PS> PowerShell.exe -ExecutionPolicy Bypass .\Invoke-RPCMap.ps1 -t localhost,host1,192.168.1.50 -openLog
