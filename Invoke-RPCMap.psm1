<# 
.SYNOPSIS

Invoke-RPCMap can be used to enumerate local and remote RPC services/ports via the RPC Endpoint Mapper
service.

.DESCRIPTION

Invoke-RPCMap can be used to enumerate local and remote RPC services/ports via the RPC Endpoint Mapper
service. 

This information can useful during an investigation where a connection to a remote port is known, but 
the service is running under a generic process like svchost.exe.

This script will do the following:
- Create a local log file
- Connect to the RPC Endpoint Mapper service and retreive a list of ports/uuids
- Compare the returned uuids to the list in the script to indentify the service name
- Print the results
- Map the next host if multiple hosts are provided
- Open the log file (optional)
- Test if the identified ports are reachable on the target host(s). (optional)

Author
- Rob Willis @b1t_r0t
  Blog: robwillis.info

Contributors
- DJ Stomp (GH/DJStompZone)
  Discord: discord.stomp.zone

The core of this script was sourced from the following script:
https://devblogs.microsoft.com/scripting/testing-rpc-ports-with-powershell-and-yes-its-as-much-fun-as-it-sounds/

Note: This script assumes that you have the appropriate execution policy set to run scripts on your system.
If you encounter execution policy restrictions, consult the PowerShell documentation or consider using -ExecutionPolicy bypass. 
It's unwise to change the execution policy without understanding the implications.

.INPUTS
This script accepts input from the pipeline. 
The input should be a string that represents the target host(s).

.OUTPUTS
None. This script doesn't generate any output.

.PARAMETER TargetHosts
The target host(s) to scan. This can be a single host or a list of hosts. 
The default is localhost.

.PARAMETER OpenLog
Open the log file in notepad when the script has completed. 
By default, the log file will not be opened.

.PARAMETER Reachable
Whether to test port reachability on the target host(s). 
By default, this switch is not present.

.EXAMPLE
PS> .\Invoke-RPCMap.ps1
Basic (default) functionality

.EXAMPLE
PS> .\Invoke-RPCMap.ps1 -TargetHosts localhost,host1,192.168.1.50
Scan multiple hosts

.EXAMPLE
PS> .\Invoke-RPCMap.ps1 -t localhost,host1,192.168.1.50 -OpenLog
Open the log file in notepad when the script has completed

.EXAMPLE
PS> .\Invoke-RPCMap.ps1 -t 192.168.1.50 -Reachable
Test port reachability on the target host(s)

.LINK
GitHub repository: https://github.com/robwillisinfo/Invoke-RPCMap

#>
# Add additional command aliases and allow pipeline input - DJ
[CmdletBinding()] Param(
    [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $True)]
    [Alias("t", "Target")]
    [string[]]$TargetHosts = 'localhost',

    [Parameter(Mandatory = $false)]
    [Alias("o", "Log")]
    [switch]$OpenLog,

    [Parameter(Mandatory = $false)]
    [Alias("r", "Test")]
    [switch]$Reachable = $false
)

# Set up logging - RW
# Create a timestamp to use for a unique enough filename
$timeStamp = Get-Date -format "MMM-dd-yyyy_HH-mm"
# Create the output path
$outputPath = $pwd.path + "\" + "Invoke-RPCMap_" + $timeStamp + ".txt"
$startLog = Start-Transcript $outputPath

# Author: Ryan Ries [MSFT]
# Origianl date: 15 Feb. 2014
#Requires -Version 3
Function Invoke-RPCMap {
    [CmdletBinding(SupportsShouldProcess = $False)]
    Param([Parameter(ValueFromPipeline = $True)][String[]]$ComputerName = 'localhost')
    BEGIN {
        Set-StrictMode -Version Latest
        # Force Computer to be ComputerName - RW
        $Computer = $ComputerName
        $PInvokeCode = @'
        using System;
        using System.Collections.Generic;
        using System.Runtime.InteropServices;



        public class Rpc
        {
            // I found this crud in RpcDce.h

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcBindingFromStringBinding(string StringBinding, out IntPtr Binding);

            [DllImport("Rpcrt4.dll")]
            public static extern int RpcBindingFree(ref IntPtr Binding);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcMgmtEpEltInqBegin(IntPtr EpBinding,
                                                    int InquiryType, // 0x00000000 = RPC_C_EP_ALL_ELTS
                                                    int IfId,
                                                    int VersOption,
                                                    string ObjectUuid,
                                                    out IntPtr InquiryContext);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcMgmtEpEltInqNext(IntPtr InquiryContext,
                                                    out RPC_IF_ID IfId,
                                                    out IntPtr Binding,
                                                    out Guid ObjectUuid,
                                                    out IntPtr Annotation);

            [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
            public static extern int RpcBindingToStringBinding(IntPtr Binding, out IntPtr StringBinding);

            public struct RPC_IF_ID
            {
                public Guid Uuid;
                public ushort VersMajor;
                public ushort VersMinor;
            }


            // Returns a dictionary of <Uuid, port>
            public static Dictionary<int, string> QueryEPM(string host)
            {
                Dictionary<int, string> ports_and_uuids = new Dictionary<int, string>();
                int retCode = 0; // RPC_S_OK 
                               
                IntPtr bindingHandle = IntPtr.Zero;
                IntPtr inquiryContext = IntPtr.Zero;                
                IntPtr elementBindingHandle = IntPtr.Zero;
                RPC_IF_ID elementIfId;
                Guid elementUuid;
                IntPtr elementAnnotation;

                try
                {                    
                    retCode = RpcBindingFromStringBinding("ncacn_ip_tcp:" + host, out bindingHandle);
                    if (retCode != 0)
                        throw new Exception("RpcBindingFromStringBinding: " + retCode);

                    retCode = RpcMgmtEpEltInqBegin(bindingHandle, 0, 0, 0, string.Empty, out inquiryContext);
                    if (retCode != 0)
                        throw new Exception("RpcMgmtEpEltInqBegin: " + retCode);
                    
                    do
                    {
                        IntPtr bindString = IntPtr.Zero;
                        retCode = RpcMgmtEpEltInqNext (inquiryContext, out elementIfId, out elementBindingHandle, out elementUuid, out elementAnnotation);
                        if (retCode != 0)
                            if (retCode == 1772)
                                break;

                        retCode = RpcBindingToStringBinding(elementBindingHandle, out bindString);
                        if (retCode != 0)
                            throw new Exception("RpcBindingToStringBinding: " + retCode);
                            
                        string s = Marshal.PtrToStringAuto(bindString).Trim().ToLower();
                        if(s.StartsWith("ncacn_ip_tcp:"))
                            if (ports_and_uuids.ContainsKey(int.Parse(s.Split('[')[1].Split(']')[0])) == false) ports_and_uuids.Add(int.Parse(s.Split('[')[1].Split(']')[0]), elementIfId.Uuid.ToString());
                           
                        RpcBindingFree(ref elementBindingHandle);
                        
                    }
                    while (retCode != 1772); // RPC_X_NO_MORE_ENTRIES

                }
                catch(Exception ex)
                {
                    Console.WriteLine(ex);
                    return ports_and_uuids;
                }
                finally
                {
                    RpcBindingFree(ref bindingHandle);
                }
                
                return ports_and_uuids;
            }
        }
'@
    }
    PROCESS {
 
        [Bool]$EPMOpen = $False
        [Bool]$bolResult = $False
        $Socket = New-Object Net.Sockets.TcpClient
                
        Try {                    
            $Socket.Connect($ComputerName, 135)
            If ($Socket.Connected) {
                $EPMOpen = $True
            }
            $Socket.Close()                    
        }
        Catch {
            $Socket.Dispose()
            ""
            "+-------------------------------------------------------------------------------------------------------------+"
            ""
            Write-Host "Unable to connect to:"
            Write-Host "$ComputerName" -ForegroundColor Red
            ""
        }
                
        If ($EPMOpen -and $Reachable) {
            Add-Type $PInvokeCode
            
            # Build the UUID Mapping hash table - RW
            $uuidMapping = @{
                "51a227ae-825b-41f2-b4a9-1ac9557a1018" = "Ngc Pop Key Service"
                "367abb81-9844-35f1-ad32-98f038001003" = "Service Control Manager/Services"
                "12345678-1234-abcd-ef00-0123456789ab" = "Printer Spooler Service"
                "f6beaff7-1e19-4fbb-9f8f-b89e2018337c" = "Event Log TCPIP"
                "86d35949-83c9-4044-b424-db363231fd0c" = "Task Scheduler Service" 
                "d95afe70-a6d5-4259-822e-2c84da1ddb0d" = "WindowsShutdown Interface"
                "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5" = "DHCP Client LRPC Endpoint"
                "3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6" = "DHCPv6 Client LRPC Endpoint"
                "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7" = "RemoteAccessCheck"
                "12345678-1234-abcd-ef00-01234567cffb" = "Net Logon Service"
                "12345778-1234-abcd-ef00-0123456789ab" = "LSA Access"
                "12345778-1234-abcd-ef00-0123456789ac" = "SAM Access"
                "8fb74744-b2ff-4c00-be0d-9ef9a191fe1b" = "Ngc Pop Key Service"
                "b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86" = "KeyIso"
                "c9ac6db5-82b7-4e55-ae8a-e464ed7b4277" = "Impl Friendly Name"
                "e3514235-4b06-11d1-ab04-00c04fc2dcd2" = "MS NT Directory DRS Interface"
                "0d3c7f20-1c8d-4654-a1b3-51563b298bda" = "UserMgrCli"
                "1ff70682-0a51-30e8-076d-740be8cee98b" = "Scheduler Service"
                "201ef99a-7fa0-444c-9399-19ba84f12a1a" = "AppInfo"
                "2e6035b2-e8f1-41a7-a044-656b439c4c34" = "Proxy Manager Provider Server Endpoint"
                "552d076a-cb29-4e44-8b6a-d15e59e2c0af" = "IP Transition Configuration Endpoint"
                "58e604e8-9adb-4d2e-a464-3b0683fb1480" = "AppInfo"
                "5f54ce7d-5b79-4175-8584-cb65313a0e98" = "AppInfo"
                "b18fbab6-56f8-4702-84e0-41053293a869" = "UserMgrCli"
                "c36be077-e14b-4fe9-8abc-e856ef4f048b" = "Proxy Manager Client Server Endpoint"
                "c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1" = "Adh APIs"
                "fb9a3757-cff0-4db0-b9fc-bd6c131612fd" = "AppInfo"
                "fd7a0523-dc70-43dd-9b2e-9c5ed48225b1" = "AppInfo"
                "6b5bdd1e-528c-422c-af8c-a4079be4fe48" = "Windows Firewall Remote Service"
            }

            # Dictionary <Uuid, Port>
            $RPC_ports_and_uuids = [Rpc]::QueryEPM($Computer)
            $PortDeDup = ($RPC_ports_and_uuids.Keys) | Sort-Object -Unique
            # Write the hostname, ports, and uuids - RW
            ""
            "+-------------------------------------------------------------------------------------------------------------+"
            ""
            Write-Host "Scanning:"
            Write-Host "$ComputerName" -ForegroundColor Green
            ""
            # Initialize the new hash table to store the results of the scan results vs uuid mapping - RW
            $enrichedResults = @{}
            # Search the results for matches in the RPC port and uuid hash table
            foreach ($port in $RPC_ports_and_uuids.Keys) {
                # Grab just the uuid from the hash table via port key
                $uuid = $RPC_ports_and_uuids.Item($port)
                # Now query the uuidMapping for a match
                if ($uuidMapping.ContainsKey($uuid)) {
                    # There was a match, now create a new hash table with the updated informaton
                    # Associate the uuid with the name
                    $mappingResultName = $uuidMapping.Item($uuid)
                    # Add the results to the new enriched results hash table
                    $enrichedResults.Add($port, $uuid + " (" + "$mappingResultName" + ")")
                }
                else {
                    # There was not a match to the uuid mapping
                    # Add the port and uuid from the original RPC port and uuid hash table
                    $enrichedResults.Add($port, $uuid)
                }
            }
            Write-Output "Results:"
            # Format the results
            $enrichedResults.Keys | Select-Object @{l = 'Port'; e = { $_ } }, @{l = 'UUID (Service name)'; e = { $enrichedResults.$_ } } | out-host
            
            # Test reachability if the Reachable switch is provided - DJ
            foreach ($Port in $PortDeDup) {
                $Socket = New-Object Net.Sockets.TcpClient
                Try {
                    $Socket.Connect($Computer, $Port)
                    If ($Socket.Connected) {
                        Write-Output "$Port Reachable"
                    }
                    $Socket.Close()
                }
                Catch {
                    Write-Output "$Port Unreachable"
                    $Socket.Dispose()
                }
            }
        }

  
    }

    END {

    }
}

# Execute - RW

""
"+-------------------------------------------------------------------------------------------------------------+"
"| Invoke-RPCMap v0.1 r1"
"+-------------------------------------------------------------------------------------------------------------+"
""
Write-Output "Saving log file to: $outputPath"

ForEach ($targetHost in $TargetHosts) {
    Invoke-RPCMap -ComputerName $targetHost
}

"+-------------------------------------------------------------------------------------------------------------+"
""
$stopLog = Stop-Transcript

# If the open log switch is present, open the log file with notepad
if ($OpenLog.IsPresent) {
    notepad $outputPath
}