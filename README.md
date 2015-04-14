Getting Started
===============
1. Navigate to the directory containing Create-WmiShell.ps1 and the 2 VB scripts
2. Import-Module .\Create-WmiShell.psm1
3. New-WmiShell -ComputerName <hostname or IP> -UserName <Domain\Administrator> -UploadTo <file path> -Encoding <Base64 or Hex>
4. List-WmiShells
5. Enter-WmiShell -Session <# from List-WmiShells>

When creating a new wmishell, you can start powershell with the runas.exe command and skip the -UserName parameter.

TODOs
===============
1. Test functionality against (multiple) target host file
2. Better implementation of List-WmiShells function
3. Test Close-WmiShell function
