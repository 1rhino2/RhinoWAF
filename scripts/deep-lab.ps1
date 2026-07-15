# Deep live lab suite against RhinoWAF on :8080 -> backend :9000
$ErrorActionPreference = 'Continue'
$base = 'http://127.0.0.1:8080'
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
$acceptJson = 'application/json'
$acceptHtml = 'text/html,application/xhtml+xml'
$results = [System.Collections.Generic.List[object]]::new()

function Classify([string]$body) {
  if ($body -match 'Malicious Input') { return 'BLOCK_malicious' }
  if ($body -match 'Access Denied') { return 'BLOCK_denied' }
  if ($body -match 'Rate Limit') { return 'BLOCK_ratelimit' }
  if ($body -match 'CSRF') { return 'BLOCK_csrf' }
  if ($body -match 'Security Verification') { return 'fingerprint' }
  if ($body -match 'Backend unavailable|Unable to connect') { return 'backend_down' }
  if ($body -match '"ok"\s*:\s*true') { return 'BACKEND_json' }
  if ($body -match 'about page from real backend') { return 'BACKEND_about' }
  if ($body -match '400 Bad Request') { return 'http_400' }
  if ($body -match 'Method not allowed|Only POST') { return 'method' }
  return 'other'
}

function Hit($name, $group, $expect, $url, $extra = @()) {
  $tmp = New-TemporaryFile
  $args = @('-s','-o',$tmp.FullName,'-w','%{http_code}') + $extra + @($url)
  $code = & curl.exe @args 2>$null
  if (-not $code) { $code = '000' }
  $body = Get-Content -Raw $tmp.FullName -ErrorAction SilentlyContinue
  if ($null -eq $body) { $body = '' }
  $kind = Classify $body
  $pass = $false
  switch -Regex ($expect) {
    '^200_backend' { $pass = ([int]$code -eq 200 -and $kind -like 'BACKEND*') }
    '^405' { $pass = ([int]$code -eq 405) }
    '^403' { $pass = ([int]$code -eq 403) }
    '^4\d\d' { $pass = ([int]$code -ge 400 -and [int]$code -lt 500) }
    '^block' { $pass = ($kind -like 'BLOCK*' -or ([int]$code -ge 400 -and [int]$code -lt 500)) }
    '^fingerprint_or_backend' { $pass = ($kind -eq 'fingerprint' -or $kind -like 'BACKEND*') -and [int]$code -eq 200 }
    '^200' { $pass = ([int]$code -eq 200) }
    default { $pass = ($code -eq $expect) }
  }
  $row = [pscustomobject]@{
    Group = $group; Name = $name; Expect = $expect; Code = $code; Kind = $kind; Pass = $pass
  }
  $results.Add($row) | Out-Null
  $mark = if ($pass) { 'OK' } else { 'FAIL' }
  Write-Host ("[{0}] {1,-12} {2,-40} {3} {4}" -f $mark, $group, $name, $code, $kind)
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

Write-Host '======== CLEAN / FALSE POSITIVES ========'
Hit 'root json' 'clean' '200_backend' "$base/" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'about json' 'clean' '200_backend' "$base/about" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'page query' 'clean' '200_backend' "$base/?page=1&sort=asc" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'search hello' 'clean' '200_backend' "$base/?q=hello%20world" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'email-ish' 'clean' '200_backend' "$base/?email=user%40example.com" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'json body get' 'clean' '200_backend' "$base/?data=%7B%22name%22%3A%22test%22%7D" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'firefox ua' 'clean' '200_backend' "$base/about" @('-H','User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0','-H',"Accept: $acceptJson")
Hit 'safari ua' 'clean' '200_backend' "$base/about" @('-H','User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15','-H',"Accept: $acceptJson")
Hit 'edge ua' 'clean' '200_backend' "$base/about" @('-H','User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0','-H',"Accept: $acceptJson")
Hit 'html fingerprint' 'clean' 'fingerprint_or_backend' "$base/" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'path with dash' 'clean' '200_backend' "$base/about" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'unicode name' 'clean' '200_backend' "$base/?name=Jos%C3%A9" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")

Write-Host '======== SQLI ========'
$sqli = @(
  '1%20union%20select%20null',
  "1'%20OR%20'1'%3D'1",
  '1;%20drop%20table%20users',
  '1%20AND%201%3D1%20--',
  'admin%27--',
  '1%20UNION%20ALL%20SELECT%20NULL%2CNULL',
  '%27%20or%201%3D1%23',
  '1%20waitfor%20delay%20%270%3A0%3A5%27',
  '1%27%3B%20EXEC%20xp_cmdshell%28%27dir%27%29--'
)
$i=0; foreach ($q in $sqli) { $i++; Hit "sqli_$i" 'sqli' '403' "$base/?id=$q" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml") }

Write-Host '======== XSS ========'
$xss = @(
  '%3Cscript%3Ealert(1)%3C/script%3E',
  '%3Cimg%20src=x%20onerror=alert(1)%3E',
  'javascript%3Aalert(1)',
  '%3Csvg%20onload=alert(1)%3E',
  '%22%3E%3Cscript%3Ealert(1)%3C/script%3E',
  '%3Ciframe%20src=javascript%3Aalert(1)%3E'
)
$i=0; foreach ($q in $xss) { $i++; Hit "xss_$i" 'xss' '403' "$base/?q=$q" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml") }

Write-Host '======== TRAVERSAL / CMD / SSTI / SSRF ========'
Hit 'trav_etc' 'path' '403' "$base/?file=../../../../etc/passwd" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'trav_enc' 'path' '403' "$base/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'cmd_semi' 'cmd' '403' "$base/?cmd=%3Bcat%20/etc/passwd" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'cmd_pipe' 'cmd' '403' "$base/?x=%7C%20whoami" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'ssti' 'ssti' '403' "$base/?name=%7B%7B7*7%7D%7D" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'ssrf_meta' 'ssrf' '403' "$base/?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'ssrf_local' 'ssrf' '403' "$base/?url=http%3A%2F%2F127.0.0.1%3A9000%2F" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")

Write-Host '======== HEADERS / UA ========'
Hit 'empty ua' 'ua' '403' "$base/about" @('-H','User-Agent:','-H',"Accept: $acceptJson")
Hit 'sqlmap ua' 'ua' '403' "$base/about" @('-A','sqlmap/1.7.2#stable','-H',"Accept: $acceptJson")
Hit 'nikto ua' 'ua' 'block' "$base/about" @('-A','Mozilla/5.00 (Nikto/2.1.6)','-H',"Accept: $acceptJson")
Hit 'ua xss' 'ua' '403' "$base/" @('-A','<script>alert(1)</script>','-H',"Accept: $acceptJson")
Hit 'ua shellshock' 'ua' '403' "$base/" @('-A','() { :; }; /bin/bash -c id','-H',"Accept: $acceptJson")
Hit 'xff localhost' 'hdr' '403' "$base/" @('-H',"User-Agent: $ua",'-H','X-Forwarded-For: 127.0.0.1','-H',"Accept: $acceptJson")
Hit 'x-original-url' 'hdr' '403' "$base/" @('-H',"User-Agent: $ua",'-H','X-Original-URL: /admin','-H',"Accept: $acceptJson")

Write-Host '======== CSRF ========'
Hit 'post no token' 'csrf' 'block' "$base/" @('-X','POST','-H',"User-Agent: $ua",'-H','Content-Type: application/x-www-form-urlencoded','-H',"Accept: $acceptJson",'-d','a=1')
Hit 'post json no token' 'csrf' 'block' "$base/" @('-X','POST','-H',"User-Agent: $ua",'-H','Content-Type: application/json','-H',"Accept: $acceptJson",'-d','{"a":1}')

Write-Host '======== ADMIN LOCALHOST ========'
Hit 'health' 'admin' '200' "$base/health" @()
Hit 'metrics' 'admin' '200' "$base/metrics" @()
Hit 'reload get' 'admin' '405' "$base/reload" @('-X','GET')

Write-Host '======== PATH EDGE ========'
Hit 'long query' 'edge' '403' ("$base/?q=" + ('a'*9000)) @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'null byte q' 'edge' '403' "$base/?q=test%00.php" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'double ext' 'edge' '403' "$base/?f=shell.php.jpg" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'ognl' 'edge' '403' "$base/?x=%24%7B%23context%7D" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'nosql' 'edge' '403' "$base/?user%5B%24gt%5D=" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptHtml")
Hit 'dotenv' 'edge' '403' "$base/.env" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'gitconfig' 'edge' '403' "$base/.git/config" @('-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'trace method' 'edge' '403' "$base/" @('-X','TRACE','-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'head ok' 'edge' '200' "$base/" @('-I','-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")
Hit 'options ok' 'edge' '200' "$base/" @('-X','OPTIONS','-H',"User-Agent: $ua",'-H',"Accept: $acceptJson")

Write-Host '======== CONCURRENT CLEAN ========'
$jobs = 1..20 | ForEach-Object {
  Start-Job -ScriptBlock {
    param($b,$u)
    curl.exe -s -o NUL -w '%{http_code}' -H "User-Agent: $u" -H 'Accept: application/json' "$b/about"
  } -ArgumentList $base,$ua
}
$codes = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job -Force
$okN = ($codes | Where-Object { $_ -eq '200' }).Count
$failN = ($codes | Where-Object { $_ -ne '200' }).Count
Write-Host "concurrent_clean 200=$okN other=$failN ($($codes -join ','))"
$results.Add([pscustomobject]@{Group='load'; Name='concurrent_20'; Expect='mostly_200'; Code="$okN/20"; Kind='mix'; Pass=($okN -ge 18)}) | Out-Null

Write-Host '======== RATE LIMIT PRESSURE ========'
$rl = @()
1..80 | ForEach-Object {
  $rl += curl.exe -s -o NUL -w '%{http_code}' -H "User-Agent: $ua" -H "Accept: $acceptJson" "$base/?n=$_"
}
$rl403 = ($rl | Where-Object { $_ -eq '429' -or $_ -eq '403' }).Count
$rl200 = ($rl | Where-Object { $_ -eq '200' }).Count
Write-Host "rate_burst 200=$rl200 blocked=$rl403"
$results.Add([pscustomobject]@{Group='load'; Name='rate_burst_80'; Expect='some_block_or_all_ok'; Code="$rl200/$rl403"; Kind='mix'; Pass=$true}) | Out-Null

Write-Host '======== SUMMARY ========'
$pass = ($results | Where-Object { $_.Pass }).Count
$fail = ($results | Where-Object { -not $_.Pass }).Count
Write-Host "PASS=$pass FAIL=$fail TOTAL=$($results.Count)"
$results | Where-Object { -not $_.Pass } | Format-Table -AutoSize | Out-String | Write-Host
$out = Join-Path $PSScriptRoot 'deep-lab-results.json'
# when run via -File, PSScriptRoot is scripts; when dot-sourced may differ
if (-not $PSScriptRoot) { $out = '.\scripts\deep-lab-results.json' } else { $out = Join-Path $PSScriptRoot 'deep-lab-results.json' }
$results | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $out
Write-Host "wrote $out"
exit $(if ($fail -gt 0) { 1 } else { 0 })
