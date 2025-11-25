# tests/smoke_tests.ps1 - run from project root in Windows PowerShell (with backend running)
$base = "http://127.0.0.1:5000/simulate_traffic"
function post($payload) {
  $json = $payload | ConvertTo-Json
  try {
    $r = Invoke-RestMethod -Uri $base -Method Post -Body $json -ContentType "application/json"
    return $r
  } catch {
    Write-Host "Request failed: $_"
    return $null
  }
}

Write-Host "1) SQLi test"
$post = @{ src_ip="10.0.0.10"; payload="SELECT * FROM users; --" }
$post | ConvertTo-Json | Write-Host
$post | post | ConvertTo-Json -Depth 5 | Write-Host

Write-Host "`n2) XSS test"
$post = @{ src_ip="10.0.0.11"; payload="<script>alert('x')</script>" }
$post | post | ConvertTo-Json -Depth 5 | Write-Host

Write-Host "`n3) Brute-force test"
$post = @{ src_ip="10.0.0.12"; payload="login attempt failed password admin" }
$post | post | ConvertTo-Json -Depth 5 | Write-Host

Write-Host "`n4) Portscan test"
$post = @{ src_ip="10.0.0.13"; payload="nmap SYN scan probe" }
$post | post | ConvertTo-Json -Depth 5 | Write-Host
