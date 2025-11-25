# simulate_attack.ps1
# SAFE PowerShell version (no escaping errors)

$Endpoint = "http://localhost:5000/simulate_traffic"
$SampleFilePath = "/mnt/data/19808629-9c7a-4102-b25c-3a5f839f5332.png"

$payloads = @(
    @{
        src_ip = "10.0.0.10"
        payload = "SELECT * FROM users; --"
        description = "SQLi classic"
    },
    @{
        src_ip = "10.0.0.11"
        payload = "' OR '1'='1' --"
        description = "SQLi boolean"
    },
    @{
        src_ip = "10.0.0.12"
        payload = "<script>alert(1)</script>"
        description = "XSS"
    },
    @{
        src_ip = "10.0.0.13"
        payload = "admin' -- pw=123456"
        description = "Auth brute-like"
    },
    @{
        src_ip = "10.0.0.14"
        payload = "GET /admin.php HTTP/1.1`nHost: victim"
        description = "HTTP probe"
    },
    @{
        src_ip = "10.0.0.15"
        payload = "nmap -sS -p 1-1024 10.0.0.1"
        description = "Port scan"
    },
    @{
        src_ip = "10.0.0.16"
        payload = "`$(sleep 10); `$(cat /etc/passwd)"
        description = "Command injection"
    },
    @{
        src_ip = "10.0.0.17"
        payload = "FUZZ_{1..200}"
        description = "Fuzzing"
    }
)

Write-Host "`nSending $($payloads.Count) attack events to $Endpoint`n"

foreach ($p in $payloads) {

    $bodyHash = @{
        src_ip = $p.src_ip
        payload = $p.payload
        description = $p.description
        sample_file_url = $SampleFilePath
    }

    $jsonBody = $bodyHash | ConvertTo-Json -Depth 4

    try {
        $response = Invoke-RestMethod `
            -Uri $Endpoint `
            -Method POST `
            -Body $jsonBody `
            -ContentType "application/json"

        Write-Host "[$($p.src_ip)] $($p.description) => OK"
        Write-Host ($response | ConvertTo-Json -Depth 6)
    }
    catch {
        Write-Host "[$($p.src_ip)] ERROR => $($_.Exception.Message)" -ForegroundColor Red
    }

    Start-Sleep -Milliseconds 300
}

Write-Host "`nNext: watch backend detections:"
Write-Host "docker logs -f adaptive_honeypot-backend-1 --tail 50"
