# BioCorp Live Masking Test in PowerShell
# 1. Mint JWT from BioCorp IdP (:8086) for clinical-analyst (dr.smith@biocorp.com)
$token = (Invoke-RestMethod -Method POST -Uri "http://localhost:8086/token" -ContentType "application/json" -Body '{"sub":"dr.smith@biocorp.com","groups":["biocorp-researchers"],"aud":"masking-api"}').access_token

Write-Host "Minted BioCorp RS256 Token for dr.smith@biocorp.com (Role: clinical-analyst)`n" -ForegroundColor Green

# 2. Send payload to Masking Engine (:8000)
$payload = Get-Content "data/biocorp_payload.json" -Raw
$response = Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/v1/mask" -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body $payload

# 3. Display the Masked Patient Record
Write-Host "--- MASKED PATIENT RECORD (Zero PII, Billing Dropped, Diagnosis Generalized) ---" -ForegroundColor Cyan
$response.patients[0] | ConvertTo-Json -Depth 6
