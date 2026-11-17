$id       = "K0eHAXplxpocUex3XX84mddMnMh5PsnHDXbHhPGMVt0U65FQ"
$redirect = "https://localhost/callback"      # must match the registered URI exactly
$state    = [guid]::NewGuid().ToString("N")
$authUrl  = "https://stout.egnyte.com/puboauth/token?client_id=$id&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=Egnyte.filesystem&state=$state&response_type=code"
# Ask for the secret first, so the exchange can run the moment the code is pasted (codes are short-lived).
$secure = Read-Host "Client secret (input hidden)" -AsSecureString
$secret = [System.Net.NetworkCredential]::new("", $secure).Password

Write-Host "state to expect: $state"
Start-Process $authUrl

# Sign in and click Allow. The browser then goes to https://localhost/callback?code=...&state=...
# ("can't connect" is expected). Paste the whole address, or just the code value.
$pasted = (Read-Host "Paste the address from the address bar (or just the code)").Trim()
if ($pasted -match '[?&]error=([^&#]+)') { throw "Egnyte returned an error instead of a code: $($Matches[1])" }
if ($pasted -match '[?&]state=([^&#]+)' -and $Matches[1] -ne $state) { throw "The state in that address is not from this run. Start the script again and use the new browser tab." }
if ($pasted -match '[?&]code=([^&#]+)') { $code = $Matches[1] } else { $code = $pasted }
$code = [uri]::UnescapeDataString($code)
Write-Host "code length: $($code.Length)"

try {
    $r = Invoke-RestMethod -Method Post -Uri "https://stout.egnyte.com/puboauth/token" -MaximumRedirection 0 -Body @{
        client_id     = $id
        client_secret = $secret
        redirect_uri  = $redirect
        code          = $code
        grant_type    = "authorization_code"
    }
} catch {
    Write-Host "Token request failed: HTTP $([int]$_.Exception.Response.StatusCode) $($_.ErrorDetails.Message)"
    return
}
$r.PSObject.Properties.Name -join ", "
"expires_in: $($r.expires_in)"
$r.access_token | Set-Clipboard