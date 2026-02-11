param(
    [Parameter(Mandatory)]
    [string] $ActionJson
)

$payload = Get-Content -Path $ActionJson -Raw | ConvertFrom-Json
Write-Output ("Simulated reset for {0}" -f $payload.Action.Target.SamAccountName)
exit 0
