# AccountActions Pode Web API Server
# Requires: Pode module
# Runs under service account with AD permissions

Import-Module Pode
Import-Module "C:\AccountActions\ActionEngine.psm1"

$BasePath   = 'C:\AccountActions'
$ActionsDir = Join-Path $BasePath 'store\actions'

Start-PodeServer {

    Add-PodeEndpoint -Address '*' -Port 8080 -Protocol Http

    # ---------- Middleware ----------

    # Simple request logging
    Add-PodeMiddleware -Name 'RequestLogger' -ScriptBlock {
        Write-Host "[$(Get-Date -Format o)] $($WebEvent.Method) $($WebEvent.Path)"
        return $true
    }

    # CSRF protection (cookie + header/field)
    Add-PodeCsrfMiddleware -CookieName 'AA-CSRF' -HeaderName 'X-CSRF-TOKEN'

    # ---------- Routes ----------

    # GET /a/{token} – confirmation page
    Add-PodeRoute -Method Get -Path '/a/:token' -ScriptBlock {
        param($token)

        try {
            $action = Get-AccountActionByToken -RawToken $token
        }
        catch {
            Write-PodeHtmlResponse -StatusCode 410 -Value '<h2>Ссылка недействительна или истекла</h2>'
            return
        }

        $csrf = New-PodeCsrfToken

        $html = @"
<html>
<head><title>Подтверждение действия</title></head>
<body>
<h2>Подтверждение административного действия</h2>
<p><b>Объект:</b> $($action.Target.DisplayName) ($($action.Target.SamAccountName))</p>
<p><b>Причина:</b> $($action.Meta.Reason)</p>
<form method='POST' action='/a/$token/execute'>
<input type='hidden' name='csrf-token' value='$csrf' />
<button type='submit'>Подтвердить</button>
</form>
</body>
</html>
"@

        Write-PodeHtmlResponse -Value $html
    }

    # POST /a/{token}/execute – confirm + invoke
    Add-PodeRoute -Method Post -Path '/a/:token/execute' -ScriptBlock {
        param($token)

        try {
            $action = Get-AccountActionByToken -RawToken $token
        }
        catch {
            Write-PodeHtmlResponse -StatusCode 410 -Value '<h2>Ссылка недействительна или уже использована</h2>'
            return
        }

        # Windows authentication identity (if enabled via IIS / reverse proxy)
        $currentUser = $WebEvent.Request.User.Identity.Name
        if ($currentUser -and $action.Responsible.AdLogin) {
            if ($currentUser -ne $action.Responsible.AdLogin) {
                Write-PodeHtmlResponse -StatusCode 403 -Value '<h2>Вы не уполномочены подтверждать это действие</h2>'
                return
            }
        }

        Confirm-AccountAction -ActionId $action.Id

        # async execution
        Start-Job -ScriptBlock {
            param($ActionId)
            Import-Module "C:\AccountActions\ActionEngine.psm1"
            Invoke-AccountAction -ActionId $ActionId
        } -ArgumentList $action.Id | Out-Null

        Write-PodeHtmlResponse -Value "<h2>Запрос принят</h2><p>ID действия: $($action.Id)</p>"
    }
}
