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

    function Test-AccountActionsAdminAccess {
        $identity = $WebEvent.Request.User.Identity
        if (-not $identity -or -not $identity.IsAuthenticated) {
            Write-PodeJsonResponse -StatusCode 401 -Value @{ error = 'Windows authentication is required' }
            return $false
        }

        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole('AccountActionsAdmin')) {
            Write-PodeJsonResponse -StatusCode 403 -Value @{ error = 'AccountActionsAdmin membership is required' }
            return $false
        }

        return $true
    }

    function ConvertTo-ActionApiResponse {
        param([hashtable] $Action)

        return [ordered]@{
            Id = $Action.Id
            ActionType = $Action.ActionType
            Status = $Action.Status
            CreatedAt = $Action.CreatedAt
            ConfirmedAt = $Action.ConfirmedAt
            ExecutedAt = $Action.ExecutedAt
            FinishedAt = $Action.FinishedAt
            ExpiresAt = $Action.ExpiresAt
            Target = $Action.Target
            Responsible = $Action.Responsible
            Meta = $Action.Meta
            Result = $Action.Result
            Audit = $Action.Audit
        }
    }

    # GET /api/actions/{id} – action details
    Add-PodeRoute -Method Get -Path '/api/actions/:id' -ScriptBlock {
        param($id)

        if (-not (Test-AccountActionsAdminAccess)) {
            return
        }

        $action = Get-ActionById -ActionId $id
        if (-not $action) {
            Write-PodeJsonResponse -StatusCode 404 -Value @{ error = 'Action not found' }
            return
        }

        Write-PodeJsonResponse -Value (ConvertTo-ActionApiResponse -Action $action)
    }

    # GET /api/actions?status=PENDING – list actions (optional status filter)
    Add-PodeRoute -Method Get -Path '/api/actions' -ScriptBlock {
        if (-not (Test-AccountActionsAdminAccess)) {
            return
        }

        $statusFilter = $null
        if ($WebEvent.Query.ContainsKey('status') -and -not [string]::IsNullOrWhiteSpace($WebEvent.Query['status'])) {
            $statusFilter = $WebEvent.Query['status'].ToUpperInvariant()
        }

        $actions = @()
        $actionFiles = Get-ChildItem -Path $ActionsDir -Filter 'action-*.json' -File -ErrorAction SilentlyContinue
        foreach ($file in $actionFiles) {
            $actionId = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) -replace '^action-', ''
            $action = Get-ActionById -ActionId $actionId
            if (-not $action) {
                continue
            }

            if ($statusFilter -and $action.Status.ToUpperInvariant() -ne $statusFilter) {
                continue
            }

            $actions += (ConvertTo-ActionApiResponse -Action $action)
        }

        $orderedActions = $actions | Sort-Object -Property CreatedAt -Descending
        Write-PodeJsonResponse -Value @{ items = @($orderedActions); count = @($orderedActions).Count }
    }

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
