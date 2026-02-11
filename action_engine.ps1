# ActionEngine.psm1
# Core execution engine for privileged account actions
# Atomic state handling, allowlist validation, structured logging

Set-StrictMode -Version Latest

# ==========================
# Configuration
# ==========================

$script:EngineRoot = Split-Path -Parent $PSScriptRoot
$script:StateDir   = Join-Path $script:EngineRoot "state"
$script:LogDir     = Join-Path $script:EngineRoot "logs"
$script:AllowListFile = Join-Path $script:EngineRoot "allowlist.json"

# Ensure directories exist
foreach ($dir in @($script:StateDir, $script:LogDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# ==========================
# Utility: Atomic write
# ==========================
function Write-AtomicFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Content,
        [Parameter()] [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
    )

    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $Content, $Encoding)

    if (Test-Path $Path) {
        Remove-Item $Path -Force
    }

    Move-Item -Path $tmp -Destination $Path -Force
}

# ==========================
# Utility: Logging
# ==========================
function Write-EngineLog {
    param(
        [string] $Level,
        [string] $Message,
        [hashtable] $Context
    )

    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        level     = $Level
        message   = $Message
        context   = $Context
    }

    $json = ($entry | ConvertTo-Json -Depth 8 -Compress)
    $logFile = Join-Path $script:LogDir "engine.log"

    Add-Content -Path $logFile -Value $json
}

# ==========================
# Allowlist handling
# ==========================
function Get-AllowList {
    if (-not (Test-Path $script:AllowListFile)) {
        throw "Allowlist file not found: $script:AllowListFile"
    }

    return Get-Content $script:AllowListFile -Raw | ConvertFrom-Json
}

function Test-AllowListAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionName
    )

    $allow = Get-AllowList

    $match = $allow.actions | Where-Object { $_.name -eq $ActionName }

    if (-not $match) {
        throw "Action '$ActionName' is not allowed by allowlist"
    }

    return $match
}

# ==========================
# State handling
# ==========================
function Get-ActionStatePath {
    param([string] $ActionId)

    return Join-Path $script:StateDir "$ActionId.json"
}

function Save-Action {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Action
    )

    if (-not $Action.Id) {
        throw "Action.Id is required"
    }

    $path = Get-ActionStatePath -ActionId $Action.Id
    $json = $Action | ConvertTo-Json -Depth 10
    Write-AtomicFile -Path $path -Content $json

    return $Action
}

function Get-ActionById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionId
    )

    $path = Get-ActionStatePath -ActionId $ActionId
    if (-not (Test-Path $path)) {
        return $null
    }

    $raw = Get-Content -Path $path -Raw | ConvertFrom-Json
    $json = $raw | ConvertTo-Json -Depth 10
    return ConvertFrom-Json -InputObject $json -AsHashtable
}

function Get-AllActionPaths {
    Get-ChildItem -Path $script:StateDir -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
}

# ==========================
# Core execution
# ==========================
function New-ActionId {
    return [guid]::NewGuid().ToString()
}

function New-RandomToken {
    $minTokenBytes = 32
    $bytes = New-Object byte[] $minTokenBytes
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd('=') -replace '\+', '-' -replace '/', '_'
}

function Get-TokenHash {
    param([Parameter(Mandatory)] [string] $RawToken)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($RawToken)
        $hash = $sha.ComputeHash($bytes)
        return [Convert]::ToHexString($hash).ToUpperInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-FixedTimeEqualsHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $LeftHash,
        [Parameter(Mandatory)] [string] $RightHash
    )

    $leftBytes = [System.Text.Encoding]::UTF8.GetBytes($LeftHash.ToUpperInvariant())
    $rightBytes = [System.Text.Encoding]::UTF8.GetBytes($RightHash.ToUpperInvariant())

    $diff = $leftBytes.Length -bxor $rightBytes.Length
    $maxLength = [Math]::Max($leftBytes.Length, $rightBytes.Length)

    for ($i = 0; $i -lt $maxLength; $i++) {
        $leftByte = if ($i -lt $leftBytes.Length) { $leftBytes[$i] } else { [byte]0 }
        $rightByte = if ($i -lt $rightBytes.Length) { $rightBytes[$i] } else { [byte]0 }
        $diff = $diff -bor ($leftByte -bxor $rightByte)
    }

    return ($diff -eq 0)
}

function New-AccountAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionType,
        [Parameter(Mandatory)] [string] $SamAccountName,
        [Parameter(Mandatory)] [string] $ResponsibleEmail,
        [Parameter()] [string] $ResponsibleAdLogin,
        [Parameter()] [string] $DisplayName,
        [Parameter()] [string] $Reason,
        [Parameter()] [hashtable] $Parameters,
        [Parameter()] [int] $TokenTtlMinutes = 60
    )

    Test-AllowListAction -ActionName $ActionType | Out-Null

    $actionId = New-ActionId
    $token = New-RandomToken
    $utcNow = [DateTime]::UtcNow

    $action = [ordered]@{
        Id = $actionId
        TokenHash = (Get-TokenHash -RawToken $token)
        Status = 'PENDING'
        ActionType = $ActionType
        CreatedAt = $utcNow.ToString('o')
        ConfirmedAt = $null
        ExecutedAt = $null
        FinishedAt = $null
        ExpiresAt = $utcNow.AddMinutes($TokenTtlMinutes).ToString('o')
        Target = @{
            SamAccountName = $SamAccountName
            DisplayName = $DisplayName
        }
        Responsible = @{
            Email = $ResponsibleEmail
            AdLogin = $ResponsibleAdLogin
        }
        Meta = @{
            Reason = $Reason
        }
        Parameters = $Parameters
        Result = $null
        Error = $null
    }

    Save-Action -Action $action | Out-Null
    Write-EngineLog -Level 'INFO' -Message 'Account action created' -Context @{ id = $actionId; actionType = $ActionType; status = 'PENDING' }

    $approveBaseUrl = [Environment]::GetEnvironmentVariable('ACTION_APPROVE_BASE_URL')
    if ([string]::IsNullOrWhiteSpace($approveBaseUrl)) {
        $approveBaseUrl = '/a'
    }

    $approveUrl = '{0}/{1}' -f $approveBaseUrl.TrimEnd('/'), $token

    return @{
        Id = $actionId
        ApproveUrl = $approveUrl
        ExpiresAt = $action.ExpiresAt
        Status = $action.Status
    }
}

function Get-AccountActionByToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $RawToken
    )

    $tokenHash = Get-TokenHash -RawToken $RawToken
    $utcNow = [DateTime]::UtcNow

    foreach ($path in Get-AllActionPaths) {
        $action = Get-Content -Path $path -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        if (-not $action.TokenHash) {
            continue
        }

        if (-not (Test-FixedTimeEqualsHash -LeftHash $action.TokenHash -RightHash $tokenHash)) {
            continue
        }

        if ([datetime]$action.ExpiresAt -lt $utcNow) {
            throw 'Token expired'
        }

        if ($action.Status -notin @('PENDING', 'CONFIRMED')) {
            throw "Action in invalid state '$($action.Status)' for token usage"
        }

        return $action
    }

    throw 'Action not found for token'
}

function Confirm-AccountAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionId,
        [Parameter()] [string] $ConfirmedBy
    )

    $action = Get-ActionById -ActionId $ActionId
    if (-not $action) {
        throw "Unknown action id: $ActionId"
    }

    if ([datetime]$action.ExpiresAt -le [DateTime]::UtcNow) {
        throw 'Action token expired'
    }

    if ($action.Status -ne 'PENDING') {
        throw "Cannot confirm action in status '$($action.Status)'"
    }

    $action.Status = 'CONFIRMED'
    $action.ConfirmedAt = [DateTime]::UtcNow.ToString('o')

    if ($ConfirmedBy) {
        $action.Responsible.ConfirmedBy = $ConfirmedBy
    }

    Save-Action -Action $action | Out-Null
    Write-EngineLog -Level 'INFO' -Message 'Account action confirmed' -Context @{ id = $ActionId; status = 'CONFIRMED' }

    return $action
}

function Invoke-AccountAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionId
    )

    $action = Get-ActionById -ActionId $ActionId
    if (-not $action) {
        throw "Unknown action id: $ActionId"
    }

    if ($action.Status -ne 'CONFIRMED') {
        throw "Cannot execute action in status '$($action.Status)'"
    }

    $allowed = Test-AllowListAction -ActionName $action.ActionType

    $execParams = @{}
    if ($action.Parameters -is [hashtable]) {
        $execParams = $action.Parameters
    }

    if (-not $execParams.ContainsKey('SamAccountName')) {
        $execParams['SamAccountName'] = $action.Target.SamAccountName
    }

    try {
        $scriptBlock = [scriptblock]::Create($allowed.script)
        $result = & $scriptBlock @execParams
        $action.Status = 'EXECUTED'
        $action.ExecutedAt = [DateTime]::UtcNow.ToString('o')
        $action.Result = $result
        $action.Error = $null
    }
    catch {
        $action.Status = 'FAILED'
        $action.ExecutedAt = [DateTime]::UtcNow.ToString('o')
        $action.Result = @{
            Message = $_.Exception.Message
        }
        $action.Error = $_.Exception.Message
        Write-EngineLog -Level 'ERROR' -Message 'Account action execution failed' -Context @{ id = $ActionId; error = $action.Error }
    }
    finally {
        $action.FinishedAt = [DateTime]::UtcNow.ToString('o')
        Save-Action -Action $action | Out-Null
    }

    Write-EngineLog -Level 'INFO' -Message 'Account action invocation finished' -Context @{ id = $ActionId; status = $action.Status }
    return $action
}

Export-ModuleMember -Function @(
    'New-AccountAction',
    'Get-AccountActionByToken',
    'Confirm-AccountAction',
    'Invoke-AccountAction',
    'Save-Action',
    'Get-ActionById'
)
