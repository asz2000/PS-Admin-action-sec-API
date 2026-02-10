# ActionEngine.psm1
# Core execution engine for privileged actions
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

    $json = ($entry | ConvertTo-Json -Depth 6)
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

function Save-ActionState {
    param(
        [string] $ActionId,
        [hashtable] $State
    )

    $path = Get-ActionStatePath $ActionId
    $json = $State | ConvertTo-Json -Depth 6
    Write-AtomicFile -Path $path -Content $json
}

function Get-ActionState {
    param([string] $ActionId)

    $path = Get-ActionStatePath $ActionId
    if (-not (Test-Path $path)) {
        return $null
    }

    return Get-Content $path -Raw | ConvertFrom-Json
}

# ==========================
# Core execution
# ==========================
function New-ActionId {
    return [guid]::NewGuid().ToString()
}

function Start-Action {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionName,
        [Parameter()] [hashtable] $Parameters
    )

    $allowed = Test-AllowListAction -ActionName $ActionName

    $actionId = New-ActionId

    $state = @{
        id         = $actionId
        name       = $ActionName
        status     = "pending"
        started_at = (Get-Date).ToString("o")
        finished_at = $null
        parameters = $Parameters
        result     = $null
        error      = $null
    }

    Save-ActionState -ActionId $actionId -State $state
    Write-EngineLog -Level "INFO" -Message "Action started" -Context @{ id = $actionId; name = $ActionName }

    try {
        $state.status = "running"
        Save-ActionState -ActionId $actionId -State $state

        $scriptBlock = [scriptblock]::Create($allowed.script)
        $result = & $scriptBlock @Parameters

        $state.status = "success"
        $state.result = $result
    }
    catch {
        $state.status = "failed"
        $state.error  = $_.Exception.Message
        Write-EngineLog -Level "ERROR" -Message "Action failed" -Context @{ id = $actionId; error = $state.error }
    }
    finally {
        $state.finished_at = (Get-Date).ToString("o")
        Save-ActionState -ActionId $actionId -State $state
    }

    return $actionId
}

function Get-ActionStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ActionId
    )

    $state = Get-ActionState -ActionId $ActionId
    if (-not $state) {
        throw "Unknown action id: $ActionId"
    }

    return $state
}

Export-ModuleMember -Function *
