Set-StrictMode -Version Latest

Describe 'Action Engine full flow: create -> validate -> approve -> execute' {
    BeforeAll {
        $repoRoot = Split-Path -Parent $PSScriptRoot
        $modulePath = Join-Path $repoRoot 'action_engine.ps1'

        Import-Module $modulePath -Force

        InModuleScope action_engine {
            $script:EngineRoot = $TestDrive
            $script:StateDir = Join-Path $TestDrive 'store/actions'
            $script:LogDir = Join-Path $TestDrive 'logs'
            $script:AllowedScriptsDir = Join-Path $TestDrive 'scripts'
            $script:AllowListFile = Join-Path $TestDrive 'allowlist.json'

            foreach ($dir in @($script:StateDir, $script:LogDir, $script:AllowedScriptsDir)) {
                if (-not (Test-Path -LiteralPath $dir)) {
                    New-Item -Path $dir -ItemType Directory -Force | Out-Null
                }
            }
        }

        Copy-Item -Path (Join-Path $PSScriptRoot 'fixtures/allowlist.test.json') -Destination (Join-Path $TestDrive 'allowlist.json') -Force
        Copy-Item -Path (Join-Path $PSScriptRoot 'fixtures/scripts/reset_password.ps1') -Destination (Join-Path $TestDrive 'scripts/reset_password.ps1') -Force
    }

    It 'creates task, validates token, confirms approval and executes admin script' {
        Mock Start-Process -ModuleName action_engine -MockWith {
            param(
                [string] $FilePath,
                [string[]] $ArgumentList,
                [switch] $Wait,
                [switch] $PassThru,
                [string] $RedirectStandardOutput,
                [string] $RedirectStandardError
            )

            Set-Content -Path $RedirectStandardOutput -Value 'ok' -Encoding UTF8
            Set-Content -Path $RedirectStandardError -Value '' -Encoding UTF8

            return [pscustomobject]@{ ExitCode = 0 }
        }

        $createResult = New-AccountAction `
            -ActionType 'ResetPassword' `
            -SamAccountName 'jsidorov' `
            -DisplayName 'John Sidorov' `
            -ResponsibleEmail 'admin@example.com' `
            -ResponsibleAdLogin 'CORP\admin01' `
            -Reason 'Security check' `
            -Parameters @{ SamAccountName = 'jsidorov' } `
            -TokenTtlMinutes 15

        $createResult.Status | Should -Be 'PENDING'
        $createResult.ApproveUrl | Should -Match '/a/'

        $token = ($createResult.ApproveUrl -split '/')[-1]
        $token | Should -Not -BeNullOrEmpty

        $actionByToken = Get-AccountActionByToken -RawToken $token
        $actionByToken.Id | Should -Be $createResult.Id
        $actionByToken.Responsible.Email | Should -Be 'admin@example.com'

        { Get-AccountActionByToken -RawToken 'invalid-token' } | Should -Throw

        $confirmed = Confirm-AccountAction -ActionId $createResult.Id -ConfirmedBy 'CORP\admin01'
        $confirmed.Status | Should -Be 'CONFIRMED'

        $executed = Invoke-AccountAction -ActionId $createResult.Id
        $executed.Status | Should -Be 'EXECUTED'
        $executed.Result.ExitCode | Should -Be 0

        Assert-MockCalled Start-Process -ModuleName action_engine -Times 1 -Exactly
    }
}
