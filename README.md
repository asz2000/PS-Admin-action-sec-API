# PS-Admin-action-sec-API

## Tests

Repository now includes an end-to-end Pester test that validates the privileged action flow:

- create action task;
- validate confirmation token;
- verify responsible email was stored;
- approve action;
- execute allowlisted admin script.

Run locally in PowerShell with Pester installed:

```powershell
Invoke-Pester -Path ./tests/ActionEngine.E2E.Tests.ps1
```

Test fixtures:

- allowlist: `tests/fixtures/allowlist.test.json`
- admin script: `tests/fixtures/scripts/reset_password.ps1`
