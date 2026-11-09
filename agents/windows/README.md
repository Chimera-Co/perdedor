# Windows agent, v1 (PowerShell 7), legacy

> **v2 uses the native agent** (`native/`, `perdedor-windows-x64.exe`): 432 checks, no PowerShell
> or .NET needed in the guest. This PowerShell agent is kept unchanged as a fallback and receives
> no new checks.

It runs 30 checks from PowerShell 7 and emits the same report format:

```powershell
pwsh -File .\Invoke-Perdedor.ps1 -OutputPath C:\perdedor\report.json
```

or, from the analyst host, `perdedor test windows --engine legacy`. Score the report with
`perdedor score report.json`.

Use it only where the native executable cannot run. Its checks are a subset of the native agent's,
with the same ids, so reports from either can be compared.
