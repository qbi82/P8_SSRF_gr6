param(
    [ValidateSet('auto','vulnerable','hardened','network')]
    [string]$Scenario='auto',
    [switch]$NoBuild
)
& "$PSScriptRoot/scripts/run-evidence.ps1" -Scenario $Scenario -NoBuild:$NoBuild
exit $LASTEXITCODE
