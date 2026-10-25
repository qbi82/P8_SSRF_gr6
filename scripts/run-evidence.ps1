param(
    [ValidateSet('auto','vulnerable','hardened','network')]
    [string]$Scenario='auto',
    [switch]$NoBuild
)
$ErrorActionPreference='Stop'
$labRoot=Split-Path -Parent $PSScriptRoot
$utf8=New-Object System.Text.UTF8Encoding($false)
$dockerCommand=Get-Command docker -ErrorAction SilentlyContinue
if($dockerCommand){$dockerExe=$dockerCommand.Source}
else{$dockerExe=Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin/docker.exe'}
if(-not (Test-Path -LiteralPath $dockerExe)){throw 'Docker Desktop nie jest zainstalowany.'}
$requested=$Scenario
if($Scenario -eq 'auto'){
    $health=Invoke-RestMethod -Uri 'http://127.0.0.1:8080/health' -TimeoutSec 5
    if($health.mode -eq 'vulnerable' -and $health.egress){$Scenario='network'}
    else{$Scenario=$health.mode}
}else{
    $env:VULNERABLE=if($Scenario -eq 'hardened'){'0'}else{'1'}
    $env:ENABLE_EGRESS=if($Scenario -eq 'network'){'1'}else{'0'}
}
$compose=@('compose','-f','docker-compose.yml')
if($Scenario -eq 'network'){$compose+=@('-f','hardening/docker-compose.hardened.yml')}
function Invoke-LabDocker([string[]]$Arguments,[switch]$AllowFailure){
    $info=New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName=$dockerExe
    $info.WorkingDirectory=$labRoot
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    # Arguments are controlled by this script and contain no embedded quotes.
    $info.Arguments=(($compose+$Arguments | ForEach-Object {'"'+$_+'"'}) -join ' ')
    $process=New-Object System.Diagnostics.Process
    $process.StartInfo=$info
    [void]$process.Start()
    $stdout=$process.StandardOutput.ReadToEndAsync()
    $stderr=$process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $text=$stdout.Result+$stderr.Result
    if($process.ExitCode -ne 0 -and -not $AllowFailure){throw $text}
    return [pscustomobject]@{ExitCode=$process.ExitCode;Output=$text}
}
if(-not $NoBuild){Write-Host 'Budowanie kontenerow...'; $null=Invoke-LabDocker @('--profile','test','build')}
if($requested -ne 'auto'){Write-Host "Uruchamianie: $Scenario"; $null=Invoke-LabDocker @('up','-d','--wait','--wait-timeout','90')}
$started=[DateTime]::UtcNow.ToString('o')
$runId=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,6)
$relative="evidence/$Scenario/$runId"
$out=Join-Path $labRoot $relative
if(Test-Path -LiteralPath $out){throw 'Katalog dowodowy juz istnieje.'}
[void](New-Item -ItemType Directory -Path $out)
function Save-Text([string]$Name,[string]$Text){[IO.File]::WriteAllText((Join-Path $out $Name),$Text,$utf8)}
Save-Text 'compose-resolved.yml' (Invoke-LabDocker @('config')).Output
Save-Text 'containers.txt' (Invoke-LabDocker @('ps')).Output
Write-Host 'Wykonywanie testow i zapisywanie odpowiedzi HTTP...'
$test=Invoke-LabDocker @('run','--rm','--no-deps','-e',"EVIDENCE_DIR=/$relative",'tests','python','-m','pytest','-q',"--junitxml=/$relative/pytest.xml") -AllowFailure
Save-Text 'pytest.txt' $test.Output
Write-Host $test.Output
foreach($service in @('app','dns','rebinder','fixture','internal-api','metadata-mock')){
    Save-Text ($service+'.log') (Invoke-LabDocker @('logs','--no-color','--timestamps','--since',$started,$service) -AllowFailure).Output
}
if($Scenario -eq 'network'){
    foreach($tool in @('iptables','ip6tables')){
        Save-Text ($tool+'.txt') (Invoke-LabDocker @('exec','-T','--user','0','app',$tool,'-S')).Output
    }
}
$sourceHashes=@{}
foreach($folder in @('app','lab','tests','hardening','scripts')){
    Get-ChildItem -LiteralPath (Join-Path $labRoot $folder) -Recurse -File |
        Where-Object {$_.FullName -notmatch '__pycache__'} | ForEach-Object {
        $name=$_.FullName.Substring($labRoot.Length+1).Replace('\','/')
        $sourceHashes[$name]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest=@{scenario=$Scenario;run=$runId;started_utc=$started;finished_utc=[DateTime]::UtcNow.ToString('o');pytest_exit_code=$test.ExitCode;source_sha256=$sourceHashes}
Save-Text 'manifest.json' ($manifest | ConvertTo-Json -Depth 5)
$hashes=@{}
Get-ChildItem -LiteralPath $out -File | ForEach-Object {$hashes[$_.Name]=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
Save-Text 'SHA256SUMS.json' ($hashes | ConvertTo-Json)
[IO.File]::WriteAllText((Join-Path $labRoot "evidence/latest-$Scenario.txt"),$relative+"`n",$utf8)
Write-Host "Zapisano dowody: $relative"
exit $test.ExitCode
