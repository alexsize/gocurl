param([string]$GoExecutable = '', [string]$LintExecutable = '')

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path $PSScriptRoot -Parent
$previousLocation = Get-Location
$previousPath = $env:PATH
$previousToolchain = $env:GOTOOLCHAIN

try {
    Set-Location -LiteralPath $projectDirectory
    $moduleText = Get-Content -LiteralPath 'go.mod' -Raw
    if ($moduleText -notmatch '(?m)^go\s+(\d+\.\d+\.\d+)\s*$') {
        throw 'Не удалось определить минимальную версию Go из go.mod.'
    }
    $minimumGo = [version]$Matches[1]
    $env:GOTOOLCHAIN = 'local'
    $candidates = @()
    if ($GoExecutable) {
        $candidates += $GoExecutable
    } else {
        $currentGo = Get-Command go -CommandType Application -ErrorAction SilentlyContinue
        if ($currentGo) { $candidates += $currentGo.Source }
        $programs = Join-Path $env:LOCALAPPDATA 'Programs'
        $candidates += Join-Path $env:ProgramFiles 'Go\bin\go.exe'
        if (Test-Path -LiteralPath (Join-Path $programs 'Go')) {
            $candidates += Get-ChildItem -LiteralPath (Join-Path $programs 'Go') -Directory |
                ForEach-Object { Join-Path $_.FullName 'bin\go.exe' }
        }
        $candidates += Get-ChildItem -LiteralPath $programs -Directory -Filter 'Go*' |
            ForEach-Object { Join-Path $_.FullName 'go\bin\go.exe' }
    }
    $selectedGo = $null
    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (!(Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $versionText = & $candidate version
        if ($LASTEXITCODE -ne 0 -or $versionText -notmatch 'go(\d+\.\d+\.\d+)') { continue }
        $version = [version]$Matches[1]
        if ($version.Major -eq $minimumGo.Major -and $version.Minor -eq $minimumGo.Minor -and $version -ge $minimumGo) {
            $selectedGo = (Resolve-Path -LiteralPath $candidate).Path
            break
        }
    }
    if (!$selectedGo) { throw "Нужен установленный Go $($minimumGo.Major).$($minimumGo.Minor).x не ниже $minimumGo. Передайте -GoExecutable." }
    $env:PATH = (Split-Path $selectedGo -Parent) + ';' + $previousPath
    if (!$LintExecutable) {
        $linter = Get-Command golangci-lint -CommandType Application -ErrorAction SilentlyContinue
        if ($linter) { $LintExecutable = $linter.Source } else {
            $goBin = Join-Path ([Environment]::GetFolderPath('UserProfile')) 'go\bin\golangci-lint.exe'
            if (Test-Path -LiteralPath $goBin) { $LintExecutable = $goBin }
        }
    }
    if (!$LintExecutable) { throw 'Не найден golangci-lint. Передайте -LintExecutable.' }
    $lintVersion = & $LintExecutable version
    if ($LASTEXITCODE -ne 0 -or $lintVersion -notmatch 'built with go(\d+\.\d+\.\d+)') {
        throw 'Не удалось проверить toolchain сборки golangci-lint.'
    }
    $lintGo = [version]$Matches[1]
    if ($lintGo.Major -lt $minimumGo.Major -or ($lintGo.Major -eq $minimumGo.Major -and $lintGo.Minor -lt $minimumGo.Minor)) {
        throw "golangci-lint собран слишком старым Go: $lintGo."
    }
    Write-Host "Go: $selectedGo"
    Write-Host $lintVersion
    & $selectedGo mod verify
    if ($LASTEXITCODE -ne 0) { throw 'go mod verify завершился с ошибкой.' }
    & npx --no-install markdownlint-cli .
    if ($LASTEXITCODE -ne 0) { throw 'Markdownlint обнаружил ошибки.' }
    & $LintExecutable run --modules-download-mode=vendor
    if ($LASTEXITCODE -ne 0) { throw 'golangci-lint обнаружил ошибки.' }
    & $selectedGo vet -mod=vendor ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet обнаружил ошибки.' }
    & $selectedGo test -race -count=1 -v '-bench=.' -mod=vendor ./...
    if ($LASTEXITCODE -ne 0) { throw 'go test завершился с ошибкой.' }
    & $selectedGo test -race -count=1 -mod=vendor -run 'Test(ReorderTransportParametersKeepsGreaseAndUnlistedOrder|TransportParametersMarshalUsesConfiguredOrder|TransportParametersMarshalPreservesExplicitZeroValues)$' github.com/quic-go/quic-go/internal/wire
    if ($LASTEXITCODE -ne 0) { throw 'Проверки vendored QUIC завершились с ошибкой.' }
    & $selectedGo build -mod=vendor ./...
    if ($LASTEXITCODE -ne 0) { throw 'go build завершился с ошибкой.' }
} finally {
    $env:PATH = $previousPath
    $env:GOTOOLCHAIN = $previousToolchain
    Set-Location -LiteralPath $previousLocation.Path
}
