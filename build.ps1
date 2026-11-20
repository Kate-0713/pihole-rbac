# SPDX-FileCopyrightText: 2026 Kate O'Grady
# SPDX-License-Identifier: AGPL-3.0-or-later

<#
.SYNOPSIS
  Build tasks for Windows. Same task names and commands as the Makefile;
  keep the two in step.

.EXAMPLE
  .\build.ps1 test
  .\build.ps1 build
  .\build.ps1 dev-api
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'web', 'web-check', 'web-test', 'e2e', 'build', 'check-embedded', 'test', 'tree-check', 'fmt-check', 'race', 'vulncheck', 'audit', 'shellcheck', 'docker-smoke', 'release-check', 'generate', 'generate-check', 'dev-api', 'dev-web', 'docker', 'snapshot', 'clean')]
    [string]$Task = 'help'
)

$ErrorActionPreference = 'Stop'
Push-Location -Path $PSScriptRoot

$Bin = 'bin\pihole-rbac.exe'
# sqlc and oapi-codegen are pinned in tools/go.mod, not the main go.mod (see the comment there).
$Sqlc = @('tool', '-modfile=tools/go.mod', 'sqlc')
$Oapi = @('tool', '-modfile=tools/go.mod', 'oapi-codegen', '-config', 'api/oapi-codegen.yaml', 'api/openapi.yaml')
# openapi-typescript generates the frontend's API types from the same spec.
$WebGen = @('--prefix', 'web', 'run', '--silent', 'generate')
$ApiGen = @('internal\api\gen\api.gen.go', 'web\src\lib\api\schema.d.ts')
# The deploy scripts ShellCheck covers (the same list as the CI install job).
$ShellScripts = @('deploy/lxc/install.sh', 'deploy/lxc/test-install.sh', 'deploy/lxc/test-update.sh', 'deploy/docker/smoke-test.sh')
# The checks release-check runs, in this order: quick ones first, slow ones last. Skip some with
# $env:RELEASE_CHECK_SKIP = 'race docker-smoke' (space or comma separated); skipped checks are listed at the end.
$ReleaseChecks = @('tree-check', 'fmt-check', 'generate-check', 'test', 'race', 'vulncheck', 'audit', 'web-check', 'web-test', 'e2e', 'shellcheck', 'docker-smoke', 'snapshot')
$Pkg = 'github.com/Kate-0713/pihole-rbac/internal/buildinfo'
$env:CGO_ENABLED = '0'
if (-not $env:PIHOLE_RBAC_DATA_DIR) {
    $env:PIHOLE_RBAC_DATA_DIR = Join-Path $PSScriptRoot '.devdata'
}

# Run a native command and stop if it fails ($ErrorActionPreference doesn't
# apply to exit codes in Windows PowerShell 5.1).
function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

function Get-GitOrDefault {
    param([string[]]$Arguments, [string]$Default)
    try {
        $out = & git @Arguments 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return "$out".Trim() }
    } catch { }
    return $Default
}

function Install-WebDeps {
    $lock = Get-Item 'web\package-lock.json'
    $mods = Get-Item 'web\node_modules' -ErrorAction SilentlyContinue
    if (-not $mods -or $mods.LastWriteTime -lt $lock.LastWriteTime) {
        Invoke-Native 'npm' @('--prefix', 'web', 'ci')
        (Get-Item 'web\node_modules').LastWriteTime = Get-Date
    }
}

function Test-Embedded {
    $out = & ".\$Bin" version
    if ($LASTEXITCODE -ne 0) { throw "$Bin version failed" }
    $out | Write-Host
    if (-not ($out -contains 'frontend: embedded')) { throw "frontend is not embedded in $Bin" }
}

try {
    switch ($Task) {
        'help' {
            Write-Host 'Tasks: web, web-check, web-test, e2e, build, check-embedded, test, tree-check, fmt-check, race, vulncheck, audit, shellcheck, docker-smoke, release-check, generate, generate-check, dev-api, dev-web, docker, snapshot, clean'
        }
        'web' {
            Install-WebDeps
            Invoke-Native 'npm' @('--prefix', 'web', 'run', 'build')
        }
        'web-check' {
            Install-WebDeps
            Invoke-Native 'npm' @('--prefix', 'web', 'run', 'check')
        }
        'web-test' {
            Install-WebDeps
            Invoke-Native 'npm' @('--prefix', 'web', 'test')
        }
        'e2e' {
            # Builds first, as the Makefile's e2e depends on build. Playwright downloads its Chromium once; later runs
            # find it installed.
            & $PSCommandPath 'build'
            Invoke-Native 'npm' @('--prefix', 'web', 'exec', '--', 'playwright', 'install', 'chromium')
            Invoke-Native 'npm' @('--prefix', 'web', 'run', 'e2e')
        }
        'build' {
            Install-WebDeps
            Invoke-Native 'npm' @('--prefix', 'web', 'run', 'build')
            $version = Get-GitOrDefault @('describe', '--tags', '--always', '--dirty') 'dev'
            $commit = Get-GitOrDefault @('rev-parse', '--short', 'HEAD') 'unknown'
            $date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $ldflags = "-s -w -X $Pkg.Version=$version -X $Pkg.Commit=$commit -X $Pkg.Date=$date"
            Invoke-Native 'go' @('build', '-trimpath', '-ldflags', $ldflags, '-o', $Bin, './cmd/pihole-rbac')
            Test-Embedded
        }
        'check-embedded' { Test-Embedded }
        'test' {
            Invoke-Native 'go' @('vet', './...')
            Invoke-Native 'go' @('test', './...')
        }
        'tree-check' {
            $dirty = & git status --porcelain
            if ($LASTEXITCODE -ne 0) { throw 'git status failed' }
            if ($dirty) { $dirty | Write-Host; throw 'the working tree has uncommitted changes' }
        }
        'fmt-check' {
            # In batches, to stay inside Windows' command-line length limit.
            $files = @(& git ls-files '*.go')
            if ($LASTEXITCODE -ne 0) { throw 'git ls-files failed' }
            $bad = @()
            for ($i = 0; $i -lt $files.Count; $i += 100) {
                $last = [Math]::Min($i + 99, $files.Count - 1)
                $bad += @(& gofmt -l @($files[$i..$last]))
                if ($LASTEXITCODE -ne 0) { throw 'gofmt failed' }
            }
            if ($bad.Count -gt 0) { $bad | Write-Host; throw 'these files need gofmt (gofmt -w)' }
        }
        'race' {
            # The race detector needs cgo, so a C compiler, unlike the rest of the build.
            if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
                throw 'the race detector needs a C compiler (gcc on PATH, for example from MSYS2 or WinLibs); to skip it, set RELEASE_CHECK_SKIP=race'
            }
            $env:CGO_ENABLED = '1'
            try { Invoke-Native 'go' @('test', '-race', './...') } finally { $env:CGO_ENABLED = '0' }
        }
        'vulncheck' {
            # govulncheck is pinned in tools/go.mod with the other dev tools.
            Invoke-Native 'go' @('tool', '-modfile=tools/go.mod', 'govulncheck', './...')
        }
        'audit' {
            Invoke-Native 'npm' @('--prefix', 'web', 'audit', '--audit-level=high')
        }
        'shellcheck' {
            if (-not (Get-Command shellcheck -ErrorAction SilentlyContinue)) { throw 'shellcheck is not installed' }
            Invoke-Native 'shellcheck' $ShellScripts
        }
        'docker-smoke' {
            # The smoke test is a bash script (Git Bash or WSL) and needs Docker, curl and openssl.
            & $PSCommandPath 'docker'
            Invoke-Native 'bash' @('deploy/docker/smoke-test.sh', 'pihole-rbac:dev')
        }
        'release-check' {
            $skip = @($env:RELEASE_CHECK_SKIP -split '[\s,]+' | Where-Object { $_ })
            foreach ($name in $skip) {
                if ($ReleaseChecks -notcontains $name) {
                    throw "RELEASE_CHECK_SKIP names an unknown check '$name' (checks: $($ReleaseChecks -join ' '))"
                }
            }
            $n = 0
            $skipped = @()
            foreach ($check in $ReleaseChecks) {
                $n++
                Write-Host ''
                if ($skip -contains $check) {
                    Write-Host "==> [$n/$($ReleaseChecks.Count)] ${check}: SKIPPED"
                    $skipped += $check
                    continue
                }
                Write-Host "==> [$n/$($ReleaseChecks.Count)] $check"
                & $PSCommandPath $check
            }
            Write-Host ''
            if ($skipped.Count -gt 0) {
                Write-Host "release-check: passed, but these were SKIPPED: $($skipped -join ' ')" -ForegroundColor Yellow
            } else {
                Write-Host "release-check: all $($ReleaseChecks.Count) checks passed" -ForegroundColor Green
            }
            Write-Host ''
            Write-Host 'Still to do by hand:'
            Write-Host '  - CI is green on this commit (the LXC install and update, rsyslog and Prometheus jobs need a systemd host'
            Write-Host '    or downloads, so they run only there)'
            Write-Host '  - security-sensitive changes since the last release are reviewed (QUALITY.md, Release checks)'
            Write-Host '  - both deployments are tried by hand if the installer, updater or image changed'
        }
        'generate' {
            Install-WebDeps
            Invoke-Native 'go' ($Sqlc + 'generate')
            Invoke-Native 'go' $Oapi
            Invoke-Native 'npm' $WebGen
        }
        'generate-check' {
            # Fails if the generated code doesn't match the queries and the API spec. It compares with the files as
            # they are now, committed or not, and leaves them unchanged either way.
            Install-WebDeps
            Invoke-Native 'go' ($Sqlc + 'diff')
            $before = @{}
            foreach ($gen in $ApiGen) { $before[$gen] = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $gen)) }
            $stale = @()
            try {
                Invoke-Native 'go' $Oapi
                Invoke-Native 'npm' $WebGen | Out-Null
                foreach ($gen in $ApiGen) {
                    $after = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $gen))
                    if ([Convert]::ToBase64String($before[$gen]) -ne [Convert]::ToBase64String($after)) { $stale += $gen }
                }
            } finally {
                foreach ($gen in $ApiGen) { [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot $gen), $before[$gen]) }
            }
            if ($stale.Count -gt 0) {
                throw "$($stale -join ', ') out of date with api/openapi.yaml; run .\build.ps1 generate"
            }
        }
        'dev-api' {
            New-Item -ItemType Directory -Force -Path $env:PIHOLE_RBAC_DATA_DIR | Out-Null
            Invoke-Native 'go' @('run', './cmd/pihole-rbac', 'serve')
        }
        'dev-web' {
            Install-WebDeps
            Invoke-Native 'npm' @('--prefix', 'web', 'run', 'dev')
        }
        'docker' {
            $version = Get-GitOrDefault @('describe', '--tags', '--always', '--dirty') 'dev'
            $commit = Get-GitOrDefault @('rev-parse', '--short', 'HEAD') 'unknown'
            $date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            Invoke-Native 'docker' @('build', '-f', 'deploy/docker/Dockerfile', '-t', 'pihole-rbac:dev',
                '--build-arg', "VERSION=$version", '--build-arg', "COMMIT=$commit", '--build-arg', "DATE=$date", '.')
        }
        'snapshot' {
            # Unsigned: signing needs the release key. The notices step needs bash (Git Bash or WSL).
            Invoke-Native 'goreleaser' @('release', '--snapshot', '--clean', '--skip=sign')
        }
        'clean' {
            foreach ($p in @('bin', 'dist', 'web\build\app', 'web\test-results', 'web\playwright-report')) {
                if (Test-Path $p) { Remove-Item -Recurse -Force $p }
            }
        }
    }
} finally {
    Pop-Location
}
