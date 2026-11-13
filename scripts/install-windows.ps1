<#
.SYNOPSIS
    Install, upgrade or remove ShadowScope for the current Windows user.

.DESCRIPTION
    Per-user install, no admin rights required:

      <InstallDir>\venv\                 isolated Python virtualenv
      <InstallDir>\bin\shadowscope.exe   launcher (this folder is added to the user PATH)
      <InstallDir>\.env                  API keys (ACL restricted to the current user)
      <InstallDir>\data\                 SQLite cache + threat-feed mirrors

    The default InstallDir is %LOCALAPPDATA%\ShadowScope, which is also where an
    installed ShadowScope looks for .env and data\ by default. For any other
    InstallDir the script sets the SHADOWSCOPE_HOME user environment variable.

    Re-running the script upgrades the install in place. The .env file and data\
    are never overwritten.

.PARAMETER Source
    The thing to pip-install. Defaults to the repository that contains this
    script, or to the GitHub repo when the script runs outside a checkout.
    Accepts any pip spec: a local path, a wheel, or git+https://...@<tag>.

.PARAMETER InstallDir
    Install root. Default: %LOCALAPPDATA%\ShadowScope

.PARAMETER Python
    Interpreter used to build the venv. Default: the newest Python 3.10+
    found through the `py` launcher, then `python` on PATH.

.PARAMETER WithMcp
    Also install the MCP server (the "mcp" extra), copy shadowscope-mcp.exe
    into <InstallDir>\bin and print the block to register it with Claude.

.PARAMETER NoPath
    Do not add <InstallDir>\bin to the user PATH.

.PARAMETER Uninstall
    Remove the venv, the launcher and the PATH entry. Keeps .env and data\.

.PARAMETER Purge
    With -Uninstall: also delete .env and data\ (cached enrichments, cases).

.PARAMETER DryRun
    Print every action without changing anything.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install-windows.ps1

.EXAMPLE
    .\scripts\install-windows.ps1 -DryRun

.EXAMPLE
    .\scripts\install-windows.ps1 -Source "git+https://github.com/Raizer1996/Shadow-Scope.git@main"

.EXAMPLE
    .\scripts\install-windows.ps1 -WithMcp

.EXAMPLE
    .\scripts\install-windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Source,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'ShadowScope'),
    [string]$Python,
    [switch]$WithMcp,
    [switch]$NoPath,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoUrl = 'git+https://github.com/Raizer1996/Shadow-Scope.git'
$MinPython = [Version]'3.10'
$DefaultInstallDir = Join-Path $env:LOCALAPPDATA 'ShadowScope'

$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$VenvDir = Join-Path $InstallDir 'venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$BinDir = Join-Path $InstallDir 'bin'
$EnvFile = Join-Path $InstallDir '.env'
$DataDir = Join-Path $InstallDir 'data'

function Write-Step([string]$Message) {
    $prefix = if ($DryRun) { '[dry-run]' } else { '[*]' }
    Write-Host "$prefix $Message" -ForegroundColor Cyan
}

function Invoke-Step([string]$Message, [scriptblock]$Action) {
    Write-Step $Message
    if (-not $DryRun) { & $Action }
}

function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed (exit $LASTEXITCODE): $Exe $($Arguments -join ' ')"
    }
}

function Find-Python {
    if ($Python) { return ,@($Python) }
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in '3.14', '3.13', '3.12', '3.11', '3.10') { $candidates += ,@('py', "-$v") }
    }
    $candidates += ,@('python')
    $candidates += ,@('python3')
    $tried = @()
    foreach ($cand in $candidates) {
        $exe = $cand[0]
        $pre = @($cand | Select-Object -Skip 1)
        $label = $cand -join ' '
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { $tried += "  $label : not on PATH"; continue }
        try {
            # No double quotes inside the probe: Windows PowerShell 5.1 strips embedded
            # double quotes when it passes arguments to a native program, so the old
            # print("%d.%d" % ...) reached Python as a syntax error and every interpreter
            # was skipped. chr(46) is "." without needing a quote.
            # The Microsoft Store "python.exe" stub prints nothing useful and exits non-zero.
            $out = & $exe @pre -c 'import sys; print(sys.version_info[0], sys.version_info[1], sep=chr(46))' 2>$null
            $code = $LASTEXITCODE
            $text = "$out".Trim()
            if ($code -ne 0 -or -not $text) { $tried += "  $label : did not run (exit $code)"; continue }
            if ([Version]$text -ge $MinPython) { return ,$cand }
            $tried += "  $label : Python $text is older than $MinPython"
        } catch { $tried += "  $label : $($_.Exception.Message)"; continue }
    }
    $detail = if ($tried) { "`nTried:`n" + ($tried -join "`n") } else { '' }
    throw "Python $MinPython+ not found. Install it from https://www.python.org/downloads/windows/ (tick 'Add python.exe to PATH') or: winget install Python.Python.3.12 - or point at one with -Python <path>.$detail"
}

function Get-UserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    try {
        # DoNotExpandEnvironmentNames keeps %USERPROFILE%-style entries intact on write-back.
        return [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally { $key.Close() }
}

function Set-UserPath([string]$Value) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $key.SetValue('Path', $Value, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally { $key.Close() }
    # Broadcast WM_SETTINGCHANGE so new Explorer/terminal windows see the change.
    [Environment]::SetEnvironmentVariable('SHADOWSCOPE_PATH_REFRESH', '1', 'User')
    [Environment]::SetEnvironmentVariable('SHADOWSCOPE_PATH_REFRESH', $null, 'User')
}

function Test-PathEntry([string]$PathValue, [string]$Dir) {
    return @($PathValue -split ';' | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') }).Count -gt 0
}

function Resolve-Source {
    if ($Source) { return $Source }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    if (Test-Path (Join-Path $repoRoot 'pyproject.toml')) { return $repoRoot }
    return $RepoUrl
}

function Get-PipSpec([string]$Spec) {
    # pip takes extras as "path[mcp]" for a folder or wheel, and as
    # "shadowscope[mcp] @ <url>" for a VCS / http source.
    if (-not $WithMcp) { return $Spec }
    if ($Spec -match '\[[A-Za-z0-9_,\- ]+\]\s*$' -or $Spec -match '^shadowscope\[') { return $Spec }
    if ($Spec -match '^(git\+|https?://)') { return "shadowscope[mcp] @ $Spec" }
    return "$Spec[mcp]"
}

# --------------------------------------------------------------------------
# Uninstall
# --------------------------------------------------------------------------
if ($Uninstall) {
    if (Test-Path $VenvDir) { Invoke-Step "Remove $VenvDir" { Remove-Item -Recurse -Force $VenvDir } }
    if (Test-Path $BinDir)  { Invoke-Step "Remove $BinDir"  { Remove-Item -Recurse -Force $BinDir } }

    $userPath = Get-UserPath
    if (Test-PathEntry $userPath $BinDir) {
        $newPath = ($userPath -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ine $BinDir.TrimEnd('\')) }) -join ';'
        Invoke-Step "Remove $BinDir from user PATH" { Set-UserPath $newPath }
    }
    if ([Environment]::GetEnvironmentVariable('SHADOWSCOPE_HOME', 'User') -ieq $InstallDir) {
        Invoke-Step 'Remove SHADOWSCOPE_HOME user variable' {
            [Environment]::SetEnvironmentVariable('SHADOWSCOPE_HOME', $null, 'User')
        }
    }

    if ($Purge) {
        if (Test-Path $EnvFile) { Invoke-Step "Delete $EnvFile (API keys)" { Remove-Item -Force $EnvFile } }
        if (Test-Path $DataDir) { Invoke-Step "Delete $DataDir (cache, cases, history)" { Remove-Item -Recurse -Force $DataDir } }
        if ((Test-Path $InstallDir) -and -not (Get-ChildItem -Force $InstallDir)) {
            Invoke-Step "Remove empty $InstallDir" { Remove-Item -Force $InstallDir }
        }
    } else {
        Write-Host "Kept $EnvFile and $DataDir. Re-run with -Uninstall -Purge to delete them." -ForegroundColor Yellow
    }
    Write-Host 'ShadowScope uninstalled.' -ForegroundColor Green
    return
}

# --------------------------------------------------------------------------
# Install / upgrade
# --------------------------------------------------------------------------
$pySpec = Find-Python
$pyExe = $pySpec[0]
$pyPre = @($pySpec | Select-Object -Skip 1)
$src = Get-PipSpec (Resolve-Source)
Write-Step "Python:      $($pySpec -join ' ')"
Write-Step "Source:      $src"
Write-Step "Install dir: $InstallDir"

if (-not (Test-Path $VenvPython)) {
    Invoke-Step "Create virtualenv $VenvDir" { Invoke-Native $pyExe ($pyPre + @('-m', 'venv', $VenvDir)) }
}

Invoke-Step 'Upgrade pip' {
    Invoke-Native $VenvPython @('-m', 'pip', 'install', '--disable-pip-version-check', '--quiet', '--upgrade', 'pip')
}
Invoke-Step "pip install $src" {
    Invoke-Native $VenvPython @('-m', 'pip', 'install', '--disable-pip-version-check', '--upgrade', $src)
}

Invoke-Step "Create $DataDir" { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null }

if (-not (Test-Path $EnvFile)) {
    Invoke-Step "Create $EnvFile from template (empty values, ACL: current user only)" {
        $template = (& $VenvPython -c 'from ioc_tool.core import paths; print(paths.env_example_file())').Trim()
        if (-not (Test-Path $template)) { throw "Bundled .env.example not found at $template" }
        # Template values are placeholders like "your_x_api_key_here"; left as-is the
        # CLI would treat every key as configured and send junk credentials upstream.
        $content = Get-Content -LiteralPath $template | ForEach-Object { $_ -replace '^([A-Z0-9_]+)=your_[A-Za-z0-9_]*_here\s*$', '$1=' }
        # ASCII: no BOM, readable by python-dotenv and every editor.
        Set-Content -LiteralPath $EnvFile -Value $content -Encoding ascii
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Invoke-Native 'icacls.exe' @($EnvFile, '/inheritance:r', '/grant:r', "*${sid}:(F)") | Out-Null
    }
} else {
    Write-Step "Keep existing $EnvFile"
}

Invoke-Step "Install launcher into $BinDir" {
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    # pip's console-script .exe embeds the venv's absolute python.exe path, so a
    # copy outside Scripts\ still runs inside the venv, without putting the venv's
    # python.exe / pip.exe on PATH.
    Copy-Item -Force (Join-Path $VenvDir 'Scripts\shadowscope.exe') (Join-Path $BinDir 'shadowscope.exe')
    if ($WithMcp) {
        $mcpExe = Join-Path $VenvDir 'Scripts\shadowscope-mcp.exe'
        if (-not (Test-Path $mcpExe)) { throw "shadowscope-mcp.exe was not installed - the 'mcp' extra is missing from $src" }
        try {
            Copy-Item -Force $mcpExe (Join-Path $BinDir 'shadowscope-mcp.exe')
        } catch {
            # Claude keeps the MCP server running, and Windows will not replace a running .exe.
            Write-Host "[!] Could not replace $BinDir\shadowscope-mcp.exe (in use - close Claude and re-run to update it)." -ForegroundColor Yellow
        }
    }
}

if ($InstallDir -ine $DefaultInstallDir) {
    Invoke-Step "Set SHADOWSCOPE_HOME=$InstallDir (user variable)" {
        [Environment]::SetEnvironmentVariable('SHADOWSCOPE_HOME', $InstallDir, 'User')
    }
    $env:SHADOWSCOPE_HOME = $InstallDir
}

if (-not $NoPath) {
    $userPath = Get-UserPath
    if (-not (Test-PathEntry $userPath $BinDir)) {
        $newPath = (@($userPath.TrimEnd(';'), $BinDir) | Where-Object { $_ }) -join ';'
        Invoke-Step "Add $BinDir to user PATH" { Set-UserPath $newPath }
    }
    if (-not (Test-PathEntry $env:Path $BinDir)) { $env:Path = "$env:Path;$BinDir" }
}

if (-not $DryRun) {
    Write-Step 'Smoke test: shadowscope --help'
    Invoke-Native (Join-Path $BinDir 'shadowscope.exe') @('--help') | Out-Null
}

Write-Host ''
Write-Host 'ShadowScope installed.' -ForegroundColor Green
Write-Host "  1. Add API keys:  notepad `"$EnvFile`""
Write-Host '  2. Open a NEW terminal, then:  shadowscope enrich 8.8.8.8'
Write-Host '     Dashboard:                  shadowscope serve   ->  http://127.0.0.1:8765/ui'
Write-Host "  Upgrade: re-run this script.  Remove: $($MyInvocation.MyCommand.Name) -Uninstall"
if ($WithMcp) {
    $mcpPath = Join-Path $BinDir 'shadowscope-mcp.exe'
    # Hand-built: ConvertTo-Json in Windows PowerShell 5.1 indents this into an unreadable sprawl.
    $jsonPath = $mcpPath.Replace('\', '\\')
    $jsonLines = @('{', '  "mcpServers": {', '    "shadowscope": {', "      `"command`": `"$jsonPath`",")
    if ($InstallDir -ine $DefaultInstallDir) {
        $jsonLines += '      "args": [],'
        $jsonLines += "      `"env`": { `"SHADOWSCOPE_HOME`": `"$($InstallDir.Replace('\', '\\'))`" }"
    } else {
        $jsonLines += '      "args": []'
    }
    $jsonLines += @('    }', '  }', '}')
    Write-Host ''
    Write-Host 'MCP server installed:' -ForegroundColor Green
    Write-Host "  $mcpPath"
    Write-Host '  With the claude CLI:'
    Write-Host "    claude mcp add --scope user shadowscope -- `"$mcpPath`""
    Write-Host '  Without it (Claude desktop app only): merge this into %USERPROFILE%\.claude.json, then restart Claude:'
    $jsonLines | ForEach-Object { Write-Host "    $_" }
    Write-Host '  It reads the same .env and cache as the CLI and the dashboard.'
}
