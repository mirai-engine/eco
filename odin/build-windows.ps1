# Run in an x64 Native Tools Command Prompt or Developer PowerShell for Visual Studio.
[CmdletBinding()]
param([switch]$Test)

$ErrorActionPreference = 'Stop'
function Invoke-Checked([string] $Program, [string[]] $Arguments) {
    # The exit code decides; Windows PowerShell turns redirected stderr lines into errors.
    $ErrorActionPreference = 'Continue'
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program exited with $LASTEXITCODE" }
}

function Get-Dependency([string] $Name, [string] $Url, [string] $Revision) {
    $Directory = ".eco-deps/$Name"
    if (!(Test-Path "$Directory/.git")) {
        Invoke-Checked git @('init', '-q', $Directory)
    }
    $Present = & git -C $Directory rev-parse -q --verify "$Revision`^{commit}"
    if (!$Present) {
        Invoke-Checked git @('-C', $Directory, 'fetch', '-q', '--depth', '1', $Url, $Revision)
    }
    Invoke-Checked git @('-C', $Directory, 'checkout', '-q', '--detach', $Revision)
}

Push-Location (Join-Path $PSScriptRoot '..')
try {
    if ($env:VSCMD_ARG_TGT_ARCH -and $env:VSCMD_ARG_TGT_ARCH -ne 'x64') {
        throw 'Run this build in an x64 Visual Studio developer shell.'
    }
    $null = New-Item -ItemType Directory -Force -Path '.eco-deps', '.eco-deps/windows_amd64', 'bin'
    Get-Dependency blake3 'https://github.com/mirai-engine/odin-blake3.git' 'd937acf940a85fa26b2ec207df51b9bda04f6c20'
    Get-Dependency kcp 'https://github.com/skywind3000/kcp.git' 'b1a7a2101dcbb96017681a500d6b82bbe5a88766'
    $Objects = @()
    foreach ($Source in @('odin/platform_windows_io.c', 'odin/platform_windows_fs.c',
                          'odin/platform_windows_process.c', '.eco-deps/kcp/ikcp.c')) {
        $Stem = [IO.Path]::GetFileNameWithoutExtension($Source)
        $Object = ".eco-deps/windows_amd64/$Stem.obj"
        Invoke-Checked cl.exe @('/nologo', '/O2', '/MT', '/std:c11', '/D_CRT_SECURE_NO_WARNINGS',
                                '/c', $Source, "/Fo$Object")
        $Objects += $Object
    }
    Invoke-Checked lib.exe (@('/nologo', '/out:.eco-deps/eco_platform.lib') + $Objects)
    $Compiler = if ($env:ODIN) { $env:ODIN } else { 'odin' }
    $Linker = '-extra-linker-flags:ws2_32.lib advapi32.lib bcrypt.lib iphlpapi.lib userenv.lib ole32.lib'
    $Options = @('odin', '-target:windows_amd64', "-collection:deps=$((Get-Location).Path)/.eco-deps", $Linker)
    if ($Test) {
        Invoke-Checked $Compiler (@('test') + $Options + @('-out:bin/eco-windows-tests.exe'))
    } else {
        Invoke-Checked $Compiler (@('build') + $Options + @('-o:speed', '-out:bin/eco.exe'))
    }
} finally {
    Pop-Location
}
