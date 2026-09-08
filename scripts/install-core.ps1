[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$JarPath,
    [string]$Version = "0.3.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$resolvedJar = [IO.Path]::GetFullPath($JarPath)
if (-not (Test-Path -LiteralPath $resolvedJar -PathType Leaf)) {
    throw "Core JAR not found: $resolvedJar"
}
if ([IO.Path]::GetExtension($resolvedJar) -ne ".jar") {
    throw "JarPath must reference a .jar file."
}
if ($Version -notmatch '^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$') {
    throw "Version must be Maven-compatible semantic versioning."
}

$releasePom = Join-Path (Split-Path -Parent $PSScriptRoot) "release/idax-core-$Version.pom"
$arguments = @("install:install-file", "-Dfile=$resolvedJar")
if (Test-Path -LiteralPath $releasePom) {
    $arguments += "-DpomFile=$releasePom"
} else {
    $arguments += @(
        "-DgroupId=es.idynamicsax.idax", "-DartifactId=idax-core",
        "-Dversion=$Version", "-Dpackaging=jar", "-DgeneratePom=true"
    )
}
& mvn @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Maven installation failed with exit code $LASTEXITCODE."
}
