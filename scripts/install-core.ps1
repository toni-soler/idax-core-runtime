[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$JarPath,
    [string]$Version = "0.1.0"
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

& mvn install:install-file `
    "-Dfile=$resolvedJar" `
    "-DgroupId=es.idynamicsax.idax" `
    "-DartifactId=idax-core" `
    "-Dversion=$Version" `
    "-Dpackaging=jar" `
    "-DgeneratePom=true"
if ($LASTEXITCODE -ne 0) {
    throw "Maven installation failed with exit code $LASTEXITCODE."
}
