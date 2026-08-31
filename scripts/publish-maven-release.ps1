[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JarPath,
    [string]$Version = "0.2.0",
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$resolvedJar = (Resolve-Path -LiteralPath $JarPath).Path
$resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$expectedPom = Join-Path $resolvedRoot "release/idax-core-$Version.pom"
if (-not (Test-Path -LiteralPath $expectedPom)) {
    throw "Release POM not found: $expectedPom"
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("idax-core-maven-" + [guid]::NewGuid())
$artifactPath = Join-Path $stage "maven2/es/idynamicsax/idax/idax-core/$Version"
New-Item -ItemType Directory -Path $artifactPath | Out-Null

try {
    $jarName = "idax-core-$Version.jar"
    $pomName = "idax-core-$Version.pom"
    Copy-Item -LiteralPath $resolvedJar -Destination (Join-Path $artifactPath $jarName)
    Copy-Item -LiteralPath $expectedPom -Destination (Join-Path $artifactPath $pomName)

    foreach ($name in @($jarName, $pomName)) {
        $file = Join-Path $artifactPath $name
        $sha1 = (Get-FileHash -LiteralPath $file -Algorithm SHA1).Hash.ToLowerInvariant()
        $sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        Set-Content -LiteralPath "$file.sha1" -Value $sha1 -NoNewline
        Set-Content -LiteralPath "$file.sha256" -Value $sha256 -NoNewline
    }

    $metadataPath = Join-Path $stage "maven2/es/idynamicsax/idax/idax-core/maven-metadata.xml"
    @"
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>es.idynamicsax.idax</groupId>
  <artifactId>idax-core</artifactId>
  <versioning>
    <latest>$Version</latest>
    <release>$Version</release>
    <versions><version>$Version</version></versions>
  </versioning>
</metadata>
"@ | Set-Content -LiteralPath $metadataPath -NoNewline

    Write-Output $stage
} catch {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    throw
}
