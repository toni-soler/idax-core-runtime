#!/usr/bin/env sh
set -eu

jar_path="${1:?usage: install-core.sh PATH_TO_JAR [VERSION]}"
version="${2:-0.3.0}"

test -f "$jar_path"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
release_pom="$script_dir/../release/idax-core-$version.pom"
if [ -f "$release_pom" ]; then
  mvn install:install-file -Dfile="$jar_path" -DpomFile="$release_pom"
else
  mvn install:install-file \
    -Dfile="$jar_path" \
    -DgroupId=es.idynamicsax.idax \
    -DartifactId=idax-core \
    -Dversion="$version" \
    -Dpackaging=jar \
    -DgeneratePom=true
fi
