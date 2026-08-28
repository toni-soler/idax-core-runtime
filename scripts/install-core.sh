#!/usr/bin/env sh
set -eu

jar_path="${1:?usage: install-core.sh PATH_TO_JAR [VERSION]}"
version="${2:-0.1.0}"

test -f "$jar_path"
mvn install:install-file \
  -Dfile="$jar_path" \
  -DgroupId=es.idynamicsax.idax \
  -DartifactId=idax-core \
  -Dversion="$version" \
  -Dpackaging=jar \
  -DgeneratePom=true
