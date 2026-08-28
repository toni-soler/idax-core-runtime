# IDAX Core Runtime

This repository is the public runtime boundary for applications built on IDAX
Core. It contains the open database bootstrap and integration documentation,
but it does **not** contain the proprietary `idax-core` Java source.

## Included

- the minimal `idax_core` PostgreSQL migrations required by IDAX Ledger and
  osTRIS;
- scripts for installing an authorized Core JAR in a local Maven repository;
- the public Maven coordinates and compatibility contract;
- provider-neutral database configuration examples.

## Deliberately excluded

- `idax-core` source, tests, source JARs and Javadoc JARs;
- all IDAX code generators;
- `idax-legacy` and every Dynamics AX integration artifact;
- `idax-api`, `idax-app` and the full IDAX frontend;
- credentials, signing keys and private repository settings.

## Binary dependency

Applications resolve the following separately licensed binary from the public,
anonymous Maven repository:

```text
es.idynamicsax.idax:idax-core:0.1.0
```

```xml
<repository>
  <id>idax-public</id>
  <url>https://toni-soler.github.io/idax-core-runtime/maven2</url>
</repository>
```

The Core JAR is not covered by this repository's Apache License 2.0. Downloading
or using it is subject to the [IDAX Core Runtime Binary License 1.0](IDAX_CORE_BINARY_LICENSE.md).

Maven consumers normally do not need a manual install. For offline use, install
an authorized downloaded JAR locally with:

```powershell
.\scripts\install-core.ps1 -JarPath C:\downloads\idax-core-0.1.0.jar
```

```shell
./scripts/install-core.sh /downloads/idax-core-0.1.0.jar
```

## Database bootstrap

Run the migrations in `database/migration-idax-core` with Flyway, using schema
`idax_core` and a dedicated Flyway history table. Example:

```shell
docker run --rm --network host \
  -v "$PWD/database/migration-idax-core:/flyway/sql:ro" \
  flyway/flyway:11 \
  -url=jdbc:postgresql://localhost:5432/idax \
  -user=postgres -password="$POSTGRES_PASSWORD" \
  -schemas=idax_core \
  -table=flyway_schema_history_idax_core \
  migrate
```

The selected migrations provide tenant/RLS primitives, users, audit events,
granular permissions, base roles and service-principal grants. AX legacy,
reverse-sync, messaging and AI-development schemas are intentionally absent.

## Compatibility

| Runtime | Java | Spring Boot | PostgreSQL | Ledger | osTRIS |
| --- | --- | --- | --- | --- | --- |
| 0.1.x | 21 | 3.4.x | 17 | 0.1.x | 0.1.x |

The repository is not an identity-provider application. Deployments must supply
trusted JWT validation material and, when service-to-service calls are enabled,
a compatible token issuer.
