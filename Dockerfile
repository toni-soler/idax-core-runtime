FROM flyway/flyway:11.12.0-alpine
COPY database/migration-idax-core/ /flyway/sql/

