# Database Security

## What
Protecting the database tier itself: relational engines (PostgreSQL, MySQL/MariaDB, SQL Server, Oracle), document and key-value stores (MongoDB, Redis, Elasticsearch/OpenSearch) and their managed cloud equivalents (RDS/Aurora, Azure SQL, Cloud SQL, Atlas). It covers network exposure, authentication, privilege design, encryption, auditing and backups. Injection in the application layer is covered in `kb/03-application/owasp-top10.md`; this file is about the server, its accounts and its data.

## Why it matters
- The database is usually where the regulated and valuable data lives, so it is the end goal of most intrusions and the source of most breach notifications.
- Internet-exposed databases with no or weak authentication are a recurring cause of large data leaks and of "wipe and ransom" campaigns against MongoDB, Elasticsearch and Redis.
- An application account with superuser or DDL rights turns a single SQL injection into full data theft, file write or OS command execution.
- Database dumps and snapshots are copies of production data that often escape the controls on the live system.

## Attacks
*For authorized testing only. Each item lists the matching defense.*

| Attack | How it works | Defense |
|---|---|---|
| Exposed service | 5432 (PostgreSQL), 3306 (MySQL), 1433 (SQL Server), 27017 (MongoDB), 6379 (Redis), 9200 (Elasticsearch) reachable from the internet; scanned within hours | Private subnets / private endpoints only, security groups allow app tier only, no public IP |
| Missing or default auth | Redis without `requirepass`/ACLs, MongoDB without `security.authorization`, default `sa`/`root`/`postgres` passwords | Enable auth everywhere, unique strong credentials, disable or rename default admin logins |
| Credential theft | Connection strings in code, CI logs, `.env` files, container images | Secrets manager or dynamic credentials (`kb/05-identity-crypto/secrets-management.md`), cloud IAM database auth |
| Over-privileged app account | App connects as owner/superuser; SQLi can `DROP`, read every schema, or reach the OS | Separate migration (DDL) and runtime (DML) roles; least privilege per table/schema |
| Database-to-OS escape | PostgreSQL `COPY ... TO/FROM PROGRAM` (superuser or `pg_execute_server_program`), SQL Server `xp_cmdshell`, MySQL `SELECT ... INTO OUTFILE`, Redis `CONFIG SET dir` + `SAVE` to write files, Redis `MODULE LOAD` | No superuser for apps; keep `xp_cmdshell` disabled; set `secure_file_priv`; Redis ACLs deny `@admin`/`@dangerous` commands |
| Cleartext transport | Credentials and rows sniffed or altered on the network; clients that do not verify the server certificate are open to MITM | Server TLS required, clients use `sslmode=verify-full` (PostgreSQL) or `ssl-mode=VERIFY_IDENTITY` (MySQL) |
| Tenant data leak | Multi-tenant tables filtered only by an application `WHERE tenant_id = ?` that one query forgets | Row-level security as a second layer, tested per tenant |
| Backup / snapshot leak | Dumps in public buckets, snapshots shared publicly or cross-account, unencrypted exports | Encrypted backups in a separate account, block public sharing, restricted restore rights |
| Malicious server reading client files | MySQL `LOAD DATA LOCAL INFILE` lets a rogue server request files from the client | Disable `local_infile` on clients and servers unless required |
| Ransom / wipe | Attacker with write access deletes data and leaves a ransom note | Auth + network isolation, immutable backups, deletion protection, tested restore (`kb/08-defensive/ransomware-resilience.md`) |

## Defenses

### Network
1. No public endpoints. Place databases in private subnets and reach them through private endpoints (PrivateLink, Private Link, Private Service Connect).
2. Allow inbound only from the application tier's security group, never `0.0.0.0/0`. Administrators connect through SSM/IAP/Bastion or a PAM proxy, not a direct path.
3. Bind self-hosted engines to internal interfaces (`listen_addresses` in PostgreSQL, `bind-address` in MySQL, `net.bindIp` in MongoDB, `bind` in Redis). Keep Redis `protected-mode yes`.

### Authentication
- PostgreSQL: `password_encryption = scram-sha-256` and `scram-sha-256` (not `md5` or `trust`) in `pg_hba.conf`; use `hostssl` lines so non-TLS connections are refused.
  ```
  # pg_hba.conf: TLS only, SCRAM, app subnet only
  hostssl  appdb  app_rw  10.0.1.0/24  scram-sha-256
  ```
- MySQL 8: `caching_sha2_password` (the default); remove anonymous users and test databases.
- MongoDB: `security.authorization: enabled`, SCRAM-SHA-256 or x.509, one user per application.
- Redis 6+: named ACL users with their own passwords and restricted command categories, and the `default` user disabled or password-protected, for example `ACL SETUSER app on >EXAMPLE_PASSWORD ~app:* +@read +@write -@admin -@dangerous`.
- Managed cloud: prefer IAM / Entra ID database authentication (RDS IAM auth, Microsoft Entra authentication for Azure SQL, Cloud SQL IAM database authentication) so no static password exists. Otherwise use dynamic, short-lived credentials from a secrets manager.

### Authorization (least privilege)
- Separate roles: **owner** (owns objects, used only by migrations), **app_rw** (DML on the tables it needs), **app_ro** (reporting), **admin** (humans, through PAM, MFA, session logging).
- PostgreSQL: on versions before 15, `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` (15+ already does this). Grant per schema, not per database.
  ```sql
  CREATE ROLE app_rw LOGIN;
  GRANT USAGE ON SCHEMA app TO app_rw;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_rw;
  ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;
  ```
- Never give applications `SUPERUSER`, `BYPASSRLS`, `pg_execute_server_program`, `sysadmin`, MySQL `FILE`/`SUPER`, or MongoDB `root`.
- **Row-level security** for multi-tenant data. Table owners bypass RLS unless it is forced, and superusers and `BYPASSRLS` roles always bypass it:
  ```sql
  ALTER TABLE app.invoices ENABLE ROW LEVEL SECURITY;
  ALTER TABLE app.invoices FORCE ROW LEVEL SECURITY;
  CREATE POLICY tenant_isolation ON app.invoices
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
  ```
  The app sets `app.tenant_id` per transaction (`SET LOCAL`) from the authenticated session, never from user input.
- Keep dangerous features off: SQL Server `xp_cmdshell` (disabled by default), MySQL `local_infile=0` and `secure_file_priv` set to a dedicated directory or `NULL`, untrusted PostgreSQL extensions not installed.

### Encryption
- **In transit**: require TLS on the server (PostgreSQL `ssl = on` plus `hostssl`; MySQL `require_secure_transport = ON`; MongoDB `net.tls.mode: requireTLS`; RDS PostgreSQL parameter `rds.force_ssl = 1`). Clients verify the certificate and hostname. See `kb/05-identity-crypto/pki-and-tls.md`.
- **At rest**: storage or transparent data encryption (TDE, cloud KMS) protects lost disks, snapshots and backups. It does not protect against anyone who can run SQL.
- **Field-level**: for the most sensitive columns (national IDs, card data), encrypt in the application or use client-side features such as SQL Server Always Encrypted or MongoDB Client-Side Field Level Encryption / Queryable Encryption, with keys in a KMS the database cannot read. Hash passwords with Argon2id or bcrypt, never reversible encryption (`kb/05-identity-crypto/cryptography.md`).

### Auditing and monitoring
- Enable connection and DDL/privilege logging: PostgreSQL `log_connections`, `log_disconnections` and the `pgaudit` extension; MySQL Enterprise Audit or the MariaDB audit plugin; SQL Server Audit; MongoDB auditing (Enterprise/Atlas); cloud database activity streams.
- Ship logs to the SIEM. Alert on: logins from unexpected hosts, failed-login bursts, new roles or grants, `ALTER ... BYPASSRLS`, enabling `xp_cmdshell`, large result sets or exports by unusual principals, backup/snapshot sharing changes.
- Do not log bind values or query results that contain secrets or personal data (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).

### Backups, data lifecycle and patching
- Encrypted, automated backups copied to a separate account with immutability and deletion protection; restore tested on a schedule with the RPO/RTO measured.
- Non-production uses masked or synthetic data, not production copies.
- Retention and deletion follow the data classification and privacy schedule (`kb/09-governance/grc-compliance-privacy.md`).
- Track engine versions against vendor end-of-life dates and patch through the vulnerability management process (`kb/09-governance/vulnerability-management.md`).

## How to verify
- Exposure: from outside the network, `nmap -Pn -p 1433,3306,5432,6379,9200,27017 <public-ip-range>` (authorized ranges only) finds nothing open; CSPM shows no publicly accessible database instance or public snapshot.
- PostgreSQL:
  ```sql
  SELECT rolname FROM pg_roles WHERE rolsuper OR rolbypassrls;          -- only admin/break-glass roles
  SELECT usename, ssl, version FROM pg_stat_ssl JOIN pg_stat_activity USING (pid);  -- every session ssl = t
  SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'invoices';
  SHOW password_encryption;                                            -- scram-sha-256
  ```
  Client check: `psql "host=db.internal dbname=appdb user=app_rw sslmode=verify-full sslrootcert=ca.pem"` succeeds and the same connection with `sslmode=disable` is rejected.
- MySQL: `SHOW VARIABLES WHERE Variable_name IN ('require_secure_transport','local_infile','secure_file_priv');` and `SELECT user, host, plugin FROM mysql.user;` (no empty users, no `%` host for admin accounts).
- Redis: `redis-cli -h <host> PING` without credentials returns `NOAUTH`; `ACL LIST` shows no user with `+@all` except admin.
- MongoDB: connecting without credentials and running `db.adminCommand({listDatabases: 1})` fails with an authorization error.
- RLS test: as `app_rw` with `app.tenant_id` set to tenant A, a `SELECT` returns zero rows of tenant B.
- Benchmark scans: CIS Benchmarks for PostgreSQL, MySQL, SQL Server, MongoDB; `prowler` checks for RDS/Azure SQL/Cloud SQL public access, encryption and backups.

## References
- OWASP Database Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html
- PostgreSQL docs, Client Authentication: https://www.postgresql.org/docs/current/client-authentication.html · Row Security Policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html · Secure TCP/IP Connections with SSL: https://www.postgresql.org/docs/current/ssl-tcp.html
- MySQL 8.4 Reference Manual, Security Guidelines: https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html
- MongoDB Security Checklist: https://www.mongodb.com/docs/manual/administration/security-checklist/
- Redis security: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
- CIS Benchmarks (database engines): https://www.cisecurity.org/cis-benchmarks
- NIST SP 800-53 Rev. 5 (AC-6 least privilege, AU-2 event logging, SC-8 transmission confidentiality, SC-28 protection of information at rest)
- MITRE ATT&CK T1190 (Exploit Public-Facing Application), T1213 (Data from Information Repositories), T1485 (Data Destruction)
- See also `kb/04-cloud-infra/cloud-security.md`, `kb/05-identity-crypto/secrets-management.md`, `kb/03-application/owasp-top10.md`, `kb/08-defensive/ransomware-resilience.md`, `kb/09-governance/data-security-and-dlp.md`
