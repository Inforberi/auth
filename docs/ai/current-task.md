# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1k project token/native

[Контракт](../features/project-token-runtime.md). Внутренний ProjectTokens: prepared project key/JWKS, Exchange, native password/email OTP, native MFA/enrollment, refresh/logout. Existing SQL ledger/primary/policy/revoke/reuse гарантии, scoped Redis/HMAC, current runtime guards сохранены. Новых SQL/schema/deps/ENV/HTTP/readiness нет. Key loader отдаёт только redacted SigningKey; private PEM потребляется/очищается через Use, existing codec всё ещё декодирует весь bundle, нулевой Goheap не обещаем.

Service.Factory хранит immutable policy/admission8 без repo; Bind создаёт request-local Service с repository. Проектный компонент resident по exact key, не конструировать на каждый запрос. Signer admission сохраняется. NewProjectTokenRedis — один process owner no-retry pool8/таймауты1s, shared проектами, close после drain. Go-redis9.19 Options нормализует input -1 в0, сверено Context7+installed source; обычный Redis не меняется. Native MFA infrastructure enabled не делает фактор обязательным для каждого пользователя.

Main formatter/diff и targeted review Helmholtz; tests не запускал. Luna: task check/lint0 и affected race PASS; V2 security PASS (нет вызываемых кодом уязвимостей; одна в dependency недостижима по scanner); TestPostgresSchema PASS, включая token/native regressions. Полный TestPrepareCommandSQL V3 retry PASS exit0 на Linux ARM64 binary/read-only source, PG18.6 TLS/SCRAM и Redis8.2DB15 после исправления fixture profile. Перед retry подтверждены TLS/wrong-password deny/Redis PONG. Manifest20 совпал до/после и с main. Собственные containers/network/certs/binary удалены. Snapshot `/private/tmp/auth-project-token-v3.7cllhrm_`, manifest `/private/tmp/auth-project-token-v3.7cllhrm_-manifest.sha256`, metadata `/private/tmp/auth-project-token-v3.7cllhrm_-snapshot.json`; лог `/private/tmp/auth-project-token-v3-prepare-sql-retry.log`. Блок проверен; пользователь запросил коммит. Git/staging и факт коммита проверять через Git.

## Следующий шаг

После фиксации проверенного блока продолжить проектную introspection/consumer assembly, readiness/MP5 issuer/host/cookie guards; managed key rotation/overlap, remaining MFA recovery/retention/fleet fairness/MP6R/MP7/MP8 отдельно. UI не начинать до отдельного согласования; [email templates](../planning/email-templates.md) — A7 после backend.

## Процесс и ограничения

- Local read-only researcher Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, сохранять для reuse. Bohr закрыт по просьбе пользователя.
- Executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- UsePool не сохраняет pool/services/async за callback. Final guard не обещает rollback committed in-flight действий. Shared resources закрываются owner после drain.
- Component flags не подменяют SQL policy/permissions и не разрешают platform operator proof вместо project session. Crypto-only verification не проверяет текущий revoke; strict online и local expiry сохраняют разные гарантии.
- PostgreSQL+Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий OIDC697476f проверен/закоммичен; его PASS не подтверждает этот diff.
