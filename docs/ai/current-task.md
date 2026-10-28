# Текущий шаг

Обновлено 28 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.3a runtime MFA policy

[Контракт](../features/mfa-policy.md#применение-в-runtime--a63m3a). SQL realm_requires_mfa + role OR + enrolled protection. Browser/native issuance, MFA challenge/enrollment, session view/token exchange/refresh/introspection, local/platform sensitive guards и last-admin используют saved mode. Optional не снимает личный фактор. Administrative password-only session разрешается только после permanent password/verified email/current authority checks; primary proof передаётся в SQL.

Усиление mode атомарно повышает mfa_settings.session_revision; sessions/challenges привязаны к ней, смягчение не воскрешает старые tokens. All old sessions требуют нового входа при усилении, без массового UPDATE. Public issuance/challenge completion берут общий Access lock до user locks. View fail-closed при потерянной row. Offline JWT revocation только в существующих TTL границах. Technical MFA disabled конфликтует с required policy. MFA status requiredByPolicy и Swagger обновлены. Новых deps/ENV/workers/settings routes нет.

Luna V1/V2: task check/API, targeted lint0/race, full Linux ARM64 command SQL, enforcement/disabled-capability/storage/role/administrative/schema native/JWT/refresh, platform optional operator и operator HTTPS PASS. V2 восстановил factor FOR SHARE в platform mutation, согласовал schema limited admin enrollment и negative fixtures/error semantics. No issuance/audit/refresh consume assertions сохранены; NULL-MFA session не допускает step-up. Fixtures удалены.

Проверенный snapshot `/private/tmp/auth-mfa-policy-runtime-v2.u48j2rdu`, manifest35/metadata/Swagger hashes рядом; все source/artifacts сверены с main. Evidence в history. Пользователь разрешил коммит после PASS; факт коммита проверять Git.

## Следующий шаг

После приёмки закрыть first-run optional choice, capability/readiness matrix и protected settings HTTP. Bootstrap пока сохраняет прежний TOTP setup; MP5/MP6R/MP7/MP8 отдельно. UI — после предупреждения и отдельного согласования. Внешние OAuth/SMTP, GC/RPS не закрыты.

## Процесс

Read-only researcher Luna medium `01a183e1-ca25-7972-a67a-eadef20a0b41`, переиспользовать; необходимые первоисточники проверяет main. Executable checks только чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local/exact snapshot; checkout 6377/auth устарел. Последний cursor `19bf04ec-f4f6-4693-9c20-73f414b172e4:27`. Main не дублирует и не ждёт полный прогон.

Own LinuxARM64 PG18.6/readonly /src, socket trust/TCP127 SCRAM wrongpwdeny/TLS SAN127; Redis8.2 PGnetwork127/DB15. Mandatory SCRAM_HOST/TLS_CA/ROOT=/src/Redis127. Schema auth_schema_test DB/role/env AUTH_SCHEMA_TEST_DATABASE_URL/cwd package; platform auth_platform_test/user auth/env AUTH_PLATFORM_TEST_DATABASE_URL/cwd migrations/platform; app AUTH_OPERATOR_TEST_DATABASE_URL/REDIS_ADDR/ROOT. Pinned lint2.14.0/Go1.27.3 host module cache /Users/inforberi/go/pkg/mod и build cache /Users/inforberi/Library/Caches/go-build; offline при недоступном proxy. Только свои fixtures; main/realENV/secrets/DB/staging не трогать.

Предыдущий storage A6.3m.2a PASS, commit `7772cb2`; evidence в history. Security/resource gates открыты; новые зависимости требуют согласования.

