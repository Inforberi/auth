# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1j project Google/Telegram OIDC

[Контракт](../features/project-oidc-runtime.md). Добавлены внутренние ProjectOIDC Start/Callback/StartLink/Unlink и shared MFA. Сохранённые provider credentials/revision читаются на операцию; scope Redis/cipher, SQL policy/identity/session/revision guards и current runtime до/после сохраняются. Два process HTTP/JWKS owners ProjectOIDCClients заимствуются immutable views с project callback/credentials. Закрывает owner процесс после drain; lifecycle/public HTTP/readiness не подключены. Нет новых SQL/deps/ENV/SSO, loss-all-factors recovery закрыт.

Main formatter golangci-lint/v2.14.0 fmt exit0 (existing gofumpt warning), targeted review Helmholtz без конкретных ошибок; tests не запускал. Callback host — только trusted assembly config, public origin/host/cookie matrix остаётся MP5. Добавлены unit disabled/config/MFA issuer, shared immutable credential/redirect view race и actual project SQL/Redis start/binding/cross-method/cross-scope/revision/replay/policy fixture без внешней сети. Полный реальный provider login/link/MFA NOT RUN.

Luna проверяет immutable snapshot `/private/tmp/auth-project-oidc-v1.16gzx6jf`, manifest `/private/tmp/auth-project-oidc-v1.16gzx6jf-manifest.sha256`, metadata `/private/tmp/auth-project-oidc-v1.16gzx6jf-snapshot.json`. Luna: task check exit0/lint0, affected race exit0 с loopback access, local TLS OIDC/full command SQL exit0 без SKIP. Manifest10 совпал до/после и с main; RedisDB15 пуста, собственные containers удалены. Блок проверен, пользователь запросил коммит; факт коммита проверять через Git.

## Следующий шаг

После фиксации проверенного блока продолжить project token/JWT assembly и readiness/MP5 guards; remaining MFA recovery/retention/fleet fairness/MP6R/MP7/MP8 отдельно. UI не начинать до отдельного согласования; [email templates](../planning/email-templates.md) — A7 после backend.

## Процесс и ограничения

- Local read-only researcher Helmholtz (gpt-6-luna medium), ID01a17292-5405-7341-bae9-f5884a755889, сохранять для reuse. Bohr закрыт по просьбе пользователя.
- Executable checks — отдельная «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; default6377/auth stale. Main не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).
- UsePool не сохраняет pool/services/async за callback. Final guard не обещает rollback committed in-flight действий. Shared resources закрываются owner после drain.
- Component flags не подменяют SQL policy/permissions и не разрешают platform operator proof вместо project session. Target scope/host routing/issuer/cookie matrix — MP5.
- PostgreSQL+Redis; новые deps только с разрешения. Реальные ENV/БД/secrets/staging сохранять. Commit только по запросу. Предыдущий OTP d8a1dd3 проверен/закоммичен; его PASS не подтверждает этот diff.
