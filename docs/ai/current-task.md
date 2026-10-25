# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1d deployment capabilities

[Контракт](../features/project-auth-deployment.md). Optional PLATFORM_PROJECT_AUTH_CONFIG_FILE задаёт startup UUID manifest для OTP/reauth/Google/Telegram/JWT/native/resources/hashed consumers. No file → прежний password/email source, missing UUID в explicit file → закрытый профиль. Scoped project signing/provider/SMTP secrets; issuer/callback current origin; global secret/enable fallback отсутствует. Source immutable/deep copies/realm fence; strict JSON checker access catalog reused в infra/jsonconfig.Decode. Shared OIDC clients/noRetry token Redis owner8 только selected capabilities, close послеHTTP drain.

Main formatter/diff/source review. Luna task check/targeted race/security и actual LinuxARM64 command/runtime/operator SQL PASS, без SKIP. TLS verify/SCRAM wrong-password reject/RedisDB15 preflight подтверждены. Manifest13 совпал после прогона и с main, удалённый старый checker отсутствует, deployment examples совпали. Свои containers/network/fixtures/binaries очищены. Пользователь разрешил коммит, его факт проверять Git.

Snapshot `/private/tmp/auth-project-auth-source-v1.i39k2ilp`, manifest `/private/tmp/auth-project-auth-source-v1.i39k2ilp-manifest.sha256`, metadata `/private/tmp/auth-project-auth-source-v1.i39k2ilp-snapshot.json`, basec9fd5bf. Cursor Luna001f5739-f635-4e82-85da-0f9c06b859c7:86. Полные evidence в history/логах, не перечитывать весь архив.

## Следующий шаг

Settings capabilities/полная MP5 two-project matrix и account/session/MFA management, phase-ready; rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/реальный multi-host DNS/TLS/GC/RPS не считать пройденными. UI только после предупреждения и отдельного согласования.

## Процесс

- Researcher Helmholtz01a17292-5405-7341-bae9-f5884a755889, gpt-6-luna medium, read-only/reuse; Bohr закрыт.
- Все executable checks только Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal, exact snapshot/cwd; default6377/auth stale. Main не дублирует/не ждёт весь прогон. [Процесс](development-workflow.md).
- ActualSQL: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAM wrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. Command catalog/storage +runtime auth_runtime_assembly_test +operator auth_platform_test. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 env обязательны; не macHost/randomport/trustTCP. Только own fixtures cleanup.
- Новых deps/schema/SSO/UI нет. Реальные ENV/secrets/БД/staging сохранять. Commit только по запросу. Global HTTP opt-in остаётся default-off, полный phase-ready/MP5/MP7/MP8 gate не закрыт.
