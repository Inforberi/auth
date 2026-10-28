# Текущий шаг

Обновлено 28 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.2a MFA policy storage

[Контракт](../features/mfa-policy.md#сохранение-политики--a63m2a). В каждой Auth БД собственная mfa_settings(version/mode), seed1/administrators из initial migration. Mode optional/administrators/required; existing role mfaRequired остаётся отдельным OR. Внутренние settings.MFA Current/Read/Update и platform operator Read/Update: local auth.settings.manage не подменяет platform.project_settings.manage. Current session/fresh password+MFA/Access locks сохранены; общая транзакция version/no-op/trusted capability/atomic audit. Audit включён в прежний bounded retention.

Standalone startup и project onboarding валидируют policy; platform validation встроена в существующий CheckRuntime SQL без отдельного запроса. Runtime не seed и не ENV fallback. Нет новых HTTP/deps/ENV/workers/cache/polling. Сохранённый mode ещё НЕ меняет login/authority; optional профиль закрыт до полного enforcement. Факторы/role requirements не удаляются.

Luna V1/V2: Go tests, targeted race, full Linux ARM64 command SQL, четыре schema-теста, platform operators/MFA settings, operator HTTPS PASS. Cyclop отказ исправлен переносом policy validation в CheckRuntime; финальный lint pinned2.14.0/Go1.27.3 exit0/0 issues. Проверенный snapshot `/private/tmp/auth-mfa-policy-storage-v2.7g0pjru_`, manifest17/metadata рядом; все source совпали с main. Временные fixtures очищены, evidence в history. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Полное применение effective MFA policy: platform/project login, sensitive actions, factor management, sessions/native/JWT, first-run. Затем защищённые HTTP settings. Optional не публиковать частично. MP5/MP6R/MP7/MP8 отдельно. UI — после предупреждения и отдельного согласования; внешние OAuth/SMTP, GC/RPS не закрыты.

## Процесс

Read-only researcher Luna medium `01a183e1-ca25-7972-a67a-eadef20a0b41`, переиспользовать. Все исполняемые проверки — чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, exact snapshot; checkout 6377/auth устарел. Последний cursor `19bf04ec-f4f6-4693-9c20-73f414b172e4:25`. Main не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).

SQL: свой Linux ARM64 PG18.6/readonly /src, socket trust/TCP127 SCRAM wrong-password denial/TLS SAN127, Redis8.2 в общем network/DB15. SCRAM_HOST/TLS_CA/ROOT=/src/Redis127 обязательны. Schema — auth_schema_test DB/role, env AUTH_SCHEMA_TEST_DATABASE_URL/cwd package. Platform — auth_platform_test DB/user auth/AUTH_PLATFORM_TEST_DATABASE_URL/cwd migrations/platform. App fixture — AUTH_OPERATOR_TEST_DATABASE_URL/REDIS_ADDR/ROOT. При недоступном Go proxy pinned2.14.0 доступен в host module cache `/Users/inforberi/go/pkg/mod`; Go build cache `/Users/inforberi/Library/Caches/go-build`. Не подменять устаревшим binary. Только свои fixtures; реальные ENV/secrets/DB/staging сохранять.

Предыдущий A6.3m.1a PASS, commit `1632857`; общие security/resource gates открыты. Зависимости без согласования не обновлять.
