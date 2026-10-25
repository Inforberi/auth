# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1c deployment opt-in

[Контракт/ENV](../features/project-http-deployment.md). Default-off PLATFORM_PROJECT_HTTP_ENABLED подключает browser password/MFA/email verification/recovery через existing TLS listener. Exact platform Host → operator, остальные → project boundary/current catalog, без default-DB fallback. Общие registry/Redis/hasher и отдельный bounded project admission. Source копирует operational config, очищает platform email key, формирует project URLs; secrets/SMTP/policy только scoped. OIDC/OTP/native/JWT deployment source не подключён автоматически.

HTTP dispatcher drain выполняется после server shutdown до worker join/resources. При signal cancellation workers могут завершаться раньше; порядок владельцев сохраняется. Новых pools/listeners/workers/deps/schema нет, реальные ENV/TLS/БД не трогались. UI не начинать.

Main formatter/diff/source review завершён. Luna V1 actual runtime assembly/operator SQLHTTPS без SKIP и security PASS. V1 test/lint и V2 compile ошибки исправлены; V3 task check и app/config race PASS. Manifest9 совпал после прогона и с main, ENV examples совпали. Своё SQL окружение Luna очистила. Пользователь разрешил коммит; его факт проверять Git.

Snapshot `/private/tmp/auth-project-http-deployment-v3.4_v0opea`, manifest `/private/tmp/auth-project-http-deployment-v3.4_v0opea-manifest.sha256`, metadata `/private/tmp/auth-project-http-deployment-v3.4_v0opea-snapshot.json`, base7c179fd. V1 SQL/security evidence и неудачные повторы — в history. Luna cursor001f5739-f635-4e82-85da-0f9c06b859c7:85.

## Следующий шаг

Отдельные project deployment capabilities для OIDC/OTP/native/JWT и manifests без global fallback; затем полная MP5 two-project matrix, account/session/MFA management, settings capabilities/phase-ready. Rotation/retention/fleet/MP6R/MP7/MP8 отдельно. UI только после предупреждения и отдельного согласования.

## Процесс и ограничения

- Researcher Helmholtz01a17292-5405-7341-bae9-f5884a755889, gpt-6-luna medium, read-only/reuse; Bohr закрыт.
- Все executable checks — Luna01a16eab-c777-78a0-a815-47b45ff0860d, host local, exact snapshot/cwd; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- Actual SQL: own Linux ARM64 postgres18.6, readonly source/src, admin socket trust, TCP127 SCRAM wrong-password deny/TLS SAN127, Redis8.2 shared networkDB15. Runtime assembly dedicated auth_runtime_assembly_test, operator auth_platform_test. Fixtures отказываются от чужих данных.
- Предельная нагрузка/GC/fleet/external provider/SMTP/two-project release gates открыты. Новые deps только с разрешения, реальные secrets/staging сохранять. Commit только по запросу.
