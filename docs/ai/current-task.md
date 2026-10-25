# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1f project session management

[Контракт](../features/project-session-management.md). Семь browser routes: me/list/logout/logout-all/revoke/activity/rotate на существующих session handlers/services/SQL. Scoped repo внутри одного UsePool, deadline5s/current key до/после; Auth/NoRefreshAuth/LogoutAuth, exact Origin. Browser deployment сохраняет управление после отключения login methods; SessionValidation fallback проверяется при HTTP assembly. Нет новых SQL/deps/ENV/workers/UI.

Main formatter/source review; Helmholtz read-only review без findings. V1 Luna API/security/race/runtime/operator SQL PASS; исправлены lint QF1003 и старые RoutePlan assertions. V2 task check/router race/full Linux ARM64 TestPrepareCommandSQL PASS; новый session HTTP fixture выполнен без skips, своё окружение очищено. Все14source hashes совпали после проверки и с main. Evidence в history.

Snapshot `/private/tmp/auth-project-session-management-v2.1qyf4nfr`, manifest sameprefix-manifest.sha256, metadata sameprefix-snapshot.json. Luna cursor001f5739-f635-4e82-85da-0f9c06b859c7:90. Пользователь разрешил коммит; факт проверять Git.

## Следующий шаг

После приёмки блока — account/identity/MFA management HTTP и полная MP5 two-project matrix/phase-ready. Rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/DNS/TLS/GC/RPS не считать закрытыми. UI только после предупреждения и отдельного согласования.

## Процесс

- Researcher Helmholtz01a17292-5405-7341-bae9-f5884a755889, gpt-6-luna medium read-only/reuse; Bohr закрыт.
- Все executable checks только Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. Command catalog/storage +runtime auth_runtime_assembly_test +operator auth_platform_test. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory; не macHost/randomport/trustTCP. Толькоownfixturecleanup.
- Metadata final SQL guards не дубли domain validation. Real ENV/secrets/БД/staging сохранять. Commit только по запросу. UI и full MP5/MP7/MP8 gates открыты.
