# Текущий шаг

Обновлено 26 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1g project password management

[Контракт](../features/project-password-management.md). Project password change/reauth подключены к existing services/SQL под NoRefreshAuth/exact Origin/current key. Scoped one-lease adapters, project timeout, shared bounded hasher. Reauth обновляет password proof и cookie verifier без продления/MFA; change требует verified login email/старый пароль, atomic hash/version/revoke/audit. Project handler передаёт existing scoped user/IP/project limiter доhash; legacy constructor/interface сохранены. Новых SQL/deps/ENV/workers/UI нет.

Main formatter/Swagger generation/source review; project attempt gate переиспользует LoginLimit.AllowUser. V1 Luna taskcheck/API/security/race/runtime/operator SQL PASS. Исправлено только неправильное ожидание wrong-password login (400 вместо401); V2 targeted lint/full Linux ARM64 TestPrepareCommandSQL PASS, project HTTP profile выполнен без skips, своё окружение очищено. Все11source hashes и Swagger JSON/YAML совпали с main. Evidence — history.

Snapshot `/private/tmp/auth-project-password-management-v2.5v_ai31l`, manifest sameprefix-manifest.sha256, metadata sameprefix-snapshot.json. Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:2. Пользователь разрешил коммит; факт проверять Git.

## Следующий шаг

После приёмки блока — оставшиеся account/identity/MFA management HTTP, полная MP5 two-project matrix/phase-ready. Rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/DNS/TLS/GC/RPS не считать закрытыми. UI только после предупреждения и отдельного согласования.

## Процесс

- Read-only researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2, gpt-6-luna medium/reuse. Старый Helmholtz01a17292 недоступен; не обращаться к нему.
- Все executable checks только Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. Command catalog/storage +runtime auth_runtime_assembly_test +operator auth_platform_test. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory; не macHost/randomport/trustTCP. Толькоownfixturecleanup.
- SQL authority/final guards не дубли domain validation. Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
