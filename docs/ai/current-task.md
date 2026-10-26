# Текущий шаг

Обновлено 26 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1h project email management

[Контракт](../features/project-email-management.md). Шесть project routes: admin binding approval/owner confirm и self change/confirm/report/recover на existing services/SQL. Только project-local principal/proofs, точный Origin, NoRefresh для сессионных операций. UUID manifest emailBinding/emailChange(defaultfalse), browser required; binding требует reauthentication+MFA config. Trusted URLs изorigin; no newSQL/deps/ENV/workers.

Producer готовность SMTP/delivery отделена от email_binding_confirmation/email_change_protection. Private newProjectEmail(requireSMTP=false) для completion/protection, legacy public constructor остаётсяSMTP-required; runtime.use lazyMailer не требует SMTP до отправки. SQL/Redis/purpose tokens/actor authority/current key не ослаблены. Это исправляет обнаруженный researcher delivery gate на защитных действиях. Повторный read-only review без findings.

Main formatter/source review, повторный read-only review без findings. Luna taskcheck/API/security/affected race/full Linux ARM64 TestPrepareCommandSQL PASS; HTTP profile без skips. Все14source hashes и deploymentexampleJSON совпали после cleanup и с main; собственный стенд очищен. Govulncheck0reachable, 1 advisory в required module вне imported packages/call graph; уточнить при MP6R, не обновлять зависимости без разрешения. Runtime/operator SQL отдельно не повторялись, их контракты здесь не менялись.

Snapshot `/private/tmp/auth-project-email-management-v1.i9fw9hco`, manifest sameprefix-manifest.sha256, metadata sameprefix-snapshot.json; evidence history, logs `/private/tmp/auth-project-email-management-v1-*.log`. Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:3. Пользователь разрешил коммит; факт проверять Git.

## Следующий шаг

После приёмки — identity/MFA management HTTP, оставшиеся account administrative consumers по MP5, полная two-project matrix/phase-ready. Rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/DNS/TLS/GC/RPS не считать закрытыми. UI только после предупреждения и отдельного согласования.

## Процесс

- Read-only researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2, gpt-6-luna medium/reuse. Старый Helmholtz01a17292 недоступен.
- Все executable checks только Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. Command catalog/storage. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory; не macHost/randomport/trustTCP. Толькоownfixturecleanup.
- Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
