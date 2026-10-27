# Текущий шаг

Обновлено 27 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Текущий блок — MP5.1k project user directory

[Контракт](../features/user-directory.md#независимые-проекты--mp51k). Реализованы project-local GET `/api/v1/admin/users` и `/{id}` через existing handlers/services/SQL. Default-off `userDirectory` в UUID manifest требует browser; программный флаг UserDirectoryEnabled. Actor из project session, `accounts.users.read` проверяется существующим directoryActor; platform principal не используется. NoRefresh/exact Origin, bounded3s one-lease current binding guards до/после чтения, данные при post-guard error не возвращаются.

Нет новых schema/deps/ENV/workers/cache. Directory-only profile без Redis/hasher/SMTP и независимо от enabled primary methods. Добавлены source/default-off/route tests и actual HTTPS/SQL fixture с отдельными users/role/sessions и cleanup: permission denial/removal, query bounds, no secrets/cookies/session mutation. Main выполнил formatter/source review. V1 task check/API/race PASS. В fixture исправлено ожидание после прямого удаления SQL permission:403, затем explicit session_revision bump→401, fresh session→403. Production guards не менялись. V2 targeted lint0/full Linux ARM64 TestPrepareCommandSQL PASS, project_user_directory_HTTP без skip; TLS/Redis/wrong-password denial PASS. Manifest10+JSON совпали после прогона и с main, свои стенды очищены.

Snapshot `/private/tmp/auth-project-user-directory-v2.otguhsmj`, manifest/metadata sameprefix, logs `/private/tmp/auth-project-user-directory-v2-*.log`, evidence в history. Пользователь разрешил коммит; факт проверять Git.

## Следующий шаг

Project-local admin issuance/lifecycle/roles/settings consumers и MFA policy settings по MP5. Полная two-project matrix/phase-ready, rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/DNS/TLS/email-proof matrix/GC/RPS не считать закрытыми. UI только после предупреждения и отдельного согласования.

## Процесс и ограничения

- Read-only researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2, gpt-6-luna medium/reuse. Исполняемые проверки только отдельный чат Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL command: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory. Только own fixture cleanup.
- Предыдущий MP5.1j MFA management принят Luna V1/V2 PASS, commit8b55521. Последний Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:9. Govulncheck ранее0reachable,1required-module advisory внеimport/callgraph; уточнить приMP6R, не обновлятьdeps без разрешения.
- Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
