# Текущий шаг

Обновлено 26 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1j project MFA management

[Контракт](../features/project-mfa-management.md). Восемь owner MFA routes: status/enrollment+confirm/step-up/disable/recovery rotation/replacement+confirm. Existing handlers/services/SQL, NoRefresh/exactOrigin/currentkey, shared project cipher/limits. Factory хранит immutable managementConfig, projectMFA.use общий bounded one-lease guard; ни nested UsePool, ни partial secrets при post-guard error.

Management отдельно от enabled SQL primary methods, на согласованной operational MFA/session config всех configured browser methods. MFA-disabled/browser-disabled/Redis failure/config mismatch fail-closed. Email proof только при готовой выбранной reauth, SQL external-only guards прежние. Role/admin обязательность не ослаблена; новых project-wide required/optional settings нет, lost-all-factors закрыт. No new deps/ENV/schema/pools/workers/UI.

Main formatter/source/read-only review. V1 Luna taskcheck/API/security/race PASS; fixture дополнен необходимым POST password reauthentication после ordinary MFA login. Production guards не менялись. V2 targeted lint0/full Linux ARM64 TestPrepareCommandSQL PASS: новый project_MFA_management_HTTP и прежний project_MFA_login без skips. TLS verify-full/Redis/wrong-password denial PASS. Все13source hashes совпали после прогона и с main; свои containers/network/build files очищены.

Snapshot `/private/tmp/auth-project-mfa-management-v2.5413spgz`, manifest sameprefix-manifest.sha256, metadata sameprefix-snapshot.json; evidencehistory, logs `/private/tmp/auth-project-mfa-management-v2-*.log`. Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:7. Пользователь разрешил коммит; факт проверять Git.

## Следующий шаг

После приёмки — оставшиеся account administrative consumers и policy settings по MP5, полная two-project matrix/phase-ready. Rotation/retention/fleet/MP6R/MP7/MP8 отдельно. External provider/SMTP/DNS/TLS/email-proof matrix/GC/RPS не считать закрытыми. UI только после предупреждения и отдельного согласования.

## Процесс

- Read-only researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2, gpt-6-luna medium/reuse.
- Все executable checks только Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL command: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory; не macHost/randomport/trustTCP. Толькоownfixturecleanup.
- Govulncheck ранее0reachable,1required-module advisory внеimport/callgraph; уточнить приMP6R, не обновлятьdepsбезразрешения.
- Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
