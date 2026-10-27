# Текущий шаг

Обновлено 27 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1m project user lifecycle

[Контракт](../features/project-user-lifecycle.md). Project-local POST admin/users/{id}/status и DELETE admin/users/{id} через existing handlers/DTO/service/SQL. Default-off manifest userLifecycle/browser prerequisite и UserLifecycleEnabled в программной сборке. Ready MFA management config, sessionNoRefresh/exactOrigin; отдельные SQL UsersStatusManage/UsersDelete и freshpasswordMFA. One-lease5s/currentbinding pre/post, error не выдаёт успешнуюверсию, но не доказываетrollback SQL commit.

Version/conflict/revoke/no-revival/pending/tombstone/audit/last-usable-system-super-admin guards не менялись. No new schema/deps/ENV/workers/cache. Actual HTTP account fixture дополнен отдельным lifecycle case с own active/pending/superadmin users/role/session, revoke/version/retry/audit/last-admin code assertions. Request helper принимает HTTP method; прежние issuance assertions сохранены. Main formatter/source review. Luna task check/task check:api/affected race PASS; полный Linux ARM64 TestPrepareCommandSQL PASS, project_user_lifecycle_HTTP и прежние directory/MFA/identity cases без skip. TLS/Redis/wrong-password preflights PASS. Manifest12+JSON совпали после прогона и с main; свои стенды очищены.

Snapshot `/private/tmp/auth-project-user-lifecycle-v1.8e5y3oh9`, manifest/metadata sameprefix, logs `/private/tmp/auth-project-user-lifecycle-v1-*.log`. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Project-local roles/settings consumers и MFA policy settings. FullMP5 two-project matrix/phase-ready, operations/MP6R/MP7/MP8 отдельно. UI только после предупреждения и отдельного согласования; GC/RPS/external matrix не считать закрытыми.

## Процесс и ограничения

- Researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2 gpt-6-luna medium read-only/reuse. Исполняемые проверки только отдельный чат Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL command: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory. Cleanup только ownfixtures.
- Предыдущий MP5.1l issuance V1–V3 PASS, commit8029e7c. Последний Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:13. Security ранее0reachable/1requiredmodule advisory внеcallgraph, уточнитьMP6R без несогласованного обновленияdeps.
- Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
