# Текущий шаг

Обновлено 27 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1n project Access management

[Контракт](../features/project-access-management.md). 11 project-local roles/catalog/assignment/my-access/system-admin routes на existing Access handler/service/SQL. Typed projectAccess adapters queries/mutations берут одинlease5s/currentbinding pre/post, не возвращаютрезультатнаошибке. Existing SQL authority/delegation/version/sessionrevision/systemrole/lastadmin guards не менялись. Read/write readiness отдельно: read без MFA config, mutation только readyMFAmanagement. NoRefresh/exactOrigin. No new schema/deps/ENV/workers/cache.

Manifest optional access:{permissions:[]} requiresbrowser; отсутствие default-off, пустойobject=builtins. Source perUUID compiles immutable settings.Catalog, platformcatalog не наследуется. Programmatic ProjectProfileConfig.Access=*settings.Catalog. Cold CheckCatalog с3s deadline, тольконаbuild; неизвестныеstoredpermissions закрываютAccesscapability. JWTкаталог прежний отдельно, deployment definitions согласовываются вручную, runtime-reload не добавлен.

Main formatter/source review. Source/catalog/prerequisite/route tests и actual HTTPS project_access_HTTP покрывают custom role create/read/update/grant/revoke, актуальные permissions, конфликты версий, delegation/self-grant/system-flow denial и session invalidation. Luna V1 Go tests/API/race/full Linux ARM64 TestPrepareCommandSQL (новый project_access_HTTP без skip) и standalone TestAdministratorAssignmentsSchema PASS. После lint замечания выделен browserProfile в source file без изменения семантики. V2 app tests и targeted lint0 PASS; прежние SQL/API/race PASS сохраняются.

Snapshot `/private/tmp/auth-project-access-v2.ymzb1tm1`, manifest14/metadata sameprefix, JSON example artifact. Hashes совпали до/после прогонов и с main. Task-owned стенды очищены, evidence в history, logs `/private/tmp/auth-project-access-v1-*.log` и `v2-*.log`. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Project-local settings consumers и MFA policy settings. FullMP5 two-project matrix/phase-ready, operations/MP6R/MP7/MP8 отдельно. UI только после предупреждения и отдельного согласования. GC/RPS/external matrix не считать закрытыми.

## Процесс и ограничения

- Researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2 gpt-6-luna medium read-only/reuse. Исполняемыепроверки толькоотдельныйчат Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/authstale. Mainне дублирует/не ждётполныйпрогон. [Процесс](development-workflow.md).
- SQL: ownLinuxARM64 postgres18.6 readonly/src, adminsockettrust/TCP127SCRAMwrongpwdeny/TLSSAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory. Standalone schema onlyownDB/roleauth_schema_test, AUTH_SCHEMA_TEST_DATABASE_URL strict127/auth_schema_test. Cleanuponlyownfixtures.
- PreviousMP5.1m lifecyclePASS, commit145f490. Последний Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:15. Securityранее0reachable/1requiredmoduleadvisory внеcallgraph, MP6Rотдельно безнесогласованногообновленияdeps.
- RealENV/secrets/БД/stagingсохранять. Commitтолькопозапросу. FullMP5/MP7/MP8/UIgatesоткрыты.
