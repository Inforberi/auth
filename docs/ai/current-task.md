# Текущий шаг

Обновлено 27 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1l project user provisioning

[Контракт](../features/project-user-provisioning.md). Подключены пять existing project-local HTTP операций: pending user/invitation, invitation reissue/activation, temporary password provision/reissue. Reuse existing handlers/DTO/services/SQL, narrow adapters, existing current project leases/guards. Browser NoRefresh для admin, exactOrigin; accounts.users.manage и fresh password+MFA остаются SQL authority. Нет новых schema/deps/ENV/workers.

Default-off manifest invitations/temporaryPassword требуют browser. Source копирует existing operational configs, URLorigin/activate, не наследует platform Enabled/secrets. Admin issuance требует готовую MFA management config. Отдельная stored invitation activation без SMTP/delivery даже coldbuild; temporary admin без SMTP, зависит готового password/temporary профиля. Replay не возвращает temporary secret и не продлевает expiry; activation не создаёт сессию/роль.

Main formatter/source review; source/default-off/copy/route/prerequisite tests и actual HTTPS account fixture. Luna V1 Go tests/API/race PASS; V2 targeted tests/app+command lint PASS; V3 full Linux ARM64 TestPrepareCommandSQL PASS, remaining_project_account_scenarios и прежние directory/MFA/identity HTTP cases безskip. TLS/Redis/wrong-password preflights PASS. Исправлены browser ветки для cyclop, fixture Invitation.URL к projectorigin и ожидание равного expiry при reissue replay; SQL/права/гарантии не ослаблены.

Snapshot `/private/tmp/auth-project-user-provisioning-v3.s0zexpqn`, manifest13/metadata sameprefix, logs `/private/tmp/auth-project-user-provisioning-v3-*.log`. Source13+JSON hashes совпали после прогона и с main; task-owned стенды очищены. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Project-local user lifecycle/roles/settings consumers и MFA policy settings. Полная MP5 two-project matrix/phase-ready, operations/MP6R/MP7/MP8 остаются отдельно. UI только после предупреждения и отдельного согласования; GC/RPS/external matrix не считать закрытыми.

## Процесс и ограничения

- Researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2 gpt-6-luna medium read-only/reuse. Все исполняемые проверки только отдельный чат Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- SQL command: own LinuxARM64 postgres18.6 readonly/src; admin sockettrust, TCP127 SCRAMwrongpassworddeny/TLS SAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127 mandatory. Cleanup только own fixtures.
- Предыдущий MP5.1k directory V1/V2 PASS, commitba5c913. Последний Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:12. Security ранее0reachable/1requiredmodule advisory внеcallgraph, уточнитьMP6R безнесогласованногообновленияdeps.
- Real ENV/secrets/БД/staging сохранять. Commit только по запросу. Full MP5/MP7/MP8/UI gates открыты.
