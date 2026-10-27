# Текущий шаг

Обновлено 27 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1o local Auth policy settings

[Контракт](../features/project-auth-policy-settings.md). Project-local GET/POST admin/auth/settings на existing settings HTTP DTO/service/SQL. Default-off manifest authSettings/browser prerequisite; AuthSettingsEnabled programmatic. Read/write readiness отдельно, update readyMFAmanagement, NoRefresh/exactOrigin/SQLauth.settings.manage/freshpwdMFA. Новыхschema/deps/ENV/workers/cacheнет.

ProjectHTTP.Assess вынесен в shared assessProjectProfile без route publication; local preflight освобождает lease доassessment, finalServiceUpdate получает actualPolicyRuntime+dependency revisions через NewWithPolicyRuntime. Existing permission/expectedVersion/restrictive usableAdmin/dependency locks/pins/audit SQL unchanged. Read readiness наблюдает potential configuredmethods, включаяSQLdisabled; повторный Read проверяет currentactor/snapshot. Optional readiness-aware Handler service возвращает actualavailableMethods/publicTokens/readiness without secrets. POST readinessPolicyVersion prewrite, responseversion postcommit. StandaloneHandler fallback unchanged.

Main formatter/source review. Source/default-off/prerequisite/routes и actual HTTP fixture проверяют protected read/readiness, свежие proofs, not-ready Google/mail, disable/re-enable, stale version и no-op/audit. Own systemadmin/session/policy/audits cleanup. В fixture manager добавлен AuthSettingsManage, Access nondelegation теперь использует declared reports.read без выдачи actor.

Luna V1 Go tests/API/race/full Linux ARM64 TestPrepareCommandSQL/project_auth_settings_HTTP без skip PASS. После lint замечания выделен requiresBrowser в manifest без изменения boolean выражения/порядка. V2 app tests/targeted lint0 PASS; прежние SQL/API/race PASS сохраняются. Snapshot `/private/tmp/auth-project-policy-settings-v2.ybiqkdgi`, manifest18/metadata sameprefix, JSON artifact. Hashes совпали до/после и с main; task-owned стенды очищены. Logs `/private/tmp/auth-project-policy-settings-v1-*.log` и `v2-*.log`, evidence в history. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Оставшиеся project settings consumers и настраиваемая MFA policy. FullMP5 two-project matrix/phase-ready/operations/MP6R/MP7/MP8 отдельно. UI только после предупреждения и отдельного согласования; GC/RPS/external matrix не считать закрытыми.

## Процесс

- Researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2 Luna medium read-only/reuse. Исполняемыеchecks толькоотдельныйчат Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/authstale. Mainне дублирует/не ждётполныйпрогон. [Процесс](development-workflow.md).
- SQL ownLinuxARM64 postgres18.6 readonly/src; sockettrust/TCP127SCRAMwrongpwdeny/TLSSAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127mandatory. Cleanuponlyownfixtures. РеальныеENV/secrets/DB/stagingсохранять.
- PreviousMP5.1n AccessPASS commit14ee5a3. Последний Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:17. Securityранее0reachable/1requiredmoduleadvisory внеcallgraph, MP6Rотдельно безнесогласованногообновленияdeps. FullMP5/MP7/MP8/UIgatesоткрыты.
