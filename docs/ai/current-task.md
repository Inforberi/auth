# Текущий шаг

Обновлено 28 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1r retention settings

[Контракт](../features/project-retention-settings.md). Проектные GET/POST настроек сроков хранения на существующих service/HTTP/SQL. Default-off `retentionSettings`, browser prerequisite, read независимо от MFA, write при готовой MFA management. NoRefresh/exact Origin/current SQL auth.settings.manage/fresh password+MFA/version/audit. Сокращение любого срока требует confirmShortening; API не запускает purge. Один runtime lease/deadline 5s, service 3s, pre/post current-binding guards. Новых schema/deps/ENV/workers нет.

Source/prerequisite/route и реальный HTTPS fixture добавлены. Fixture восстанавливает собственные настройки/audit и не запускает очистку. Luna: task check/API/targeted race/полный Linux ARM64 TestPrepareCommandSQL/targeted TestRetentionSettingsSchema — PASS; новый HTTPS subtest без SKIP. Временные стенды удалены. Snapshot `/private/tmp/auth-project-retention-settings-v1.1xmom4xg`, manifest11/metadata рядом; проверен Luna, подробности в [history](../planning/history.md#mp51r-project-retention-settings--28-октября-2026). Все 11 source и JSON artifact сверены с main: совпадают. Пользователь разрешил коммит после PASS; факт коммита проверять Git.

## Следующий шаг

Настраиваемая MFA policy. Полная MP5/two-project/phase-ready/operations/MP6R/MP7/MP8 отдельно. UI — только после предупреждения и отдельного согласования. Внешние OAuth/SMTP, GC и RPS не считать закрытыми.

## Процесс

Researcher `01a1797b-d48d-7d71-9e48-2d92dc22d9f2` — Luna medium, read-only, переиспользовать. Все исполняемые проверки — чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, точный snapshot; default checkout 6377/auth устарел. Последний cursor `19bf04ec-f4f6-4693-9c20-73f414b172e4:20`. Основной агент не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).

SQL — собственный Linux ARM64 PG18.6 / readonly /src; socket trust, TCP127 SCRAM с wrong-password denial, TLS SAN127; Redis8.2 в общем network, DB15. Обязательные SCRAM_HOST/TLS_CA/ROOT=/src/Redis127. Standalone retention SQL — собственная auth_schema_test DB/role, env AUTH_SCHEMA_TEST_DATABASE_URL и cwd пакета для migrations. Очистка только собственных fixtures; реальные ENV/secrets/DB/staging сохранять.

Предыдущий MP5.1q providers PASS, commit `791c8fe`; доказательства в history. Общие security/resource gates открыты; зависимости без согласования не обновлять.
