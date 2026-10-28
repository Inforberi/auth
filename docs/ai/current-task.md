# Текущий шаг

Обновлено 28 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — A6.3m.1a MFA requirements

[Контракт](../features/mfa-policy.md). Первый безопасный подэтап настраиваемой обязательности: исследованы platform/operator и Auth/access guards; повторяющиеся предикаты административного доступа/MFA вынесены в SQL-функции с прежним поведением. `has_administrative_access` включает users.read, `administrative_mfa_required` не включает; role_required остаётся самостоятельным OR назначений. Функции STABLE/invoker не являются авторизацией. Существующие locks/freshness/last-admin/bootstrap/platform TOTP/management guards не изменены.

Новых settings/API/ENV/deps/workers/optional-профиля нет. Изменена initial migration (не рабочие БД), добавлен TestMFARequirementPredicatesSchema с permission/role/ACL matrix. Luna V1 task check/targeted race/full Linux ARM64 command SQL PASS. Новый fixture исправлен: параметризованные SQL statements разделены без смены query protocol. Luna V2 targeted lint0 и точный набор шести schema-тестов PASS, временные стенды удалены.

Проверенный snapshot `/private/tmp/auth-mfa-requirements-v2.0h1ohxb0`, manifest6/metadata рядом. Все шесть source совпали с main, evidence в history. Пользователь разрешил коммит после PASS; факт коммита проверять Git.

## Следующий шаг

Версионируемая realm MFA policy и согласованное применение к входу, sensitive actions, управлению фактором, сессиям/native/JWT и first-run. Optional не публиковать частично: остальные A6.3m prerequisites открыты. Полная MP5/MP6R/MP7/MP8 отдельно. UI — после предупреждения и отдельного согласования; внешние OAuth/SMTP, GC/RPS не закрыты.

## Процесс

Активный read-only researcher Luna medium `01a183e1-ca25-7972-a67a-eadef20a0b41`; прежний `01a1797b-d48d-7d71-9e48-2d92dc22d9f2` возвращал устаревший retention result и не использовался для нового вывода. Все исполняемые проверки — чат «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local, точный snapshot; default checkout 6377/auth устарел. Последний cursor `19bf04ec-f4f6-4693-9c20-73f414b172e4:22`. Main не дублирует и не ждёт полный прогон. [Процесс](development-workflow.md).

SQL: собственный Linux ARM64 PG18.6 / readonly /src; socket trust, TCP127 SCRAM с wrong-password denial, TLS SAN127; Redis8.2 в общем network, DB15. Обязательные SCRAM_HOST/TLS_CA/ROOT=/src/Redis127. Standalone schema — собственная auth_schema_test DB/role, env AUTH_SCHEMA_TEST_DATABASE_URL и cwd пакета для migrations. Очистка только собственных fixtures; реальные ENV/secrets/DB/staging сохранять.

Предыдущий MP5.1r retention PASS, commit `25ef2e7`; доказательства в history. Общие security/resource gates открыты; зависимости без согласования не обновлять.

