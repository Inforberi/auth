# Настройки авторизации внутри проекта

## MP5.1o: проектный HTTP

`GET /api/v1/admin/auth/settings` читает политику, `POST` полностью заменяет её по `expectedVersion`. Используются existing Auth settings handlers/DTO/mapper/service и SQL. Все boolean обязательны, включая false; неполный JSON не превращается в частичное обновление. Полный контракт — [auth-settings](auth-settings.md).

В UUID manifest `authSettings` default false и требует browser; программный флаг — `ProjectProfileConfig.AuthSettingsEnabled`. Readiness разделена на `auth_settings_read` и `auth_settings_write`: GET доступен без включённой MFA configuration, POST публикуется только при готовой согласованной MFA management config. Это не выдаёт actor право: оба endpoints требуют текущую проектную SQL-сессию и `auth.settings.manage`, изменение дополнительно требует свежие пароль и MFA в SQL. NoRefresh/exact browser Origin/no-store сохраняются.

Каталог платформы и platform principal не используются. Можно менять существующие methods/registration/passwordEmailVerification/tokenIssuance switches, но не добавлять отсутствующие deployment adapters, keys, callbacks, audiences или секреты. Управление SMTP/provider credentials/retention — другие существующие контракты и отдельное подключение; этот блок их не публикует.

## Readiness и безопасное обновление

Общий `assessProjectProfile` используется и существующим platform bridge, и local API. Кандидат assessment не публикуется как маршрутизируемый профиль. Отключённый в SQL метод оценивается как потенциальная возможность deployment: это позволяет безопасно включить его повторно после отключения.

GET сначала проверяет право/читает snapshot, затем после освобождения lease оценивает реальные adapters/dependencies и повторно проверяет право/snapshot. Несовпадение policy version возвращает conflict. Ответ включает actual `availableMethods`, публичный `tokenProfiles` без секретов и `readiness` с временем наблюдения/версией/feature reasons. Это локальное наблюдение, не fleet acceptance и не гарантированная будущая доступность внешнего сервиса.

POST сначала делает дешёвое authorized чтение/current-version preflight, затем assessment без удерживаемого lease/SQL locks. На финальной стадии existing transaction снова проверяет текущие permission/password/MFA, блокирует policy и сверяет expectedVersion. Runtime constructor передаёт actual methods/tokens/mail readiness и версии зависимостей в existing `CheckPolicyChange`; выбранные SMTP/providers проверяются и закрепляются SQL locks/version comparison. Preflight не заменяет authority в commit.

Ответ POST содержит readiness-наблюдение, использованное для допуска. Его policyVersion относится к версии до записи; верхний version — результат commit. На no-op они совпадают. Нового HTTP DTO/error catalog не добавлено: существующий Handler поддерживает optional readiness-aware service, standalone путь без этого контракта сохраняет прежний ответ.

Restrictive изменения сохраняют SQL требование пригодного системного суперадминистратора. Отключение login не закрывает административное управление существующей сессией и не меняет independently selected logout/introspection guarantees. После изменения policy прежний resident profile отклоняет следующий запрос и пересобирается по существующему механизму; это не принудительный вход или обновление cookie.

Lease операций ограничен пятью секундами, service SQL операции — прежними deadline; весь запрос/assessment дополнительно ограничен profile timeout и HTTP admission. Последовательные preflight/assessment/commit leases не вложены. После mutation финальный binding guard остаётся; ошибка после commit не доказывает rollback. Нужно сверить актуальные настройки перед повтором. Новых таблиц/миграций/deps/ENV/workers/cache нет.

## Проверки

Добавлены source/default-off/UUID isolation/prerequisite/route cases и actual HTTPS/SQL fixture: protected read, readiness versions, foreign Origin/no-cookie/stale-password denial, Google/email verification not-ready, disable/re-enable password при действующей admin session, stale expectedVersion, no-op/auditcount. Own usable superadmin/role/session/policy/audit cleanup изолированы; существующие Access/issuance/lifecycle cases сохраняются. Локальные проверки Luna V1/V2 PASS: Go tests/API/race/lint и полный Linux ARM64 TestPrepareCommandSQL с новым project_auth_settings_HTTP без skip. Выделение requiresBrowser проверено без изменения семантики; full MP5/two-project/fleet/securityreview/GC/RPS/UI отдельно.
