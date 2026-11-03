# Текущий шаг

3 ноября 2026. R4 завершён и принят Luna на `/private/tmp/auth-r4-mfa-v9-20mfgxxw`, base788940b, manifest566. Main сверил source hashes; после приёмки изменялись только Markdown. R3 commit:788940b; текущий commit/staging проверять через Git.

MFA разделён на login/management/recovery/telegram/delivery; общие proof/crypto/admission без обратных imports; domain выбирает метод и проверяет отключение TOTP при прежнем SQL snapshot/locked tx. HTTP bindings явные, публичные Swagger IDs сохранены. Unit tests у владельцев, connected SQL closure — app/auth/tests. Новых функций/зависимостей/SQL/routes нет.

Проверки: V7 full Go tests, V8 lint0/race, V9 targeted tests/lint0/API и все согласованные SQL roots PASS. Отдельно main подтвердил actual RUN/PASS всех27 ранее пропущенных SQL roots. Собственные host-bind PG/Redis fixtures очищены, чужие ресурсы не затронуты. [Evidence и ограничения](../operations/acceptance-summary.md#r4-mfa-приёмка--3-ноября-2026).

Следующий блок — [R5 account и методы входа](../planning/readability-refactor.md#r5-account-и-методы-входа). Архитектуру сохранять; UI не начинать. R2 live readiness/TestPrepareJWT, external/MP7/MP8/capacity/GC gates остаются отдельно.

Все executable checks — Luna. В каждом задании указывать основной чат и обязательную обратную отправку PASS/FAIL/BLOCKED через send_message_to_thread; пользователь разрешил её. Final в чате Luna не заменяет доставку. Коммит — при разрешении пользователя после полной приёмки/source сверки. Реальные env/БД/secrets не менять, новые зависимости требуют разрешения.
