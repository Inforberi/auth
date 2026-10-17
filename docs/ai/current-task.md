# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), checks — [history](../planning/history.md#результат-as5-local--17-октября-2026). Это передача контекста, не архив.

## Последний результат — AS5-local

- Независимый admin idle/absolute профиль: defaults 30m/12h, activity interval 1m. SQL issuance выбирает его по восьми core admin permissions/system super-admin, независимо от primary URL; обычные sessions сохраняют старый профиль.
- Явный POST /api/v1/auth/session/activity: current cookie + Origin + NoRefreshAuth, bounded SQL extension, без обновления proof/absolute. Фоновые reads/generic refresh не продлевают admin session. Cookie получает закоммиченный expiry, no-op не пишет cookie.
- SQL хранит lifetime policy на момент issuance; ENV changes не переписывают старые сроки. Coalescing может завершить idle до interval раньше; UI A7 должен сообщать только взаимодействие, не polling heartbeat. [Контракт/нагрузка/upgrade](../operations/browser-security.md#сроки-административных-сессий--as5).
- Unit/config/router/lint и полный PostgreSQL 18.6/race/up-down-up PASS. Non-owner SQL/HTTP: 16 concurrent reports → один UPDATE, proof/absolute неизменны, expired direct authority/rotate/reauth запрещены. Реальный MFA completion проверен с обоими intents; настоящий browser/fleet/load этим не доказан.
- AS6a/b-local уже защищают grant/permission elevation через auth_version и immutable role revisions, без fan-out UPDATE всех пользователей. MFA-role policy ещё не реализована.
- Изменён source 000001, не рабочая БД/ENV/secrets. Applied installation требует controlled schema/code/grants upgrade и invalidation прежних sessions/challenges до трафика, не reset/mixed fleet. AS6b, план совместимости и AS5 зафиксированы отдельными коммитами.

## Следующий блок — A6.3

1. MFA по custom roles и enrollment-required flow; текущие admin guards не отключаем. Усиление роли связывается с AS6/role revision, старые sessions не наследуют обход MFA.
2. Затем integration secrets/SMTP/provider rotation/connection tests, retention/runtime propagation; root/deployment secrets остаются вне UI.
3. Соблюдать [совместимость настроек A6.3/A7](../planning/implementation.md#совместимость-настроек-и-безопасные-переключения--a63--a7): реальные зависимости, сохраняемые неактивные предпочтения, last-admin и безопасные переходы. Матрица — план, не уже реализованные новые проверки.

Далее A6.4 [JWT J1–J7/S1–S10](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. Cookie/session — default, strict online authority сохраняется; local-only JWT требует отдельного ADR. Следующая реализация и коммит — по запросу пользователя.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Нужен разрешённый изолированный HTTPS-стенд с synthetic data: browser/ingress/multi-tab/interaction-vs-polling/sleep-resume/SMTP/provider/authenticator/admin workflows, fleet settings и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена.
