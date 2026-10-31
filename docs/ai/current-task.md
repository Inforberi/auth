# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Email MFA](../features/email-mfa.md).

## Завершён A6.3m.6c.4b.1 — project recovery prerequisite

Existing MFA recovery подключён к scoped project lease, SMTP/Redis/delivery readiness и проверке отдельной DB operator group. Runtime не одобряет восстановление. Добавлены две browser routes и bounded drain уведомлений в существующем ProjectDelivery; новая сессия при recovery не создаётся. Deployment RecoveryEnabled=false и email-factor CheckCapability остаются закрыты. ENV/schema/dependencies/отдельных workers не добавлено.

## Проверки

Luna: V1 task check, app/MFA HTTP и RecoveryDelivery race PASS; V4 targeted lint PASS0 и actual race TestTwoProjectMFARecoverySQL PASS/exit0, включая cleanup. Manifest19/19 совпал с рабочим деревом до обновления статусов Markdown; runtime не менялся. Все fixture DB/roles/schemas/Redis15, disposable containers/certificates очищены. Успешная внешняя SMTP-доставка не подтверждена.

Снимок `/private/tmp/auth-project-mfa-recovery-v4.yWwkfsqD`, base bb3700d. Evidence: Luna turn 01a19447-d057-7ac3-8e22-728f724cd9f9; cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:57; thread 01a16eab-c777-78a0-a815-47b45ff0860d, host local. Подробности — [history](../planning/history.md), контракт — [project MFA](../features/project-mfa-runtime.md#операторское-восстановление-проектного-mfa).

## Далее

Продолжить .4b: email factories/config budgets, явный browser/native method selection без plain fallback, project cookie rewriting/routes/Swagger и оставшаяся two-project/strong/role-transition/last-admin acceptance. Полная .4b не завершена. UI только после предупреждения и отдельного согласования.
