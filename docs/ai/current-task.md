# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Deployment](../features/project-auth-deployment.md#email-mfa-из-manifest--a63m6c4b3).

## Завершён A6.3m.6c.4b.3 — deployment opt-in email MFA

Manifest emailMFA default-off выбирает UUID; шесть operational ENV задают channel/change budgets. Loader требует browser/MFA/project delivery/валидный SMTP allowlist и budgets. RecoveryEnabled устанавливается только в копиях выбранного project browser/native profile, глобальная платформа и другие UUID не меняются. SQL allowed/personal binding отдельны; runtime readiness и cold-profile fail-closed сохраняются. Examples выключены, real ENV/manifest/DB не менялись. UI не начат; dependencies/schema/workers/routes не добавлены.

## Проверки

Luna V2: manifest20/20, task check, targeted config/app/router race и actual manifest-backed TestTwoProjectEmailMFAHTTP race PASS/exit0. DB/roles/schemas/Redis15, containers/certificates/caches очищены. V1 lint/source/JSON/ENV consistency PASS. Пустой SMTP target V1 исправлен через существующий ValidateTargets, без копии parser/rules. Main сверил20/20 до обновления только Markdown; executable checks не запускал. Предыдущие .4b.2 schema/API PASS сохранены, SQL business/Swagger не менялись.

Снимок `/private/tmp/auth-email-mfa-deployment-v2.uZ7dUVWW`, base 988109e. Evidence Luna turn 01a19694-19dd-7501-89d8-45c500342cbd, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:62; thread 01a16eab-c777-78a0-a815-47b45ff0860d, host local. Подробности — [history](../planning/history.md).

## Далее

Сверить итоговую матрицу .4b/acceptance-summary и оставшиеся pre-UI gates по фактам; не объявлять весь релиз готовым по этому блоку. Внешние SMTP secrets/доставка и capacity не подтверждены. UI только после предупреждения и отдельного согласования.
