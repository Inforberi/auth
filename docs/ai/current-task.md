# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Email MFA](../features/email-mfa.md#проектная-сборка-и-явный-выбор--a63m6c4b2).

## Завершён A6.3m.6c.4b.2 — project email MFA

Opt-in ProjectProfile.EmailMFA собирает scoped factories/config budgets/SMTP/Redis/recovery readiness, protected browser/native selected-email и policy API/Swagger. Forced native не пробует plain issuance; binding cookie содержит project UUID. SQL guards сохраняют weak-email/strong-TOTP границу, last-admin и текущую административную authority после role changes. Deployment/ENV/manifest и standalone/platform email не активированы. UI не начат; dependencies/schema/workers не добавлены.

## Проверки

Luna V2 task check, affected app/MFA HTTP/router race, два email-factor schema roots и Access/Recovery project SQL PASS. V1 API и неизменённые race packages PASS сохранены. V3 targeted lint0 и actual TestTwoProjectEmailMFAHTTP race PASS/exit0 без SKIP, включая cleanup. Manifest59/59 совпал с рабочим деревом до обновления Markdown; runtime/generated artifacts не менялись. Scratch DB/roles/schemas/Redis15, containers/certificates/caches очищены. Внешняя SMTP-доставка и capacity не заявляются.

Снимок `/private/tmp/auth-project-email-mfa-v3.RSXk5dQl`, base af39f71. Evidence Luna turn 01a1965f-06ee-7383-afdf-fd9aa8159aeb, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:60; thread 01a16eab-c777-78a0-a815-47b45ff0860d, host local. Подробности — [history](../planning/history.md).

## Далее

Завершить .4b: deployment/ENV/manifest и оставшуюся административную/realm compatibility приёмку до включения. Полная .4b ещё не закрыта. UI только после предупреждения и отдельного согласования.
