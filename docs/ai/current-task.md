# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Email factor](../features/email-mfa.md). Git/staging проверять по факту.

## Завершён A6.3m.6c.1 — подготовка email-канала

Внутренние Request/Confirm используют owned verified email, свежую password/browser session и strong MFA по текущей policy. Код привязан к purpose/source hash/auth_version; ограничены срок и попытки. Подтверждение атомарно ротирует текущий token и сохраняет email possession proof без новой session/MFA/roles/version/TTL. Переиспользованы OTP outbox/delivery/retention.

Это подготовка канала, не включённый email MFA. Новых HTTP/ENV/runtime activation нет. Исходная prerelease migration изменена; реальные DB/ENV не трогались, upgrade отдельно MP6.

## Следующий шаг

A6.3m.6c.2 — activation/policy, личный выбор и жизненный цикл канала. Затем .6c.3 atomic browser/native email factor и .6c.4 profiles/readiness/protected HTTP/two-project gates до публикации. UI отдельно после предупреждения и согласования.

## Проверки

Luna: task check, emailotp race, TestEmailFactorPreparationSchema, TestPostgresSchema и TestTwoProjectEmailOTPHTTPIsolationSQL — PASS. Manifest 24/24 и cleanup подтверждены; main сверил рабочие файлы со снимком до обновления Markdown. Снимок `/private/tmp/auth-email-factor-preparation-v1.2f_3y9e3`, manifest/metadata рядом; base 5fca78a370b96c96079cf832376aee1eeec4680f.

Все исполняемые проверки — только «Проверки Auth — Luna» 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:47. Main тесты не повторяет. Полная история и evidence — в [history](../planning/history.md).
