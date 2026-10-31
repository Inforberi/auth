# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Email MFA](../features/email-mfa.md).

## Завершён A6.3m.6c.3 — внутренний email-factor login/recovery

Password→email code использует bound MFA parent/OTP outbox и атомарную выдачу browser/native credentials с sign/audit/deadline. Session email → JWT pwd+email_otp; refresh/introspection сохраняют точный proof, strict SQL/SDK остаются TOTP/recovery. Last required factor защищён; email-only личный lifecycle требует fresh password/current factor. Первый TOTP enrollment не обходит email proof.

Потерянный/suspended email-only заменяется новым TOTP через existing password+operator-approved recovery, с отзывом credentials и без автоматической session. Optional режим без личного фактора сохранён. Административный email-only management пока закрыт: существующий TOTP сохраняется до compatibility matrix.

## Следующий шаг

A6.3m.6c.4 — profiles/readiness, выбор метода, бюджеты из конфигурации, защищённый HTTP/Swagger и реальные two-project/strong/recovery gates; отдельно platform/admin/role-transition/last-admin compatibility. CheckCapability пока закрывает email-enabled runtime; новых HTTP/ENV/startup публикаций нет. Source up/down baseline изменён, реальные DB/ENV не трогались, upgrade MP6 отдельно. UI только после предупреждения и согласования.

## Проверки

Luna V3: task check и actual TestEmailFactorLoginSchema/TestPostgresSchema/TestMFAPolicyNativeSchema/TestMFAPolicyJWTConsumersSchema с -race -count=1 PASS. V2 token service race и пять успешных SQL roots V1 сохранены без повторения. Manifest48/48 и cleanup подтверждены, main сверил рабочие файлы до обновления Markdown; Go/SQL не менялись.

Снимок `/private/tmp/auth-email-factor-login-v3.ydb9tm2o`, manifest/metadata рядом, base 0c970d7b1f4993740c2f2ba1c90df8a3bb704a78. Luna thread 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:52. Все исполняемые проверки выполняет Luna. V1/V2 blockers и полные evidence — в [history](../planning/history.md).
