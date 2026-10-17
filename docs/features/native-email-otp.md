# Email-код для JWT-входа — J4b.2b.2-local

17 октября 2026: внутренний email OTP подключён к общей API issuance и [native MFA](native-mfa.md). **App/HTTP/ENV не подключены.** `JWT_ENABLED` не публикует эти операции. Код — основной способ входа, не email verification и не второй фактор.

## Операции и владельцы

| Внутренний метод | Назначение |
| --- | --- |
| `token/service.NativeEmailLogin.Request` | Deployment resource/scope allowlist и передача target в email OTP |
| `emailotp/service.RequestNative` | Общие email validation/policy/budgets/generator/encrypted mail/SQL issue с API binding |
| `emailotp/service.AuthenticateNative` | Shape/IP/agent bounds, общие confirm budgets/policy и API-only consume |
| `emailotp/repository/postgres.ConsumeNative` | Locked current owner/contact/version/policy/code → server-only proof и сохранённый SQL target |
| `token/service.NativeEmailLogin.Confirm` | Consume → существующий NativeLogin.Begin → credentials либо MFA/enrollment challenge |

PrimaryProof — не JSON DTO или клиентский credential. Native confirm не принимает user ID, email, audience, scope или признак пройденного MFA. Внутренний request возвращает binding; его передача native-клиенту требует будущего HTTP-контракта, не переиспользования browser flow cookie.

## Привязка и одноразовость

Существующая `auth.email_login_challenges` получила credential_profile (`browser` default / `api`), native_audience/native_scope и trigger неизменяемости digest/profile/target/purpose/session binding. API profile допускает только login, reauthentication — browser-only. Audience ограничен 1..128 ASCII bytes, scope — 1..64 keys/2048 bytes; service копирует/сортирует scope, отказывает дублям и неизвестным requested permissions.

API HMAC namespaces — `native:binding:` и `native:code:` внутри существующего scoped email-login cipher. Browser/reauthentication namespaces сохранены. SQL Consume/ConsumeNative применяют фиксированный profile даже при прямой передаче digest; reauthentication требует собственный purpose/live-session binding. Короткий код не хешируется простым SHA-256.

После consume target берётся из locked SQL row и сохраняется в issuance/MFA challenge. Native MFA допускает password/emailotp primary, но не OIDC/admin intent. Final RequireLoginPrimary заново проверяет current verified login contact/public policy/version/eligibility: правильный второй фактор не компенсирует устаревшее email proof.

Consume и последующая issuance — **два последовательных workflow**, как в browser email OTP. Первый блокирует user → challenge, проверяет current contact/version/status/TTL/attempts и constant-time verifier. Неверные попытки коммитятся до публичного отказа; после пяти правильный код тоже не проходит. Успех атомарно удаляет challenge/outbox и пишет metadata audit. Audit/подтверждённый consume commit abort восстанавливает код; proof не возвращается до commit.

Затем NativeLogin.Begin повторно проверяет primary/role/grants/policy и возвращает API credentials либо только MFA challenge. Browser session не создаётся. **Ошибка после успешного consume не восстанавливает email-код**: нужен новый request с учётом общего cooldown. Retry/grace нет. При неопределённом network commit нельзя обещать rollback; неизвестный результат не выдаёт raw credentials.

Claims содержат `emailotp`, реальное auth_time и разрешённый scope. MFATime/`mfa` появляются только после второго фактора; password/private-admin proof не возникает. Required enrollment использует общую TOTP activation/version bump/revoke и требует нового email login после настройки. Refresh не повышает assurance.

## Ресурсы и ограничения

- [Eligibility и почтовые лимиты](email-otp.md) прежние: existing active user, verified current login email, постоянные password credentials; без регистрации неизвестного, external-only onboarding и pending/temporary activation. Неподходящий адрес получает generic accepted без outbox.
- Один email challenge/user между browser/API/reauthentication. Новая допустимая выдача заменяет старую. Email/IP/project/cooldown budgets общие между профилями.
- Общие SMTP/outbox/encryption/delivery worker/pool/retention; новых tables/workers/dependencies/Redis namespaces/ENV нет. Existing lease/TTL/retry/cleanup semantics сохранены; exactly-once SMTP не обещается.
- Request: deadline5s, общий token instance admission8. Confirm: deadline10s, consume5s, последующий NativeLogin3s. Consume освобождает admission slot до Begin, без вложенного занятия второго слота. Atomic credential IP/project budget выполняется до native confirm SQL, затем прежние email/token/MFA budgets. Нет per-random-code Redis key/безлимитной очереди.
- Только source000001 up/down: новые email columns/trigger и расширенный MFA profile CHECK нужны binary даже без native enable. Controlled schema/grants upgrade обязателен до traffic. Рабочие DB/ENV/secrets не менялись, reset/down рабочей базы запрещён.

## Приёмка и следующий блок

Unit/real SQL/race проверяют encrypted mail→code→issuance→refresh, один concurrent winner, committed five-guess cap, profile/namespace isolation, immutable target/purpose, replacement, current block/version/email/grants, consume audit rollback и невозможность повторить код после signing failure. Email→required enrollment→fresh code→MFA completion проверен с реальными TOTP/recovery primitives и финальным email recheck.

Далее J4b.2c: App/native config и HTTP request/confirm/MFA/enrollment/login/refresh/logout. До публикации остаются legacy browser MFA admission/cardinality, deployment ceilings, retention scan/backlog/drain/storage, API negative/concurrency и strict consumer J5. HTTPS/native client/SMTP/providers/fleet/lost-commit-reply/load/GC/restore этим блоком не проверены; capacity не установлена.
