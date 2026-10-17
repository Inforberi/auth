# Сохраняемые настройки SMTP — A6.3c.1-local

SMTP-настройки принадлежат `internal/auth/settings`. Root encryption key и egress policy остаются deployment ENV. Google/Telegram credentials имеют отдельный [контракт A6.3c.2](provider-settings.md); SMTP не превращается в общий plugin framework.

## Первоначальная настройка и хранение

На новой установке startup создаёт singleton `auth.smtp_settings` из `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_DOMAIN`, `SMTP_REQUIRE_TLS`. Существующая запись всегда приоритетнее seed; рестарт не меняет её из ENV. Конкурентные initializers сохраняют одного winner. После initialized setup marker отсутствие строки — ошибка, не разрешение повторно импортировать ENV. Повреждённый ciphertext, неверный root key или недоступная SQL также не разрешают fallback.

Пароль шифруется существующим AES-GCM с отдельным purpose `smtp-settings:v1`; root `ACCOUNT_ENCRYPTION_KEY` не переносится в SQL/UI. База хранит JSON только не-секретной конфигурации, version и password presence; пароль — отдельный ciphertext. Чтение API/audit никогда не возвращает пароль, ciphertext, прежний пароль или маску для обратного сохранения. Очистка временного decrypted byte slice не означает гарантированное стирание Go strings/памяти GC; процесс и root key защищаются deployment-политикой.

Не-секретные bootstrap ENV пока обязательны по общему config contract. После seed SMTP password можно убрать из ENV, но root key и сохранённую строку нужно сохранить. Это не механизм root-key rotation; она требует согласованной процедуры re-encryption/backup/restore.

## Разрешённые назначения

`SMTP_ALLOWED_TARGETS` — до 16 точных `host:port`, разделённых запятыми; пустое значение разрешает только bootstrap `SMTP_HOST:SMTP_PORT`. Пример: `smtp.example.com:587,relay.internal:2525`. Смена allowlist требует deployment/restart и согласования всех экземпляров **до** изменения destination в API. Запрещённый host/port отклоняется до сетевых обращений, в том числе при delivery/startup. Нет произвольных URLs, HTTP probes или клиентского адреса в connection-test.

Allowlist — граница доверия оператора, не автоматическое разрешение всех внутренних сетей. Он сознательно разрешает выбранные внутренние relay. Защиту DNS/маршрутизации и сетевой egress обеспечивает deployment; hostname не pin-ится к одному IP навсегда. В production обязательны STARTTLS с проверкой certificate chain/hostname и TLS >=1.2, без insecure-skip-verify и plaintext fallback. TLS requirement нельзя снять через API. Implicit TLS/порт 465 в этом блоке не добавлен: действующий транспорт — STARTTLS.

## API

Все три ручки требуют разрешённый HTTPS Origin, live session и актуальное `auth.settings.manage`, используют no-store/no-refresh. UUID/hash оператора из JSON не принимаются. GET не требует fresh proof. POST update/test дополнительно требует enrolled factor и fresh password+MFA в транзакции и публикуется только при включённом deployment MFA.

### GET /api/v1/admin/auth/settings/smtp

```json
{
  "version": 1,
  "config": {
    "host": "smtp.example.com",
    "port": 587,
    "username": "auth@example.com",
    "from": "auth@example.com",
    "domain": "example.com",
    "requireTls": true
  },
  "passwordSet": true
}
```

`passwordSet` означает только наличие секрета. Это не успешная аутентификация SMTP, проверка доставки или готовность остальных узлов. Username/адреса — не-секретные operational поля, доступны только управляющему разрешению.

### POST /api/v1/admin/auth/settings/smtp

```json
{
  "expectedVersion": 1,
  "config": {
    "host": "smtp.example.com",
    "port": 587,
    "username": "auth@example.com",
    "from": "auth@example.com",
    "domain": "example.com",
    "requireTls": true
  },
  "password": "NEW_SECRET"
}
```

Полная замена config; `requireTls` обязателен, включая явный false вне production. Остальные поля проходят domain/service validation один раз. Неизвестные поля/типы, лишнее JSON-значение, null config или пропущенный requireTls → `400 invalid_json`. Username может быть пустым для trusted relay без AUTH. From — mailbox без display name; строки ограничены, CR/LF/NUL отклоняются.

- Password отсутствует или null: сохранить прежний. No-op с тем же config/version не меняет version/audit.
- Password задан непустой строкой: зашифровать и заменить. Даже повтор того же значения считается явной rotation и повышает version; digest секрета для оптимизации сравнения не хранится.
- Password `""`: явная очистка, допустима только при пустом username. Для authenticated SMTP пустой секрет отклоняется.
- Смена host/port/username требует явного password, чтобы прежний секрет не отправился новому получателю автоматически. Для relay без AUTH передать `""` и пустой username.

Access lock → current actor/session/permissions/password/MFA → SMTP row/version → update+audit → commit. Ошибка аудита откатывает config/secret/version. Audit хранит только предыдущий/следующий `SMTPSnapshot` без ciphertext. SQL transaction не делает сетевых проверок. Старая expectedVersion → `409 smtp_settings_conflict`, без автоматического overwrite. Успех возвращает тот же безопасный формат, что GET.

### POST /api/v1/admin/auth/settings/smtp/test

Тело `{"expectedVersion":2}`. Проверяется **сохранённая** авторизованная версия; ввод произвольного host/password/recipient не принимается. После commit авторизации освобождены SQL/Access/user locks, затем выполняются greeting, STARTTLS/certificate/AUTH, NOOP и QUIT. Нет MAIL/RCPT/DATA, писем и OTP на клиентский адрес.

Успех: `200 {"testedVersion":2,"status":"connected"}`. Это результат данного обращения, не проверка реальной доставки, From, домена отправителя, spam reputation или fleet readiness. Тест не сохраняет «проверено навсегда». Если настройки менялись параллельно после авторизации, результат относится к testedVersion, не к более новой версии; UI перечитывает текущую version.

Общий deadline 10 секунд, TCP dial до 5 секунд, до двух tests одновременно на экземпляр, Redis лимиты 3/operator/minute и 10/project/minute. Redis outage — fail-closed до SMTP. Credentials не попадают в публичную ошибку SMTP или логи transport. Результат не создаёт новую session/cookie/audit row с network payload.

Общие ошибки: `401` — session; `403 forbidden`/`fresh_auth_required`/Origin; `400 invalid_smtp_settings`; `409 smtp_settings_conflict`/`smtp_connection_failed`; `429 rate_limited` с Retry-After; зависимости/невозможность decrypt — `503 temporarily_unavailable` без деталей.

## Применение, rotation и границы

Все mail workers Auth используют один mailer с сохранённым source. **Каждая новая отправка/повтор** читает singleton и расшифровывает текущий пароль: один indexed SQL read, без Redis cache, polling, новых workers/pools или query на каждом session request. Все экземпляры с одинаковыми root key/allowlist видят latest committed settings при следующем send. Пулы и существующие delivery budgets по-прежнему общие; RPS всего сервиса не измерялся этим шагом.

Уже начатая отправка может закончиться с прежней конфигурацией в пределах своего 20s deadline. Поэтому provider-side rotation планируется с overlap либо допустимым retry старых попыток; success сохранения не отзывает SMTP credential у внешнего provider. Существующие outbox retry/expiry/leases сохраняются, новый retry загрузит свежую запись. Переключение на неверный relay может временно остановить security mail; сначала проверить новую конфигурацию и реальную доставку на разрешённом стенде, при отказе вернуть прежний config новой version. Прежний пароль сервер не отдаёт: для rollback оператору нужен сохранённый безопасно секрет.

## Перенос и приёмка

Изменены только исходные `000001_init.up/down.sql` для новой установки: `smtp_settings`, `smtp_settings_audit`, bounded/indexed audit retention. Рабочая БД не мигрировалась. Для уже initialized installation требуются separately approved schema/grants/encrypted bootstrap и согласованный rollout **до трафика**. Автоматическое удаление setup marker/сброс базы/ENV reseed не являются upgrade; готового maintenance bootstrap CLI этот блок не добавляет. Mixed fleet с прежними ENV-only writers не поддерживается.

Локальные unit/HTTP/SQL/Redis/race проверки включают versions/no-op/rotation/audit rollback/concurrent winner, два credential consumers, проверку отсутствия Access lock во время probe, no-refresh/Origin/JSON guards, encryption failure/fail-closed, bounded probes и SMTP NOOP без письма. Настоящие provider credentials/доставка/TLS relay/DNS/egress/fleet/browser/restore/load/GC остаются pre-ui/A8 NOT RUN. Следующий блок — A6.3c.2 provider settings с явным binding credentials revision к pending OIDC flows, не переписывание SMTP под гипотетический framework.
