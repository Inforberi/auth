# Смена login email — этап 5.5

Backend request/confirm/report и восстановление password-профиля после защитной блокировки (5.5d) реализованы и локально проверены. Frontend и внешняя почтовая/browser приёмка ещё не реализованы. По умолчанию `EMAIL_CHANGE_ENABLED=false`: приложение не подключает эти маршруты, остальные методы входа продолжают работать. Включение для production до закрытия 5.5e и release gates не согласовано.

## Настройки и API

При включении нужны `EMAIL_CHANGE_URL`, `EMAIL_CHANGE_REPORT_URL` и `EMAIL_CHANGE_RECOVERY_URL`: доверенные frontend-страницы без query/fragment/credentials, HTTPS в production. `EMAIL_CHANGE_TTL=30m` ограничивает подтверждение; `EMAIL_CHANGE_PROTECTION_TTL=24h` — защитное действие, считая от запроса, не завершения. `EMAIL_CHANGE_RECOVERY_TTL=30m` начинается после защитной блокировки. Bounds: подтверждение и recovery 1m–1h, защита минимум два TTL подтверждения и максимум 48h. Secrets существующие: `EMAIL_OUTBOX_KEY` для AES-GCM и HMAC limiter keys, SMTP и Redis. Настоящие env/secrets не менялись.

| POST | Тело | Успех |
| --- | --- | --- |
| `/api/v1/auth/email/change` | `email`, `password` | 202 `status: accepted` |
| `/api/v1/auth/email/change/confirm` | `token` | 200 `status: ok`, очистка cookie |
| `/api/v1/auth/email/change/report` | `token` | 200 `status: ok`, очистка cookie |
| `/api/v1/auth/email/change/recover` | `token`, `newPassword`, `confirmPassword` | 200 `status: ok`, очистка cookie |

Все четыре ручки требуют один точный `Origin` из `AUTH_ALLOWED_ORIGINS`; ответы `no-store`. Request дополнительно требует текущую сессию. Confirm/report/recover не требуют cookie браузера, открывшего письмо: полномочие даёт соответствующий токен. Для confirm сервер повторно проверяет исходную сессию из запроса, её сроки/version/revocation. Для report/recover скомпрометированная сессия не нужна.

Ссылки содержат `#token=...`: fragment не передаётся серверу при загрузке страницы. Будущий frontend извлекает токен, убирает его из URL, не передаёт analytics и отправляет JSON POST только после нажатия кнопки; странице нужны `Referrer-Policy: no-referrer` и `Cache-Control: no-store`. GET API ничего не меняет и не существует. Frontend не добавлялся; URL в примере — контракт подключения, не работающая страница.

Формат JSON проверяет HTTP, email и password input bounds — service. Общий mapper использует локальные rules: 400 `invalid_json`/`invalid_email`/`invalid_email_change`; 401 `unauthorized`/`fresh_auth_required`; 403 `invalid_origin`; 409 `email_change_pending`; 429 `rate_limited`; 503 `temporarily_unavailable`. Зависимостные детали/password/email/token не логируются и не возвращаются.

## Последовательность

1. Пользователь вводит новый адрес и текущий пароль. Поддержан password-профиль с подтверждённым нынешним login email. Неподтверждённый старый контакт, OAuth-only/OTP/MFA-only fresh-auth требуют собственного доказательства и не получают password bypass.
2. Service один раз разбирает email, применяет Redis limits (5 запросов/user/hour, 20/IP/minute), читает credential snapshot и сравнивает пароль. Транзакция блокирует user, повторно проверяет snapshot/hash/version, действующую session и владение подтверждённым адресом.
3. Два независимых 256-bit токена хранятся только как SHA-256 digest; raw токены присутствуют исключительно в зашифрованных payload писем. Новому адресу идёт подтверждение, старому — «Это не я». Request/audit/два mail intents атомарны. Pending запрос нельзя заменить новым: 409 сохраняет защитную ссылку. После expiry допускается новый запрос; expired pending переводится в `expired`.
4. Confirm сериализуется по user и повторно проверяет state/expiry/credential/session. Request не резервирует новый адрес: окончательную уникальность обеспечивает SQL constraint. Занятый позже email даёт нейтральный отказ без изменения аккаунтов.
5. Создаётся новый verified contact; password credential переводится на него. Старый подтверждённый контакт остаётся у пользователя, но не служит login email по паролю и не освобождается для чужой регистрации. Освобождение/удаление старых контактов — retention policy 5.6.
6. Confirm увеличивает `auth_version`, отзывает все сессии, удаляет reset/verification challenges и отменяет pending changes. Audit и письмо старому адресу о завершении входят в ту же транзакцию. Сессия не создаётся; следующий login по новому email. Защитный токен завершённой смены остаётся действующим в исходном protection window.

## «Это не я»

До завершения report отменяет pending запрос и отзывает все сессии с version bump/challenge cleanup. Email и пароль не меняются, account остаётся active. Это **не обезвреживает украденный пароль**; требуется отдельное безопасное восстановление.

После завершения report блокирует account, повышает version и отзывает сессии/challenges. Email не откатывается, password не меняется, unblock/login не выполняются. Остальные completed protection intents пользователя тоже помечаются reported: после восстановления прежние ссылки не должны снова блокировать account.

Confirm/report блокируют user в одном порядке и перечитывают intent. Если report первым, confirm отклонён; если confirm первым, report блокирует account. Ошибка audit откатывает всё; ошибка completion outbox откатывает confirm. Confirm token не годится для report и наоборот. Внутренний StatusService block/unblock отменяет pending/completed intents и confirm jobs; это не разрешение на административный HTTP bypass.

Дополнительные смены, обычное изменение пароля/logout-all **не аннулируют защиту завершённой смены**: иначе атакующий мог бы отключить предупреждение. Владение новым адресом атакующего не является доказательством владельца; обычный reset не разблокирует account.

## Защищённое восстановление — 5.5d

Поддержан только текущий password-профиль с доступом владельца к прежнему подтверждённому адресу. После report завершённой смены на этот адрес ставится отдельное зашифрованное письмо с независимым 256-bit recovery-токеном. Он заранее подготовлен вместе с intent, но не выдаётся в notice/completion и не действует до report: SQL привязывает его к версии блокировки и назначает срок. Токен не возвращается HTTP-клиенту report; только digest находится в challenge columns. Confirm/report токены не могут восстановить аккаунт.

Владелец открывает страницу recovery и явно отправляет POST с новым паролем и его подтверждением. Пароль проходит существующую политику и должен отличаться от скомпрометированного. Service проверяет актуальный recovery до дорогого hash; SQL повторно проверяет authority и прочитанный hash под user lock. Redis failure закрывает операцию; 10/IP/min и общий reset budget 100/min, те же два hash slots на процесс, deadline 10s. Hash comparison failure не считается успешным доказательством смены пароля.

Один commit заменяет пароль, возвращает credential на прежний owned verified contact, снимает verification с остальных контактов, увеличивает auth_version, отзывает все сессии/challenges, инвалидирует все прежние change/report/recovery intents и их jobs, записывает `recovered`, затем оставляет аккаунт active. Другие адреса не удаляются и не освобождаются для регистрации. Вход автоматически не выполняется. SQL/audit failure откатывает весь transition; recovery outbox failure откатывает report.

Административный StatusService отменяет recovery authority, в том числе при повторном block уже заблокированного account. Его status/version no-op остаётся no-op, но отмена recovery записывается в email-change audit. Recovery не отменяет deleted/admin block и не возрождает прежнюю сессию. До завершения смены report оставляет прежний login email: для замены украденного пароля применяется обычный reset, не recovery-unblock.

Неподдержанные случаи не получают bypass: потерянная/скомпрометированная старая почта, просроченный recovery, исчерпанная доставка и intents без recovery authority требуют отдельно согласованного восстановления; публичной повторной выдачи или общего unblock нет. Mailbox-only proof нельзя автоматически переносить на будущие MFA/OIDC/Telegram профили: их recovery policy и отзыв credentials нужно определить перед подключением. 5.5e включает внешнюю доставку, browser flow, полную lifecycle race matrix и операционные ограничения; весь этап 5.5 и production release не закрыты.

## Доставка и проверки

Существующий account worker/mailer обслуживает verification и отдельный `email_change_outbox`; новые workers/scripts не добавлялись. Очереди чередуются; disabled worker не обращается к change tables. Lease 30s, bounded retry/backoff, максимум 5 attempts, acknowledgement только с текущим lease. Просроченные intents/payload удаляются порциями до 100 строк, audit сохраняется. In-flight письмо может дойти после отмены, но токен уже недействителен. Сбой доставки не откатывает ранее committed request: внешняя приёмка обязательна.

Unit/HTTP tests: service-only validation, credential handoff, разные токены/encrypted payloads, delivery reuse, limiter fail-closed, errors/cookie cleanup, Origin/no-store/disabled routes и отсутствие GET mutations. SQL suite: up/down/up, confirm/report/replay, cancellation, occupied email после request, expiry/stale session/hash, block/unblock, concurrent confirm/report и duplicate confirm, audit/outbox rollback, delivery retry/stale lease/expiry/fairness. Это локальные проверки, не нагрузка, настоящий SMTP или browser E2E.

Recovery columns, constraints, owner index, outbox kind и audit event включены в исходную 000001. До первого release отдельные промежуточные миграции не создаём. Уже применённая старая 000001 не обновится автоматически: для существующей БД нужен согласованный перенос. Intents с NULL recovery fields не дают recovery authority. Рабочая БД не сбрасывалась и миграции на ней не запускались.

Проверки 5.5d: formatter, `task check` (тесты и lint, 0 issues), Swagger generation/drift, SQL up/down/up 000001 на отдельном PostgreSQL 18.6. Дополнительно проверены purpose/unissued/replay, expiry/version/hash/deleted/contact guards, одноразовый concurrent consume, admin re-block, audit/outbox rollback, retention near protection expiry и legacy intent. Временный контейнер с тестовыми данными удалён; SMTP/browser E2E и нагрузка не выполнялись.

Локальная приёмка 5.5e, 10 октября: `protected recovery races` проверяет recovery против административного block/unblock до, после и одновременно. Если recovery уже повысил version, прежняя административная команда получает conflict: для повторной блокировки нужен явный retry с новой version. Если административная команда первая, recovery authority отменена, включая block без смены status/version. Дополнены stale session/password/reset/confirm/report, восстановление по защите более ранней смены и duplicate report.

`protected recovery delivery` проверяет настоящий SQL outbox и account worker с зашифрованным payload; SMTP заменён управляемым mailer double. Проверены старый адрес получателя, backoff 30/60s, смена lease после сбоя worker, безопасный stale acknowledgement, отмена уже взятого job, максимум пять попыток и expiry. Успешная отправка не потребляет recovery authority; исчерпание попыток или expiry не разблокируют account. Поздний acknowledgement не восстанавливает отменённый job. Это не тест внешнего SMTP и не гарантия доставки exactly-once: при сбое после отправки до acknowledgement возможно повторное письмо с тем же одноразовым токеном.

Formatter, `task check` и весь `TestPostgresSchema` на disposable PostgreSQL 18.6 пройдены. Runtime/schema/API не менялись. 5.5e-local закрыт; 5.5e-staging с настоящей почтой, браузером и операционными процедурами остаётся открытым. Далее backend 5.6.
