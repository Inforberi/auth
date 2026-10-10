# Смена login email — этап 5.5

Backend request/confirm/report реализован. Восстановление после защитной блокировки (5.5d), frontend и внешняя почтовая/browser приёмка ещё не реализованы. По умолчанию `EMAIL_CHANGE_ENABLED=false`: приложение не подключает эти маршруты, остальные методы входа продолжают работать. Включение для production до закрытия зависимостей не согласовано.

## Настройки и API

При включении нужны `EMAIL_CHANGE_URL` и `EMAIL_CHANGE_REPORT_URL`: доверенные frontend-страницы без query/fragment/credentials, HTTPS в production. `EMAIL_CHANGE_TTL=30m` ограничивает подтверждение; `EMAIL_CHANGE_PROTECTION_TTL=24h` — защитное действие, считая от запроса, не завершения. Bounds: подтверждение 1m–1h, защита минимум два TTL подтверждения и максимум 48h. Secrets существующие: `EMAIL_OUTBOX_KEY` для AES-GCM и HMAC limiter keys, SMTP и Redis. Настоящие env/secrets не менялись.

| POST | Тело | Успех |
| --- | --- | --- |
| `/api/v1/auth/email/change` | `email`, `password` | 202 `status: accepted` |
| `/api/v1/auth/email/change/confirm` | `token` | 200 `status: ok`, очистка cookie |
| `/api/v1/auth/email/change/report` | `token` | 200 `status: ok`, очистка cookie |

Все три ручки требуют один точный `Origin` из `AUTH_ALLOWED_ORIGINS`; ответы `no-store`. Request дополнительно требует текущую сессию. Confirm/report не требуют cookie браузера, открывшего письмо: полномочие даёт соответствующий токен. Для confirm сервер повторно проверяет исходную сессию из запроса, её сроки/version/revocation. Для report скомпрометированная сессия не нужна.

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

Дополнительные смены, обычное изменение пароля/logout-all **не аннулируют защиту завершённой смены**: иначе атакующий мог бы отключить предупреждение. 5.5d должен определить отдельный проверенный recovery transition: доказательство владения account, замена скомпрометированных credentials, выбор безопасного адреса, инвалидирование прежних защитных полномочий и только затем unblock. Владение новым адресом атакующего не является доказательством владельца. Публичного recovery-unblock сейчас нет; полный этап 5.5 и release не закрыты.

## Доставка и проверки

Существующий account worker/mailer обслуживает verification и отдельный `email_change_outbox`; новые workers/scripts не добавлялись. Очереди чередуются; disabled worker не обращается к change tables. Lease 30s, bounded retry/backoff, максимум 5 attempts, acknowledgement только с текущим lease. Просроченные intents/payload удаляются порциями до 100 строк, audit сохраняется. In-flight письмо может дойти после отмены, но токен уже недействителен. Сбой доставки не откатывает ранее committed request: внешняя приёмка обязательна.

Unit/HTTP tests: service-only validation, credential handoff, разные токены/encrypted payloads, delivery reuse, limiter fail-closed, errors/cookie cleanup, Origin/no-store/disabled routes и отсутствие GET mutations. SQL suite: up/down/up, confirm/report/replay, cancellation, occupied email после request, expiry/stale session/hash, block/unblock, concurrent confirm/report и duplicate confirm, audit/outbox rollback, delivery retry/stale lease/expiry/fairness. Это локальные проверки, не нагрузка, настоящий SMTP или browser E2E.

000001 расширена как на предыдущих локальных этапах. Уже применённая миграция не обновит рабочую БД: перенос существующего deployment требует отдельного согласования. Рабочая БД не сбрасывалась.
