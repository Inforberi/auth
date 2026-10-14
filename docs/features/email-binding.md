# Первая привязка почты к Google/Telegram-аккаунту

## Назначение и границы

A5.2d-local реализует контролируемую администратором первую привязку: администратор разрешает конкретный адрес для конкретного UUID, владелец аккаунта доказывает доступ к почте. Это не автоматический импорт provider email, не объединение пользователей, не passwordless регистрация и не восстановление потерянного MFA.

Требуется active external-only аккаунт с linked identity, без любых email contacts, password/temporary credentials и pending provisioning. Для аккаунта с уже имеющимся адресом этот API не заменяет verification или email change. Администратор отвечает за проверку того, что запрашиваемая привязка действительно согласована с владельцем выбранного UUID: серверная permission не способна автоматически подтвердить сведения из обращения в поддержку. Самостоятельного выбора новой доверенной почты одним владельцем session cookie нет.

Первый администратор/его MFA/role assignment должны быть настроены защищённым workflow. Этот API не создаёт первого администратора и не открывает bootstrap bypass; first-run setup/operator recovery остаются отдельными задачами. Новый permission не назначается автоматически существующим ролям.

## Конфигурация

| ENV | Default | Назначение |
| --- | --- | --- |
| `EMAIL_BINDING_ENABLED` | `false` | Включение обеих ручек и доставки pending binding |
| `EMAIL_BINDING_TTL` | `5m` | Максимальный срок intent, допустимо 1–5 минут |
| `EMAIL_BINDING_REQUESTS_PER_MINUTE` | `100` | Общий request admission установки в минуту |
| `EMAIL_BINDING_CONFIRMATIONS_PER_MINUTE` | `1000` | Общий confirm admission установки в минуту |

Дополнительно нужны `MFA_ENABLED=true` и `EMAIL_REAUTHENTICATION_ENABLED=true`. `EMAIL_OTP_ENABLED` не требуется и не включается автоматически. Флаги пока startup ENV, сохраняемые настройки — A6. Изменение source migration не обновляет уже работающую БД: требуется согласованный upgrade, не reset.

## Администратор разрешает привязку

`POST /api/v1/admin/users/{id}/email-binding`

Session cookie администратора, разрешённый HTTPS Origin, `Content-Type: application/json`:

```json
{"email":"owner@example.com"}
```

`id` — точный UUID пользователя, не issuer/subject/email и не основание авторизации. Actor UUID/hash берутся из SQL-validated session context; `actorId`, `verified`, роли и другие дополнительные JSON-поля отвергаются.

SQL проверяет актуальное `accounts.email.bind`, active/nondeleted actor, текущую действующую сессию той же auth_version, password и MFA proofs не старше пяти минут и существующий фактор. Администратор не подтверждает собственную привязку этим маршрутом. Все проверки повторяются внутри транзакции после общего Access lock, users блокируются в стабильном порядке. Из неё возвращается deadline, ограниченный также свежестью proofs/сроком сессии администратора.

Ответ `202` содержит только `expiresAt`; код или verifier администратору не возвращаются. В pending intent сохраняются target UUID/version, approved email, actor/session binding, keyed verifier восьмизначного случайного кода и encrypted mail payload. Секреты не попадают в аудит/URL. Создаётся audit `email_binding_issued`. Адрес не добавляется в user_emails и не резервируется: другой пользователь не блокируется незавершённой привязкой.

Один pending intent на target. Повторный успешный request заменяет код и delivery lease/ID; старый ack не подтверждает новую отправку. Действует три запроса/target за 15 минут, 30/actor и 30/IP в минуту, плюс project budget. Перед маленьким target budget выполняется indexed permission preflight, чтобы посторонний caller не мог исчерпать его запросами без прав. Это только admission; authoritative проверка всё равно проходит под SQL locks. Redis не вызывается внутри транзакции, его ошибка закрывает операцию.

## Владелец подтверждает почту

`POST /api/v1/auth/email/binding/confirm`

Нужны session cookie самого target и разрешённый Origin:

```json
{"code":"12345678"}
```

Owner UUID/token hash/version берутся из текущей сессии, не из JSON или ссылки. Почтового кода без входа в аккаунт недостаточно. Если MFA уже есть, у owner session нужен MFA proof не старше пяти минут; при устаревшем proof можно войти заново через провайдера с существующим фактором. Код не заменяет TOTP/recovery и не снимает MFA.

Транзакция заново проверяет живой pending intent, того же approver/session, его текущие права/password/MFA/factor, status/version и eligibility target, owner session и текущий фактор. Logout/rotation/отзыв прав или истечение proof администратора не оставляют вечного разрешения. Неверный код увеличивает committed attempts, а не откатывает счётчик. Максимум пять попыток/intent и пять/user/minute, плюс 20/IP и project budget; reissue не расширяет account-wide guessing budget.

Успех одной транзакцией:

- создаёт verified contact у прежнего UUID; UNIQUE email остаётся окончательной защитой конфликта;
- повышает auth_version и отзывает все сессии target;
- удаляет pending binding/enrollment/login challenges, не удаляя действующий фактор/recovery codes;
- пишет `email_bound` с actor и новой version в существующий security audit.

Ответ `200 {"status":"ok"}` очищает session cookie владельца. Это не login endpoint. Нужно войти снова через Google/Telegram, затем для MFA management получить новый session-bound email proof по [A5.2c](mfa.md#подтверждение-управления-mfa-по-почте-a52c-local). Код первичной привязки нельзя использовать для email login или MFA reauthentication. Роли/credentials автоматически не создаются.

Если письмо/ответ потерялись, администратор запрашивает новый intent с учётом лимитов. После успешного binding повторный confirm не выдаёт authority; после lost response можно войти снова и проверить состояние аккаунта. При ошибке audit/SQL все изменения откатываются, прежняя session и intent сохраняются. При конфликте email пользователь остаётся отдельным аккаунтом; менять target/склеивать UUID запрещено.

## Доставка, cleanup, ошибки

Одна таблица `email_bindings` совмещает короткоживущий intent и transactional mail job: отдельные code attempts и delivery attempts/lease/delivered_at. Письмо отправляет прежний account delivery runner, fair queue selection — только при enabled профиле. SMTP deadlines/connection policy, PostgreSQL pool и encrypted emailMessage переиспользованы; нового worker, пула или root secret нет. До пяти отправок с существующим backoff и ack только текущего lease. Доставка повторно проверяет status/version/approval. Retention удаляет expired intents индексируемыми bounded batches; account deletion убирает собственный pending intent. Security audit хранится по общей политике.

Все ответы `no-store`; GET не меняет состояние. Неуспешные запросы не меняют cookies. Ошибки: `invalid_json`/`invalid_email`/`invalid_email_binding` 400; `unauthorized` 401; `forbidden`/`fresh_auth_required`/`invalid_origin` 403; `email_binding_conflict` 409; `rate_limited` 429; dependency failure 503. Disabled routes отсутствуют (404). Ошибка owner confirm из-за недействительного approval не раскрывает детали сессии администратора.

Локальные service/API/SQL/race тесты не заменяют реальные SMTP/browser/provider acceptance, multi-instance/fault/load/GC и first-admin bootstrap. Самостоятельный onboarding без оператора, смена существующего адреса external-only и общий admin users/roles API этим подэтапом не объявляются реализованными.
