# Первый супер-администратор

Backend 10.3a-local. UI-мастер будет отдельным этапом; уже сейчас доступны две opt-in ручки. Это первоначальная настройка новой установки, не обычная регистрация, назначение роли существующему пользователю или восстановление потерянного администратора.

## Условия включения

```dotenv
INITIAL_SETUP_ENABLED=true
INITIAL_SETUP_SECRET=<32 случайных байта в base64url без padding>
MFA_ENABLED=true
```

В examples setup выключен, готового секрета или default password нет. Оператор генерирует секрет установки через надёжный CSPRNG и хранит его вне Git. На всех экземплярах одной установки нужен одинаковый секрет. Он не должен совпадать с `EMAIL_OUTBOX_KEY`: ключ шифрования никогда не передаётся браузеру. SMTP, root encryption key, HTTPS и разрешённый Origin настраиваются существующими параметрами.

Секрет передаётся только в `X-Setup-Token` обеих ручек. Не помещать его в URL, telemetry, логи reverse proxy, localStorage или документацию. Будущий UI получает его от оператора и держит только в памяти на время настройки. Сам факт посещения страницы не даёт права создать администратора.

После завершения оператор удаляет секрет из окружения и выключает `INITIAL_SETUP_ENABLED`. Маркер в БД закрывает setup и при оставленном флаге/секрете. При выключенном флаге или MFA routes не зарегистрированы (404). При уже завершённой настройке авторизованный setup-запрос получает `setup_closed` (404).

## 1. Начать настройку

`POST /api/v1/setup/start`

Заголовки: `Content-Type: application/json`, разрешённый `Origin`, `X-Setup-Token`.

```json
{"email":"owner@example.com","password":"<новый пароль>"}
```

Проверяются операторский секрет, открытость установки, email и существующая password policy. Пароль хешируется общим bounded Argon2id. Генерируются будущий UUID, 256-bit setup token, восьмизначный email-код и новый TOTP secret. В одной singleton-записи БД хранится только зашифрованный intent: email, hash пароля, TOTP secret и HMAC проверочного кода; самого пользователя ещё нет.

На почту отправляется код. Ответ 202:

```json
{"token":"<setup token>","secret":"<TOTP secret>","uri":"otpauth://totp/...","expiresAt":"<UTC timestamp>"}
```

`secret`/`uri` предназначены для добавления в authenticator. Они и token — секретные данные; `Cache-Control: no-store`, сессия и cookies не выдаются. Email-код отсутствует в HTTP-ответе.

Срок intent — 10 минут. Повторный start разрешён не раньше чем через минуту и заменяет предыдущие token/email-code/TOTP secret; старое подтверждение больше не работает. Использовать один мастер настройки, а не несколько вкладок одновременно. Не смешивать коды от разных попыток.

Почта отправляется синхронно в пределах 9-second service deadline и общего HTTP timeout; внешние зависимости не вызываются под SQL locks. Для этого одноразового процесса нет отдельной очереди/worker/pool. При SMTP error/timeout возвращается 503, пользователь не создан; pending intent остаётся ограниченным TTL. Явный повтор start через минуту создаёт новый intent. Timeout не доказывает, что письмо не доставлено: поздний старый код всё равно относится к старому token.

## 2. Завершить настройку

`POST /api/v1/setup/complete`, те же заголовки.

```json
{"token":"<из start>","emailCode":"12345678","totp":"123456"}
```

Не принимаются user ID, role, permissions, verified flag или session authority от клиента. Проверяются текущий операторский секрет, intent, его TTL, email-код и TOTP. Неправильный корректно оформленный email/TOTP-код увеличивает сохранённый счётчик; после пяти ошибок intent нельзя завершить. Неверный token не расходует попытки чужого intent. Некорректный формат отклоняется до SQL completion.

Одна Read Committed транзакция под общим Access lock и singleton row lock:

1. Заново проверяет отсутствие initialized marker и существующей системной роли.
2. Проверяет intent/operator binding, TTL и число попыток.
3. Проверяет email/TOTP и сохраняет потреблённый TOTP step для защиты от replay.
4. Создаёт active пользователя, профиль, verified email, password credentials, TOTP и 10 recovery code digests.
5. Создаёт `super_admin` и выдаёт пять core permissions: `access.roles.manage`, `access.assignments.manage`, `accounts.email.bind`, `accounts.users.manage`, `accounts.users.read`. Это только новая установка; сохранённые системные назначения при обновлении автоматически не расширяются.
6. Сохраняет role grant audit и MFA audit, initialized timestamp/UUID первого администратора; удаляет pending secrets/operator/request hashes.

Ответ 200:

```json
{"recoveryCodes":["<10 одноразовых кодов>"]}
```

Коды нужно сохранить безопасно. Сервис хранит только owner-bound digests, не исходные recovery codes. Ответ не выдаёт login session. Далее обычный парольный вход → общий MFA challenge → authenticator/recovery code → обычная SQL session. TOTP, использованный для setup, нельзя повторно потребить при входе: дождитесь следующего кода либо используйте recovery code.

Если успешный ответ с recovery codes потерян, completion не повторяет выдачу: setup уже закрыт. Можно войти с паролем и authenticator и заново сгенерировать recovery codes через существующий защищённый MFA management. Потеря одновременно всех факторов — отдельный operator recovery, ещё не реализованный в этом этапе.

## Ошибки и ограничения

| HTTP | Code | Причина |
| --- | --- | --- |
| 400 | invalid_json | Неверный JSON/неизвестные поля |
| 400 | invalid_email / invalid_password | Email/password policy |
| 400 | invalid_setup | Неверный/истёкший intent, исчерпанные попытки или код |
| 403 | setup_unauthorized | Нет корректного операторского секрета |
| 403 | invalid_origin | Не разрешён Origin |
| 404 | setup_closed | Настройка недоступна/завершена |
| 409 | setup_conflict | Cooldown, другой pinned operator или занятый email |
| 429 | rate_limited | Redis admission, Retry-After: 60 |
| 503 | temporarily_unavailable | SQL/Redis/SMTP/hash capacity/timeout |

Для start и complete отдельно: 10 запросов/IP/минуту и 30/установку/минуту, fail-closed при недоступном Redis. SQL cooldown ограничивает reissue до одного в минуту, intent имеет пять попыток. Это operational budgets одноразового setup, не RPS обычного auth. Общие HTTP admission/JSON bounds/Argon2 concurrency сохраняются; новых dependencies/фоновый tasks нет.

В singleton до completion закрепляется digest операторского секрета. Разные deployment secrets на репликах не перехватывают pending setup. Не менять этот секрет посреди установки; утеря его до completion требует отдельного операторского решения, автоматического env override нет. Retention удаляет истёкший encrypted payload и request hash, но сохраняет operator pin и initialized marker.

Email до completion не резервируется. Конкурирующая регистрация того же адреса может привести к 409; аккаунты не объединяются, существующий пользователь не повышается до admin. Выберите свободный адрес. UNIQUE contact constraint и rollback сохраняются.

Marker не зависит от наличия роли/активного администратора. Restart, удаление cookies, потеря роли, блокировка или удаление пользователя не открывают setup. Даже БД с прежней системной ролью без marker не принимается за новую установку. Нет публичного reset marker или startup admin/password override. Backup/restore должен сохранять marker; direct SQL reset не является поддерживаемым recovery.

Системная роль не wildcard: пользовательские permissions добавляются через отдельное управление ролями. Для потерянного пароля доступна [операторская CLI](admin-recovery.md), которая не открывает setup и не отключает MFA. Полный protected users/roles API, settings/UI и lost-factor восстановление остаются следующими этапами.

## Проверки и границы

Unit/HTTP проверки покрывают admission/валидацию/SMTP failure/закрытый setup, Origin, disabled profiles, отсутствие cookies и client-supplied authority. Disposable PostgreSQL проверки покрывают committed wrong attempts, expiry/cooldown/operator pin, UNIQUE conflict без merge, audit rollback, 16 конкурентных completions/один winner, marker после потери admin и совместимость setup с обычным password/MFA login. Реальные SMTP/browser/authenticator, multi-instance fault/load/GC и операторский runbook относятся к release acceptance, а не подтверждены этими локальными тестами.
