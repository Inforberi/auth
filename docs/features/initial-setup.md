# Первый супер-администратор

Для multi-project отдельно реализован [подготовительный stage](project-onboarding-preparation.md): generated project setup secret остаётся encrypted в каталоге, его digest pinned в проектной БД вместе с безопасными settings. Сам stage не включает эти routes, не создаёт администратора и не выдаёт token браузеру. По уточнению21 октября владелец платформы управляет новыми проектами через будущий guarded bridge без копии identity/выдачи setup secret/обязательного первого local super_admin. Описанный ниже flow относится к standalone first-install; его guards не меняются и не становятся обязательным мастером каждого owner-managed проекта.

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
{"email":"owner@example.com","password":"<новый пароль>","mfaMode":"required"}
```

Проверяются операторский секрет, открытость установки, режим MFA, email и существующая password policy. Пароль хешируется общим bounded Argon2id. Генерируются будущий UUID, 256-bit setup token и восьмизначный email-код. В одной singleton-записи БД хранится только зашифрованный intent: выбранный режим, email, hash пароля, TOTP secret при необходимости и HMAC проверочного кода; самого пользователя ещё нет.

`mfaMode`: `optional` — владелец создаётся без фактора; `administrators` — MFA обязательна для административных прав; `required` — обязательна для всех пользователей realm. Без поля сохраняется `administrators`, как у прежнего setup. В двух последних режимах владелец подтверждает TOTP до завершения. Режим закреплён операторским proof и encrypted intent; `/complete` не принимает `mfaMode`. Новый start после cooldown заменяет весь intent, включая режим и коды. Это настройка только текущей БД: платформа не меняет настройки соседних проектов.

На почту отправляется код. Ответ 202:

```json
{"token":"<setup token>","secret":"<TOTP secret>","uri":"otpauth://totp/...","expiresAt":"<UTC timestamp>"}
```

`secret`/`uri` предназначены для добавления в authenticator; в `optional` оба поля отсутствуют и TOTP secret не генерируется. Они и token — секретные данные; `Cache-Control: no-store`, сессия и cookies не выдаются. Email-код отсутствует в HTTP-ответе. Техническая MFA capability пока должна быть включена даже для optional setup; её deployment/readiness matrix — следующий блок, а не скрытое требование подключить фактор пользователю.

Срок intent — 10 минут. Повторный start разрешён не раньше чем через минуту и заменяет предыдущие token/email-code/TOTP secret; старое подтверждение больше не работает. Использовать один мастер настройки, а не несколько вкладок одновременно. Не смешивать коды от разных попыток.

Почта отправляется синхронно в пределах 9-second service deadline и общего HTTP timeout; внешние зависимости не вызываются под SQL locks. Для этого одноразового процесса нет отдельной очереди/worker/pool. При SMTP error/timeout возвращается 503, пользователь не создан; pending intent остаётся ограниченным TTL. Явный повтор start через минуту создаёт новый intent. Timeout не доказывает, что письмо не доставлено: поздний старый код всё равно относится к старому token.

## 2. Завершить настройку

`POST /api/v1/setup/complete`, те же заголовки.

```json
{"token":"<из start>","emailCode":"12345678","totp":"123456"}
```

Не принимаются user ID, role, permissions, режим MFA, verified flag или session authority от клиента. Проверяются текущий операторский секрет, intent, его TTL, email-код и TOTP, когда это требует закреплённый режим. Для `optional` поле `totp` отсутствует или пустое; непустое значение отклоняется. Пропущенный TOTP не переключает required-intent в optional. Неправильный корректно оформленный код, отсутствие обязательного TOTP или лишний TOTP у optional-intent расходуют сохранённую попытку; после пяти ошибок intent нельзя завершить. Неверный token не расходует попытки чужого intent. Некорректный непустой формат кода отклоняется до SQL completion.

Одна Read Committed транзакция под общим Access lock и singleton row lock:

1. Заново проверяет отсутствие initialized marker и существующей системной роли.
2. Проверяет intent/operator binding, TTL и число попыток.
3. Проверяет email/TOTP и сохраняет потреблённый TOTP step для защиты от replay.
4. Создаёт active пользователя, профиль, verified email, password credentials; для `administrators`/`required` — также TOTP и 10 recovery code digests. Optional не создаёт ни фактор, ни recovery data.
5. Создаёт `super_admin` и выдаёт восемь core permissions: `access.roles.manage`, `access.assignments.manage`, `accounts.email.bind`, `accounts.users.manage`, `accounts.users.read`, `accounts.users.status.manage`, `accounts.users.delete`, `auth.settings.manage`. Это только новая установка; сохранённые системные назначения при обновлении автоматически не расширяются. Settings runtime/API ещё подключаются в A6.2.
6. Сохраняет выбранную realm policy через существующий version/audit writer, role grant audit и MFA audit только при enrollment, initialized timestamp/UUID первого администратора; удаляет pending secrets/operator/request hashes. Ошибка любого шага откатывает и пользователя, и настройки. Platform owner permissions/marker входят в ту же транзакцию.

Ответ 200:

```json
{"recoveryCodes":["<10 одноразовых кодов>"]}
```

Коды нужно сохранить безопасно. Сервис хранит только owner-bound digests, не исходные recovery codes. В optional ответ содержит `{"recoveryCodes":[]}`; парольный административный вход не требует enrollment, а критические действия по-прежнему требуют свежий пароль и полномочия. Ответ setup не выдаёт login session. В остальных режимах далее парольный вход → общий MFA challenge → authenticator/recovery code → обычная SQL session. TOTP, использованный для setup, нельзя повторно потребить при входе: дождитесь следующего кода либо используйте recovery code. Личный фактор можно подключить позже существующим защищённым flow; optional не отключает уже подключённые факторы.

Если успешный ответ с recovery codes потерян, completion не повторяет выдачу: setup уже закрыт. Можно войти с паролем и authenticator и заново сгенерировать recovery codes через существующий защищённый MFA management. Потеря одновременно всех факторов — отдельный operator recovery, ещё не реализованный в этом этапе.

## Ошибки и ограничения

| HTTP | Code | Причина |
| --- | --- | --- |
| 400 | invalid_json | Неверный JSON/неизвестные поля |
| 400 | invalid_email / invalid_password | Email/password policy |
| 400 | invalid_mfa_policy | Неизвестный режим MFA |
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
