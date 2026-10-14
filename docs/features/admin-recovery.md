# Восстановление пароля супер-администратора

10.3b-local. Есть два независимых пути: обычный email reset и отдельная операторская CLI на случай недоступной почты/SMTP. Потеря MFA — другой сценарий; ни один из этих путей не отключает фактор.

## Решения по MFA recovery (13.1d.1-local)

В том же executable появились два отдельных действия. Они **только одобряют/отменяют внутренний recovery request**, не меняют TOTP, пароль, роли, статус или сессии и не выдают вход. В d.2 реализованы внутренние `mfa/service.Recovery.Start`/`Complete` и durable notification delivery; owner HTTP/App/ENV/worker registration ещё не подключены. Публичного workflow пока нет. Не создавать candidates прямым SQL вместо будущего API.

Для этих действий нужна другая инфраструктурная группа: `auth_mfa_recovery_operator`. Членство в `auth_recovery_operator` для смены пароля её не заменяет. DBA отдельно создаёт NOLOGIN группу/персональный LOGIN и применяет `deploy/mfa-recovery-grants.sql` владельцем миграций после адаптации database identifier. Не давать оператору/runtime CREATE в trusted schema, владение функцией или дополнительные write-grants.

Grants открывают только metadata пользователя/request и EXECUTE `auth.decide_mfa_recovery`. Прямое чтение candidate/current TOTP/primary reference и UPDATE request/users не разрешены. Операция SECURITY DEFINER имеет фиксированный безопасный search_path, без dynamic SQL и PUBLIC EXECUTE; проверяет именно `session_user`/membership, записывает его OID/name, environment и incident reference вместе с audit в одной транзакции. Migration owner/DBA остаётся доверенным инфраструктурным субъектом, не sandbox. Не применять через shared forced-user pooler.

Перед одобрением оператор обязан независимо проверить владельца по утверждённой внедрением процедуре. Request UUID, знание пароля/почты или наличие браузера сами по себе личность не доказывают. User UUID/request UUID не секреты и не login authority; secret/QR/cookie/recovery codes оператору не нужны и в CLI не передаются.

Пример для локального test окружения; `AUTH_RECOVERY_DATABASE_URL` передаётся отдельно защищённым способом и содержит credentials именно MFA operator login:

```bash
./bin/admin-recovery mfa-approve \
  -environment test \
  -user 11111111-1111-4111-8111-111111111111 \
  -request 22222222-2222-4222-8222-222222222222 \
  -reason INC-42
```

Preview показывает environment/host:port/database, реального DB operator, account/request UUID, state, expiry и incident reference. Затем нужно ввести точную строку:

```text
MFA-APPROVE test localhost:5432/auth 11111111-1111-4111-8111-111111111111 22222222-2222-4222-8222-222222222222 v2
```

Сверять реальный destination с инцидентом; имя environment — метка, не доказательство окружения. Для отмены те же флаги и `mfa-cancel`; подтверждение начинается с `MFA-CANCEL`. Password pipe FD 3 не используется. Прежние правила single endpoint/TLS/loopback/санитизации DSN/ограниченного пула сохраняются. Ожидание подтверждения интерактивное; после ввода актуальность проверяется повторно, поэтому истёкший за это время request не одобряется.

Срок ограничен уже существующим primary challenge (максимум 5 минут). Approval его не продлевает. Одобрение однократно: повторный approve, неверные UUID/version, consumed/expired challenge, cancelled request, blocked/deleted account или отозванный DB доступ дают безопасный отказ. Cancel допустим для pending/approved и окончателен для этого UUID. Новое owner-start/reissue создаёт другой UUID/secret и очищает approval; нужен новый операторский выбор. Новый primary challenge и normal MFA login инвалидируют прежний recovery request. Истёкший/уже удалённый request отменять не требуется: он не даёт authority.

При потере ответа исход может быть неизвестен. Сверить request state и audit через уполномоченного DBA; не создавать/одобрять новый candidate автоматически. Audit переживает удаление transient request. Completion повторно проверяет current OID/name/LOGIN/membership: отозванный, отключённый или пересозданный одноимённый DB оператор не оставляет рабочего approval. Одного `approved` для замены недостаточно.

Полный workflow ещё **не доступен через HTTP/UI**. Далее App/HTTP/ENV и worker registration, затем operational drill. До включения внедрение утверждает независимую проверку владельца. [Следующие шаги и ограничения](../planning/mfa-recovery.md).

## Завершение и уведомление MFA (13.1d.2-local)

Внутренний Complete проверяет тот же request/challenge/browser, актуальный primary и новый TOTP. Одной транзакцией заменяет фактор и recovery digests, увеличивает auth_version, отзывает сессии/незавершённые полномочия и пишет operator audit/security job. CLI не получает новые codes. Они возвращаются владельцу только при успешном commit один раз; если response потерян — вход новым TOTP и существующая protected regeneration. Автоматической login session нет, status/roles/password/contact/setup marker не меняются. Неверный код расходует одну из пяти committed attempts; чужой/unapproved request не расходует attempts. Общий account guessing cap разделяется с обычным MFA login и не растёт при reissue.

Security notice идёт на snapshot email, подтверждённого до начала запроса. Отсутствие такого адреса отмечается `notification_queued=false`: оператор обязан сам уведомить владельца по независимо проверенному каналу, не помечать email verified и не отправлять sensitive события на непроверенную почту. В письме только событие/время/request UUID, без secret, QR, codes или изменяющей GET-ссылки.

Durable job не зависит от старой auth_version, consumed request, текущего email или audit retention. SMTP outage не откатывает commit; lease/backoff допускают максимум пять отправок. После успеха ciphertext удаляется, после исчерпания retry сохраняется с failed_at. Crash на последней lease не запускает шестую отправку; потеря успешного SMTP ack может дать повторное информационное письмо (at-least-once), но не повторную смену MFA.

App пока не запускает новый delivery worker. В d.3 зарегистрировать его через существующий bounded runner/pool/SMTP, настроить операционное наблюдение pending age/failed jobs. Disabled recovery не должен обрывать уведомления о уже committed событиях. Разбор failed jobs — отдельное полномочие DBA/операций: MFA approval group не получает UPDATE/secret SELECT этой очереди. Не очищать таблицу «для исправления ошибки» и не снимать MFA ради SMTP outage.

После устранения причины доставки DBA может явно повторить **конкретную** failed job, сверив incident и UUID, без чтения encrypted payload и без изменения MFA. Пример SQL, не автоматическая операция приложения:

```sql
UPDATE auth.mfa_recovery_outbox
SET attempts=0,failed_at=NULL,available_at=clock_timestamp()
WHERE id='33333333-3333-4333-8333-333333333333'
  AND failed_at IS NOT NULL AND lease IS NULL
RETURNING id;
```

Учитывать возможное повторное письмо и сохранять операционный след такого решения. Pending/failed job не удаляется обычным retention; срок ручного разбора и дальнейшего хранения encrypted recipient определяется операционной политикой. Пока нет реальной browser/SMTP/operator приёмки, не считать локальные тесты production acceptance.

## Обычный путь

Существующие `POST /api/v1/auth/forgot-password` и `POST /api/v1/auth/reset-password`, [контракт](password-recovery.md). Ссылка сама не меняет пароль: нужен POST с новым паролем и одноразовым token.

У супер-админа сохраняются роль, permissions, TOTP и recovery codes. После reset старые сессии отозваны, новая не выдаётся: обычный вход с паролем и MFA. Заблокированный/удалённый аккаунт обычный reset не активирует. Наличие административной роли не является исключением из этих проверок.

## Когда нужна CLI

Почта или SMTP недоступны, пароль потерян, но оператор через независимую процедуру проверил владельца и имеет инфраструктурный доступ к БД. Команда работает только с существующим non-deleted `super_admin`, у которого уже есть постоянные password credentials. Другой пользователь, external-only аккаунт или удалённый администратор не превращается в password admin.

CLI не меняет email/verified flag, роли/permissions/access_version, MFA/recovery codes, статус или initialized marker. Заблокированному администратору можно сменить пароль, но он остаётся заблокированным. Нет новых HTTP routes, startup password override или способа повторно открыть setup.

Если почта потеряна или скомпрометирована, CLI **не восстанавливает владение адресом**. Отдельно разберите контакт и инцидент; текущий получатель почты может инициировать новый обычный reset. При потере authenticator и всех recovery codes эта команда не решает проблему: отдельный lost-factor процесс остаётся открытым. Не заменяйте его ручным удалением MFA/БД.

## Доступ оператора

Это инфраструктурное полномочие PostgreSQL, не Auth role/permission и не клиентский флаг. DBA отдельно создаёт NOLOGIN группу `auth_recovery_operator`, выделенный LOGIN конкретного оператора и выдаёт членство с наследованием прав. `auth_runtime` не должен быть членом этой группы. Приложение не создаёт роли БД и не выдаёт grants при запуске.

Шаблон выдачи минимальных прав — `deploy/recovery-grants.sql`; адаптируйте имя БД `auth` перед использованием, применяйте владельцем после миграции/restore. Группа может обновлять только auth_version пользователя, password_hash credentials и revoked_at сессий; не получает write-доступа к текущему TOTP, roles/user_roles, status или setup marker. Для cleanup разрешён доступ к конкретным transient tables, для аудита — INSERT/sequence usage. Старые password hashes команде не нужны.

Пример административной подготовки (не выполняется приложением):

```sql
CREATE ROLE auth_recovery_operator NOLOGIN;
CREATE ROLE auth_recovery_alice LOGIN;
GRANT auth_recovery_operator TO auth_recovery_alice WITH INHERIT TRUE;
```

Пароль/сертификат DB login задаётся отдельно защищённым способом, без literal в Git/истории. В аварийном окне выдавайте доступ на ограниченное время и отзывайте после инцидента. Не используйте общую учётную запись, если нужно различать операторов в audit.

Команда проверяет членство `session_user`, а не переданный actor ID или текущий `SET ROLE`. Повторная проверка выполняется внутри транзакции перед изменением. Используйте прямое персональное DB подключение, не shared pooler с forced-user: он скрывает исходную личность оператора. PostgreSQL superuser/владелец инфраструктуры остаётся доверенной стороной: CLI не является sandbox против прямого произвольного SQL с привилегированными credentials. Группа всё ещё имеет чувствительные права БД, её нельзя выдавать API-процессу или недоверенному пользователю.

## Запуск

Сборка: `go build -mod=readonly -trimpath -o ./bin/admin-recovery ./cmd/admin-recovery`.

Только для процесса CLI передайте `AUTH_RECOVERY_DATABASE_URL` через защищённое операторское окружение/secret manager. Это **пароль подключения к БД**, не новый пароль пользователя. Команда не загружает `.env` приложения и не требует Redis, SMTP или ключа расшифрования MFA.

В `prod` нужен PostgreSQL URL с `sslmode=verify-full` и доверенным CA/hostname; непроверенный TLS не допускается. `dev`/`test` ограничены фактическим loopback endpoint, локальный пример использует `sslmode=disable`. Разрешён один endpoint без connection fallbacks; проверяются результаты pgx ParseConfig, в том числе host overrides из query. Название environment — явная метка оператора для подтверждения и audit, а не автоматически доказанная принадлежность БД окружению. Сверяйте host/port/database с утверждённым инцидентом.

Новый пароль должен быть заранее безопасно сохранён в secret manager. Передайте его через унаследованный **pipe FD 3**. Не передавайте пароль в аргументах/ENV, через terminal echo или открытый файл. Синтаксический шаблон для Bash/Zsh на Linux/macOS:

```bash
./bin/admin-recovery \
  -environment prod \
  -user <существующий-UUID-супер-админа> \
  -reason INC-123 \
  3< <(APPROVED_PASSWORD_COMMAND)
```

`APPROVED_PASSWORD_COMMAND` — обозначение вашей реальной команды secret manager, не встроенная утилита проекта. Она должна вывести ровно новый пароль и необязательный завершающий LF/CRLF, затем закрыть pipe. Не подставляйте сюда `echo 'реальный пароль'` или shell literal. Windows pipe flow не поддержан этим runbook.

Пароль не выводится командой. Pipe ограничен по размеру и 10-second read deadline; terminal/regular file, пустой/слишком длинный input, невалидный UTF-8, NUL и дополнительные строки отклоняются. Применяется существующая password policy, Argon2id с обычными параметрами и одним hashing slot; гарантия очистки всех копий secret в памяти Go не заявляется.

Команда покажет actual host/port/database, DB operator, UUID, status, auth_version и reason. Затем потребует точное подтверждение:

```text
RESET prod db.example:5432/auth <UUID> v7
```

Не копируйте подтверждение без сверки цели. Не добавляйте secrets в `-reason`: это сохраняемая причина/номер инцидента. Отказ или старое подтверждение не читает новый пароль и не меняет БД. Результат успешной операции содержит только новую auth_version, не пароль или сессию.

## Что происходит атомарно

Read Committed, общий Access lock до user lock:

1. Проверяются текущие DB operator membership, системное назначение, существующий пароль, non-deleted status и ожидаемая auth_version.
2. Меняется password_hash, увеличивается auth_version, отзываются старые сессии.
3. Удаляются password reset/outbox, MFA login/enrollment, email login/outbox и pending email binding этого пользователя. Остальные version/session-bound полномочия становятся непригодными по текущим guards; защитные email-change evidence/report не удаляются как «мусор».
4. Пишется `password_audit.event=operator_password_reset`: target UUID, новая auth_version, фактический `session_user`, environment, reason, timestamp. Никаких паролей/token/DSN в audit нет.

SQL constraints и audit failure откатывают всю операцию. Один auth_version может быть потреблён reset только один раз: повтор со старой version получает conflict, в том числе после retention audit. Из 16 конкурентных попыток проходит одна. Preview перед hashing экономит Argon2 на denied/stale операциях, но не заменяет проверки под lock. SQL-пул — одна connection, connect/query/transaction waits ограничены; общий auth hot path не получает новых запросов.

Права/статус/MFA/marker не изменяются; новый пароль **не является готовой сессией**. После успешной смены нужен обычный login и действующий второй фактор. Нет MFA — остановиться и следовать отдельному lost-factor процессу, не выдавать новое системное назначение.

При отказе зависимости или потерянном ответе после commit исход может быть неизвестен. Не повторяйте автоматически с новой версией: сравните auth_version и audit/инцидент через уполномоченного DBA/observability. Повторный запуск CLI сначала показывает preview и ничего не меняет до нового точного подтверждения. Сам по себе новый запуск — новая операторская операция, не повторная выдача прежнего полномочия.

## После инцидента и границы приёмки

Подтвердить обычный password+MFA login, сверить audit, закрыть инцидент, отозвать временный DB operator доступ и убрать операторское окружение. БД/initialized marker не сбрасывать. На действующей установленной схеме нужен отдельный согласованный перенос: шаблон пока меняет source initial migration, не делает down/reset рабочей БД.

Локально проверены command/service admission, exact confirmation/stale confirmation, sanitization ошибок, inherited pipe subprocess/отсутствующий FD, runtime deny, реальные column grants, operator membership revoke, wrong target/deleted/demoted, audit rollback, concurrency/replay и сохранение factor/recovery/role/status/marker. Обычный email reset администратора проверен на сохранение MFA и отсутствие unblock/session issuance. Реальные production TLS/secret manager/SMTP/browser, operator drill с проверкой личности, fault/load/GC и lost-factor recovery остаются отдельными gates. Это не объявление готовности всего сервиса к production.
