# Аварийное восстановление оператора платформы

MP2.4, 18 октября 2026. Используется существующий `cmd/admin-recovery`, не второй password/MFA стек. Обычный email reset и сохранённые MFA recovery-коды остаются предпочтительным способом. Аварийные DB credentials хранятся отдельно от приложения и панели; доступ к ним требует инфраструктурного оператора. Восстановление не создаёт аккаунт, не разблокирует его, не выдаёт роли/сессию и не открывает initial setup заново.

## Два разных действия

| Что потеряно | Действие |
| --- | --- |
| Пароль, почта недоступна | CLI меняет пароль существующего super-admin, увеличивает auth_version, отзывает сессии/незавершённые login proofs; действующий MFA сохраняется |
| TOTP и все recovery-коды | Владелец доказывает пароль, начинает замену MFA; отдельный инфраструктурный оператор независимо проверяет личность и одобряет точный request через CLI; владелец подтверждает новый TOTP |
| И пароль, и MFA | Сначала аварийная смена пароля, затем тот же operator-assisted MFA workflow; пароль сам по себе не обходит MFA |

Одобрение не меняет фактор. Completion заменяет его и recovery-коды, увеличивает auth_version, отзывает прежние сессии и пишет audit/уведомление через существующий зашифрованный outbox. Автоматического входа нет: после восстановления нужен обычный password+MFA login. Marker платформы и её permissions сохраняются. При недоступной/неподтверждённой почте уведомление владельца — отдельная обязанность инфраструктурного оператора.

## Отдельные права PostgreSQL

PostgreSQL roles глобальны для кластера, а не отдельной БД. Нельзя просто применять прежние grants общим `auth_recovery_operator`/`auth_mfa_recovery_operator` в платформенной БД: это расширит права всех их участников из других установок/проектов.

DBA создаёт четыре NOLOGIN группы и два отдельных персональных LOGIN, без superuser/CREATEDB/CREATEROLE/BYPASSRLS, ownership или DDL. Группы `auth_*` могут уже существовать — не изменять их прежние права и участников.

| Персональный LOGIN | Единственная recovery-группа | Доступ |
| --- | --- | --- |
| Аварийная смена пароля | `platform_password_recovery_operator` | Прежние ограниченные password recovery grants только в платформенной БД |
| Одобрение MFA | `platform_mfa_recovery_operator` | Metadata и EXECUTE существующей decision function только в платформенной БД |

Порядок применения владельцем миграций:

1. Адаптировать копию [password grants](../../deploy/recovery-grants.sql): database `auth` → имя платформенной БД, получатель `auth_recovery_operator` → `platform_password_recovery_operator`.
2. Адаптировать копию [MFA grants](../../deploy/mfa-recovery-grants.sql): database `auth` → имя платформенной БД, получатель `auth_mfa_recovery_operator` → `platform_mfa_recovery_operator`.
3. Применить [platform grants](../../deploy/platform-recovery-grants.sql). Они дают metadata SELECT и только MEMBER-связь с прежними группами: **INHERIT FALSE, SET FALSE**. Это сохраняет существующие Auth проверки членства, но не переносит права из других БД и не разрешает SET ROLE в проектные группы. Требуется PostgreSQL с поддержкой этих membership options; проверено на18.6.
4. Выдать каждому персональному LOGIN только его платформенную группу, без ADMIN OPTION. Не включать их в обе recovery-группы, runtime или группы владельцев. Не использовать forced-user pooler.

Runtime не получает аварийных полномочий; startup отвергает membership в recovery-группах и EXECUTE decision function даже при выключенном recovery. Для новых owner-запросов нужен `MFA_RECOVERY_ENABLED=true`; включение проверяет отдельную платформенную NOLOGIN MFA-группу, безопасную MEMBER-связь, function grants и отсутствие EXECUTE у runtime. По умолчанию флаг остаётся false.

Это ограниченные operational права, **не SQL sandbox против злонамеренного DBA**: offline password login имеет необходимые прямые grants, MFA function работает SECURITY DEFINER. Доверенный migration owner управляет неизменяемым для runtime/offline marker. Не менять marker/schema/grants во время интерактивного восстановления. Неправильную ранее выданную общую роль нельзя исправить только применением нового шаблона: DBA должен отдельно отозвать старые лишние grants.

## CLI: явная платформа

`AUTH_RECOVERY_DATABASE_URL` — отдельное защищённое подключение соответствующего персонального LOGIN. Настоящий пароль/DSN не передавать в аргументах, reason или логах. Production требует `sslmode=verify-full` и один проверяемый endpoint; test/dev — только loopback. Новый пароль передаётся прежним защищённым pipe FD3, не stdin/аргументом/обычным файлом; [основной runbook](admin-recovery.md).

```bash
./bin/admin-recovery -environment prod \
  -platform-realm 11111111-1111-4111-8111-111111111111 \
  -user 22222222-2222-4222-8222-222222222222 -reason INC-42

./bin/admin-recovery mfa-approve -environment prod \
  -platform-realm 11111111-1111-4111-8111-111111111111 \
  -user 22222222-2222-4222-8222-222222222222 \
  -request 33333333-3333-4333-8333-333333333333 -reason INC-42
```

UUID платформы берётся из доверенной конфигурации установки/БД, не из запроса владельца. Admission проверяет initialized marker, совпадение realm, наличие platform permissions у цели и ограниченные DB права. Preview/мутация повторно используют существующие Auth проверки текущего статуса, super-admin/password authority либо recovery request/version/operator membership. `-platform-realm` без правильной БД/прав не даёт доступ; отсутствие флага на любой БД со schema platform отвергается. Без флага сохраняется только legacy standalone, не новый project runtime.

Точное подтверждение включает environment, фактический host:port, `[platform=<UUID>]`, database, target/version; для MFA ещё request UUID. Прежняя строка без платформы не подходит. После неизвестного commit outcome проверять audit/version/request через уполномоченного DBA, не повторять операцию вслепую. `mfa-cancel` использует те же scope/connection guards и отменяет конкретный request; фактор не меняется.

## HTTP при потере всех факторов

Только при включённом recovery, на доверенном HTTPS origin платформы и с прежней CSRF/binding защитой:

1. POST `/api/v1/admin/auth/login/email` → primary challenge и host-only MFA binding cookie, не сессия.
2. POST `/api/v1/auth/mfa/recovery/start` с `challenge` → `requestId`, новый candidate secret/URI, исходный expiry. Старый TOTP ещё действует.
3. Независимая проверка личности инфраструктурным оператором; CLI `mfa-approve` для точного UUID/request/version. Password/email/request UUID сами по себе недостаточны для независимой проверки.
4. POST `/api/v1/auth/mfa/recovery/complete` с `requestId`, исходным `challenge`, новым TOTP `code` и тем же binding cookie → десять новых recovery-кодов один раз, без session issuance.
5. Обычный password+новый MFA login; после подтверждённого завершения закрыть инцидент и отозвать временную DB membership. Отзыв до completion делает approval недействующим.

Неодобренные/истёкшие/чужие/повторные запросы и отозванный DB operator дают отказ. Переиздание candidate очищает approval и не продлевает исходный challenge. Существующие лимиты/пять попыток/SQL locks сохраняются. MFA disable и повторный bootstrap не публикуются.

## Проверки и ограничения

Локальный `TestOperatorProfileSQLHTTPS` расширен: отдельные настоящие LOGIN для runtime/password/MFA, SQL guards/cluster-role isolation, действительная CLI с FD3, negative omitted/wrong realm/wrong role, password reset без изменения TOTP, stale reset, HTTP recovery без approval/replayed approval/revoked membership/replay, session revoke, encrypted platform scope, marker/audit и повторный login. Для CLI-фазы используется отдельный собранный binary через `AUTH_OPERATOR_TEST_CLI`; без него SQL test проверяет те же service/repository операции, но не выдаётся за запуск CLI. SQL fixture без разрешающих ENV пропускается.

Результаты и очистка — [history](../planning/history.md#результат-mp24-operator-recovery--18-октября-2026). Реальная проверка личности, production TLS/secret manager/SMTP/browser/ingress, полный multi-project/fleet/fault/load/GC остаются NOT RUN. Локальный drill не закрывает эти release gates.
