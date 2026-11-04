# Создание пользователей в независимом проекте

## API — MP5.1l

Проектный HTTP dispatcher подключает существующие account/password handlers, DTO, сервисы и SQL. Это административное создание пользователя, отдельно от публичной регистрации и от platform operator API.

| Метод и путь | Назначение | Защита |
| --- | --- | --- |
| POST `/api/v1/admin/users` | Создать pending пользователя, при `invite=true` подготовить приглашение | Project session, NoRefresh, exact Origin, `accounts.users.manage`, свежий пароль и MFA |
| POST `/api/v1/admin/users/{id}/invitation` | Перевыпустить приглашение pending пользователю | Те же guards, cooldown и scoped limits |
| POST `/api/v1/auth/invitations/activate` | Однократно принять приглашение и задать постоянный пароль | Exact Origin, token, password confirmation; сессия не требуется |
| POST `/api/v1/admin/users/temporary-password` | Создать pending пользователя с временным паролем | Project session, NoRefresh, exact Origin, `accounts.users.manage`, свежий пароль и MFA |
| POST `/api/v1/admin/users/{id}/temporary-password` | Перевыпустить временный пароль pending пользователю | Те же guards, cooldown и scoped limits |

Контракты полей и ошибок остаются в [invitations](invitations.md) и [temporary passwords](temporary-passwords.md), а также в существующем Swagger. У actor нет поля в JSON: он берётся из сессии выбранного проекта. SQL проверяет актуальные полномочия и proofs внутри записи и при повторе команды. Знание чужого UUID права не даёт.

## Выбор возможностей

UUID manifest содержит независимые `invitations` и `temporaryPassword`, оба default false и требуют `browser=true`. Без manifest эти возможности не наследуют глобальное включение. [Пример](../../deploy/examples/project-auth.example.json).

Operational TTL/cooldown/budgets берутся из существующих `Invitation`/`TemporaryPassword` настроек; `Enabled` выбирается записью проекта. Invitation URL строится из доверенного origin проекта: `/activate`. Platform URL/key/secret не копируются. Новых ENV и зависимостей нет.

В программном `ProjectProfileConfig` используются существующие `EmailManagement.Invitations` и `Password.TemporaryPassword`. Readiness состояния:

- `provisioning`: выдача приглашения требует Redis, hasher, работающий project delivery/SMTP и готовую согласованную MFA management configuration.
- `invitation_activation`: отдельная сборка для уже выданного токена; Redis/hasher/SQL обязательны, SMTP и работающий delivery worker не требуются даже после cold build. Активация не включает отключённый способ входа.
- `temporary_password_admin`: требует готового password/temporary профиля и MFA management configuration. SMTP не нужен. Public temporary login/complete остаются существующим отдельным сценарием.

Неготовая возможность не публикует маршруты. Эти состояния не предоставляют actor права и не заменяют SQL-проверку. Настраиваемая обязательность MFA остаётся отдельным согласованным этапом; текущие требования issuance не ослаблены.

## Результат и повтор запросов

Создание/перевыпуск требуют UUID `idempotencyKey`, scoped по actor. Повтор той же команды возвращает прежний результат; несовместимые параметры дают конфликт. Приглашение не создаёт роль или сессию; активация задаёт пароль, подтверждает приглашённый email и переводит аккаунт из pending в active атомарно. GET по ссылке ничего не активирует: UI должен выполнить POST.

Временный пароль сервер генерирует сам и возвращает только в первом успешном ответе. Повтор не раскрывает пароль и не продлевает TTL; потерянный ответ требует перевыпуска после cooldown. Перевыпуск отменяет старый temporary/setup authority и не служит сбросом пароля активного пользователя. Пользователь проходит существующие temporary login/complete и задаёт постоянный пароль. Сам временный пароль email не подтверждает.

Ни один из пяти endpoints не создаёт пользовательскую сессию и не назначает роли. Назначения остаются самостоятельным административным действием. Ответы `no-store`, browser Origin policy и защита от логирования секретов прежние.

## Проверки

Добавлены source/manifest default-off/isolation/copy tests, prerequisites/route protection и существующий actual HTTPS/SQL project account fixture переведён на issuance HTTP. Сценарии включают 401/403, создание/replay/reissue, невозможность повторно раскрыть temporary secret, отмену старого invitation/temporary authority и активацию при выключенном delivery/удалённом SMTP. Старые binding/change/protection сценарии сохраняются. Локальные проверки Luna V1–V3 PASS: Go tests, API coherence, affected race/lint и полный Linux ARM64 TestPrepareCommandSQL. Issuance/activation и прежние directory/MFA/identity HTTP cases прошли без skip. Полная two-project matrix, нагрузка и UI остаются отдельными gates.
