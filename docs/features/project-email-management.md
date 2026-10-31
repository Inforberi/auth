# Управление email проекта

MP5.1h, 26 октября 2026. Подключены существующие account/password handlers и сервисы к выбранному project runtime. Локальные проверки Luna PASS; UI и полная MP5 приёмка остаются отдельными этапами.

## API и полномочия

Все операции — POST на точном HTTPS origin проекта. BrowserProtection требует этот Origin; CORS не включён. Проект выбирается прежней TLS/Host boundary, не из JSON, роли или токена. Сессионные ручки используют `NoRefreshAuth` и `__Host-session` текущего проекта.

| Путь | JSON | Кто выполняет и результат |
| --- | --- | --- |
| `/api/v1/admin/users/{id}/email-binding` | `email` | Администратор проекта с `accounts.email.bind`, свежими password/MFA proofs; 202 и expiresAt. Одобряет адрес для внешнего аккаунта без контактов/пароля, не привязывает его сразу |
| `/api/v1/auth/email/binding/confirm` | `code` | Сам целевой пользователь с действующей сессией и нужным MFA proof; 200, verified contact, повышение auth_version и отзыв его сессий |
| `/api/v1/auth/email/change` | `email`, необязательный `password` | Пользователь с verified login email, текущим паролем либо недавним password reauthentication; 202, без токенов в ответе |
| `/api/v1/auth/email/change/confirm` | `token` | Purpose token нового адреса, без cookie; исходная request-session перепроверяется в SQL. 200, смена адреса и отзыв сессий |
| `/api/v1/auth/email/change/report` | `token` | Отдельный защитный токен старого адреса, без cookie; 200, отмена pending change либо защитная блокировка после завершённой смены |
| `/api/v1/auth/email/change/recover` | `token`, `newPassword`, `confirmPassword` | Отдельный recovery token старого адреса после защитной блокировки; 200, восстановление старого email/замена пароля/отзыв доступа |

Администратор платформы не становится actor проекта автоматически: binding request принимает только project-local session/principal. SQL повторно проверяет permission, session/hash/version и свежие password/MFA proofs одобряющего администратора, в том числе при подтверждении пользователем. Self-target не допускается. Привязка не создаёт аккаунт, пароль, права или новую сессию и не объединяет пользователей по email.

Старый login email действует до подтверждения нового. Открытие ссылки не выполняет действие: GET не меняет состояние; будущий UI должен отправлять явный POST. Переданный ошибочный пароль отклоняется даже при свежем password proof. Смена адреса и защитные действия используют прежние транзакции, one-time tokens, audit, auth_version и немедленный отзыв.

Report не требует сессии возможного злоумышленника и не делает автоматический rollback/unblock/login. Protected recovery — отдельный password-only сценарий: не обходит административную блокировку или MFA и не выдаёт сессию. После него нужен обычный вход. Контракты ошибок, лимиты и защищённые письма переиспользованы без копирования.

## Включение

В UUID manifest добавлены независимые `emailBinding` и `emailChange`, по умолчанию false. Оба требуют `browser=true`; `emailBinding` дополнительно требует `reauthentication=true`. Binding producer требует включённую MFA configuration и готовую email reauthentication capability. SQL-полномочия администратора от этих флагов не появляются.

TTL/лимиты берутся из существующих operational EmailBinding/EmailChange/Password/Session настроек; новых ENV нет. URLs собираются только из доверенного origin проекта: `/change-email`, `/protect-account`, `/recover-account`. Platform host/URL/секреты не наследуются. Без manifest сохраняется прежний ограниченный deployment; binding требует явной настройки reauthentication через manifest. [Пример](../../deploy/project-auth.example.json).

Programmatic source использует `ProjectProfileConfig.EmailManagement`. Profile выбирает только Binding/Change и необходимые им настройки из этого config; Invitations/Verification/Recovery producer flags в нём не публикуют дополнительные ручки. Origin должен совпадать с выбранным проектом.

## Доставка и защитные действия

Новые binding/change запросы публикуются только при готовых scoped Redis, сохранённом SMTP и работающем общем delivery owner. Остановка owner закрывает новые запросы. Письма остаются в существующих encrypted outbox и доставляются прежним bounded scheduler; нового worker или pool на проект нет.

Завершение выданного binding code и confirm/report/recover используют отдельные readiness states `email_binding_confirmation` и `email_change_protection`. Они не требуют SMTP credentials или работающего worker при холодной сборке. Те же project key, crypto, Redis limits и SQL guards остаются обязательными. SQL может сохранить уведомление в outbox, которое будет отправлено после восстановления доставки; исправность SMTP не является доказательством полномочий пользователя.

Private storage assembly не меняет публичный `NewProjectEmail`, который по-прежнему требует SMTP. На storage-компоненты монтируются только конкретные completion/protection handlers. Готовность producer и защитных ручек разделена; общий Readiness.Ready может быть false, хотя защитные ручки доступны. Suspend/stale policy по-прежнему обрабатывает boundary/dispatcher.

## Проверки и границы

Добавлены source/manifest isolation/copy/URL tests, prerequisite/route-protection tests. Существующий account SQL fixture использует те же три synthetic users, роли, MFA/session proofs и encrypted payloads через реальный HTTPS ProjectHTTP: admin approval, owner confirmation, change/confirm/replay/report/recover и итоговый email/hash/status. Проверяется отсутствие session issuance, отказ ordinary actor/Origin/no-session, GET без мутации. После остановки worker и удаления собственного SMTP row новый профиль должен выполнить report/recover; stale profile сначала отклоняется. Cleanup восстанавливает policy/SMTP и удаляет только собственные users/rows/точные Redis keys.

Main: formatter/source review и read-only review исследователя. Luna на immutable snapshot: task check/API/security/affected race и полный Linux ARM64 TestPrepareCommandSQL PASS, HTTP profile без skips. Все 14 source hashes и deployment example JSON совпали с main; собственный стенд очищен. Govulncheck: 0 достижимых уязвимостей, 1 advisory в required module вне импортируемых пакетов/вызываемого кода; уточнить advisory при MP6R, без автоматического обновления зависимостей. Snapshot/evidence — в history. Реальная доставка внешней почты, полная cross-project matrix, identity/MFA management и эксплуатационная приёмка здесь не закрываются.

31 октября принят component TestTwoProjectEmailIsolationSQL: actual A/B ProjectEmail adapters, cross-project change/confirm/report/recovery tokens, scoped outbox URLs/recipient и SQL proof revocation. Luna V1 task check/Email root race PASS, manifest14 и cleanup подтверждены; [scope](../planning/multi-project.md#сессии-и-почта-двух-проектов--mp5-sessions-email). Этот component test не закрывает двухпроектную email HTTP/browser matrix или внешнюю доставку.
