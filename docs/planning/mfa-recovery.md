# Потеря всех MFA-факторов: план 13.1d

14 октября 2026. **13.1d.1 реализован локально:** внутренний start и операторские approve/cancel. Замена фактора, delivery, App/HTTP/ENV ещё не подключены; законченного recovery API пока нет. Если recovery code остался, уже работает обычный MFA login; ниже — потеря и authenticator, и всех codes.

## Основное решение

Три условия: текущий primary login владельца, независимое операторское одобрение **конкретного запроса** и подтверждение нового TOTP. До атомарной замены старый фактор остаётся действующим; никаких MFA-off окон, временных полноценных сессий или входа без второго шага.

Операторское одобрение — альтернативная доверенная процедура восстановления, не доказательство наличия потерянного фактора. Новый authenticator сам по себе личность не доказывает. Компрометация поддержки/оператора может позволить захват аккаунта, поэтому до включения нужна утверждённая внедрением проверка владельца по независимому каналу и инциденту. Одной cookie, письма «это я», номера заявки или знания пароля для одобрения недостаточно. Универсальную автоматическую проверку документов/личности не добавляем; без утверждённой процедуры recovery выключен.

Отдельный bearer recovery token не нужен: используются существующие MFA login challenge и HttpOnly browser binding. Request UUID служит ссылкой для оператора, а не разрешением войти.

## Пользовательский сценарий

1. Оператор сначала проверяет владельца вне приложения и готов к короткому workflow. Пользователь проходит обычный primary login через реально включённый password/OIDC/email OTP adapter и получает `mfa_required`, не session.
2. В том же браузере владелец начинает lost-factor запрос. Backend проверяет challenge, browser binding, current primary proof/status/version/method policy; генерирует новый TOTP candidate и возвращает его QR/manual secret, request UUID и срок. Текущий enrolled secret не раскрывается и не меняется.
3. Оператор сверяет target UUID, request UUID, environment/host/database, auth_version и incident reference. Через CLI одобряет только этот неизменяемый candidate. Пересоздание запроса меняет request ID и сбрасывает approval, не переносит его на другой браузер/secret.
4. Владелец подтверждает код из нового authenticator в том же браузере. Без актуального approval, challenge/browser binding и версии замена запрещена; cookie или первый фактор сами по себе не дают MFA proof для обычных API.
5. Одна транзакция потребляет request/approval/challenge, заменяет TOTP и использованный step, ротирует recovery digests, увеличивает auth_version, отзывает sessions/незавершённые полномочия, пишет audit и durable notification при наличии verified contact.
6. Новые recovery codes выдаются владельцу один раз, не оператору; login session не выдаётся. Далее обычный новый primary login + новый TOTP/recovery code. При потере успешного response codes не перечитываются: после входа — существующая protected regeneration.

Expiry/cancel/error сохраняют старые фактор/codes. Если normal MFA login раньше потребил тот же challenge, recovery на нём уже не завершается. Сам по себе recovery не останавливает атакующего с украденными действующими credentials: при компрометации нужен отдельный containment процесс.

## Минимальный backend-контракт

- Фича остаётся в существующем `internal/auth/mfa` по domain/service/repository/transport, не в password recovery или общем workflow framework.
- Два **предлагаемых** POST пути: `/api/v1/auth/mfa/recovery/start` и `/api/v1/auth/mfa/recovery/complete`. Пока их нет. Origin/no-store/strict JSON/resource bounds/общий mapper обязательны. Target выводится из проверенного challenge; JSON не принимает actor/user UUID, version, primary proof или approved flag. Complete сопоставляет request UUID.
- Расширить существующий `cmd/admin-recovery` явными действиями `mfa-approve`/`mfa-cancel`, сохранив password CLI контракт. Переиспользовать connection/TLS/exact-confirmation, не создавать второй CLI или shell scripts.
- Отдельная DB-группа `auth_mfa_recovery_operator`: без автоматической выдачи runtime или password-recovery оператору. Grants позволяют читать только необходимую metadata и одобрять/отменять запрос, не читать candidate secret или писать действующий TOTP/password/status/roles. Проверять session_user, а при completion — текущую identity/membership одобрившего оператора. Revoked/deleted operator не оставляет рабочего approval; пересозданный одноимённый login не наследует его.
- Одно небольшое feature-owned SQL-хранилище: один активный request/user, encrypted candidate, primary challenge/browser binding, auth_version, approval, expiry и attempts. Не маскировать primary challenge под session_hash обычного enrollment. auth_version уже связывает замену фактора с актуальностью; не добавлять второй version/fingerprint без отдельной доказанной гарантии.
- Срок не позже existing challenge expiry: `MFA_LOGIN_CHALLENGE_TTL` сейчас максимум 5 минут. Approval/retry срок не продлевают; при expiry нужны новый primary login и новое одобрение. Проверка личности выполняется до короткого browser шага.
- Пять committed wrong TOTP attempts на request, плюс общий account-wide Redis guessing cap между normal MFA/recovery/reissue. Новые requests не обнуляют cap. Переиспользовать IP/project admission; fail-closed, Redis/SMTP вне SQL locks. Wrong browser/неодобренный запрос не расходует попытки чужого candidate.
- Runtime opt-in по умолчанию off; предполагаемый `MFA_RECOVERY_ENABLED` требует MFA_ENABLED. ENV добавляется при рабочей реализации, не сейчас. Disabled проверяется при start и completion, не только в UI.

## Неизменяемые гарантии

Password, contact/verified flags, status, roles/permissions/access_version и initialized marker не меняются. Pending/blocked/deleted не активируются, пользователь не создаётся, обычный password reset не разрешает замену MFA. Последнее системное назначение сохраняется, но admin access до завершённой замены не выдаётся.

Поддержать реально включённые primary adapters, включая external-only. Обычный trusted primary challenge здесь **не равен** fresh provider reauthentication для обычного MFA management; emergency authority дополнительно даёт проверенное операторское одобрение. Отозванная identity, disabled method, изменившиеся credentials/contact/version/policy закрывают completion по текущим guards.

Если потерян пароль — отдельный email reset/10.3b, затем новый primary challenge. Для blocked/deleted recovery останавливается: разблокирование не прячется в этом процессе. Возможность операторского unblock — отдельное решение, не часть этого этапа.

## Audit и notification — до публикации HTTP

Audit: start/approve/cancel/complete, request/target UUID, реальный оператор, incident reference, version/time; без raw challenge/cookie/QR/secret/codes или документов владельца. Ошибка обязательного audit откатывает mutation.

Замена фактора требует уведомления на ранее verified contact. Notification должна сохраняться **одной транзакцией** с заменой и не исчезать при удалении login challenge/увеличении auth_version. Нельзя вслепую использовать FK/version-filter обычного OTP outbox: он удаляется именно при успешном завершении. Предусмотреть небольшой MFA security outbox, независимый от consumed challenge, переиспользуя encryption/SMTP/lease/backoff/bounded delivery runner. Точку подключения delivery и суммарные pool/worker budgets определить до HTTP публикации; без общего notification framework, новых pools/brokers или worker на каждое письмо. Это необходимая гарантия доставки security event, не произвольная продуктовая очередь.

В уведомлении нет secrets и изменяющих GET-ссылок. Нет verified contact — не отправлять на непроверенный адрес и не проставлять verified=true; оператор уведомляет владельца по независимо проверенному каналу, фиксирует incident reference, будущий UI показывает событие после входа. Это часть человеческой процедуры доверия, не новая автоматическая SMS/Telegram интеграция. SMTP outage не откатывает уже совершённую замену: остаются durable job/retries и операционное оповещение об ошибках.

## Поэтапная реализация

1. **13.1d.1 — внутренний request/approval/cancel.** Проверить existing primary/factor/version guarantees, определить SQL request/notification lifecycle и grants. Реализовать immutable request binding/CLI/audit без публичного включения незавершённого flow.
2. **13.1d.2 — completion/delivery.** Reuse TOTP/cipher/recovery generation; atomic consume/replace/version/revoke/cleanup/audit/notification. Lock order Access → user → challenge/request/factor. Не ослаблять обычный enrollment/replace ради lost-factor.
3. **13.1d.3 — App/HTTP/ENV/Swagger.** Две ручки работают с CLI вместе, API проверяет flags/grants/effective methods. UI ещё не делать; endpoint «только отключить MFA» не публиковать.
4. **13.1d.4 — приёмка/runbook.** Unit/HTTP, restricted SQL roles, disposable race и операционная процедура. Browser/authenticator/SMTP/identity drill и faults — внешние release gates, не объявлять их закрытыми unit-тестами.

### Фактический результат 13.1d.1

- `mfa/service.Recovery.Start` принимает существующие challenge/browser/IP, не target UUID. Переиспользованы canonical token check, IP/project/account admission, scoped cipher и генератор TOTP. SQL повторяет актуальные primary/status/version/method checks под Access → user → challenge locks; никакая обычная session не подделывается.
- `mfa_recovery_requests` хранит один encrypted candidate/user, immutable request UUID, ссылку на login challenge, version/expiry/attempts и approval. Reissue выдаёт новый UUID/secret и очищает approval без продления primary TTL. Новый primary challenge явно удаляет старый request; потребление/удаление challenge каскадно удаляет request. Bounded retention очищает expiry по индексу. Audit не имеет FK на transient request и переживает его удаление.
- `admin-recovery mfa-approve|mfa-cancel` требует environment/user/request/reason и точного интерактивного подтверждения destination/database/UUID/version. Используется прежняя защищённая DB connection, пароль из FD 3 для MFA не нужен. Полный контракт — [операторское руководство](../features/admin-recovery.md#решения-по-mfa-recovery-131d1-local).
- Отдельный `deploy/mfa-recovery-grants.sql`: metadata SELECT и EXECUTE одной `SECURITY DEFINER` операции `auth.decide_mfa_recovery`, без write-grants на таблицы и без чтения candidate/current TOTP/primary reference. Функция использует безопасный search_path, PUBLIC EXECUTE отозван, нет динамического SQL; session_user/OID/membership берутся сервером, mutation и audit атомарны. Именно эта узкая операция позволяет не выдавать оператору прямой UPDATE candidate или возможность подставить другого approver. Обычный runtime/password operator не получает её EXECUTE автоматически.
- Только active/non-deleted account с live challenge/current version/enrolled factor. Одобрение однократно; cancel допускается для pending/approved, terminal для этого UUID. После expiry/consumed challenge ничего не меняет. Ни решение, ни start не меняют действующий factor/codes/password/roles/status/session/version и не создают сессию. Дальнейшее completion обязано повторно проверить current primary/policy и текущие OID/name/membership approver, а не доверять одному `state=approved`.

В d.2 notification получает самостоятельную durable запись с encrypted recipient/payload, event/request UUID и временем, **без FK к consumed challenge/request и без требования старого auth_version при доставке**. Job сохраняется в той же транзакции, что factor replacement; pending delivery не удаляется вместе с transient cleanup или обычной audit retention. Использовать существующий lease/backoff/SMTP runner и общий бюджет пула; отдельная таблица/consumer появятся вместе с работающей delivery, не пустой заглушкой в d.1. Нет verified contact — отдельная операторская проверка и уведомление по независимому каналу. До реализации этой гарантии публичное включение recovery запрещено.

Приёмка: no/foreign request/browser/user/operator approval; expired/reissued/cancelled/disabled/revoked; account-wide guessing cap; 16 completions/один winner; concurrent normal login/replace/password reset/role/policy/status changes; audit/outbox failure rollback; no session/privilege до подтверждения; старые factors/codes недействительны только после commit; новые codes не перечитываются; last admin и external-only profiles. Retention/delivery failure не теряют необработанные security events. Capacity — только по отдельным замерам.

Критерий простоты: два owner endpoint + approval/cancel в существующем CLI, один ограниченный emergency request и необходимая durable notification. Без нового login метода, recovery JWT/пароля, отдельного bearer grant, универсального engine или временного MFA-off. Новые SQL entities вводятся только для состояния, которого не представляют существующие session/enrollment/OTP таблицы.

## Основание

[OWASP MFA Cheat Sheet: Resetting MFA / Changing MFA Factors](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html#resetting-mfa) рассматривает recovery как отдельную границу доверия: support должен строго проверять личность, текущей cookie недостаточно, смена фактора требует внешнего уведомления. Workflow/TTL/API выше — проектное предложение Auth, не требования OWASP и не проверенная реализация.
