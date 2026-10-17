# JWT/session recovery: условия открытия трафика

Этот документ дополняет [ADR004](../adr/004-jwt-access-profiles.md#6-ключи-кеш-и-восстановление). Реальный restore, смена secrets или запуск production здесь не выполнялись. Ответственный оператор должен подтвердить каждый шаг на разрешённом стенде; нет подтверждения — traffic остаётся закрытым.

## Что уже делает restore-wrapper

`task restore FILE=… CONFIRM=project:database` вызывает `deploy/scripts/postgres-restore.sh`: проверка archive, остановка локальных api/migrate/backup, восстановление, migrate up, grants, **SQL-инвалидизация восстановленного Auth** и DB healthcheck. После успеха **API остаётся остановленным**, даже если работал до restore. Возобновляется только ранее работавший backup scheduler. Ошибка не должна запускать сервисы или выглядеть как успешная security acceptance.

Это не global traffic fence: другие hosts/replicas/external workers останавливает оператор. `task prod:up`, restart policy, deploy-controller или ручной запуск не знают, выполнен ли recovery gate. Не вызывать их до приёмки. Wrapper инвалидирует SQL credentials, но **не меняет JWT trust/files, Redis flows, постоянные пароли, статусы, роли или внешние identities**.

## SQL-инвалидизация — J7.2-local

В wrapper включён `deploy/restore-auth-state.sql`, выполняемый через owner `psql -X -v ON_ERROR_STOP=1`. Это не миграция, не ручка API и не фоновый worker. Файл сам содержит BEGIN/COMMIT: ошибка любого шага откатывает весь отзыв вместе с аудитом. Не добавлять вокруг него `psql --single-transaction` с расчётом на вложенную транзакцию. Режим `-X` исключает локальный psqlrc.

| Данные | Действие |
| --- | --- |
| Cookie/API sessions, refresh families | Выставить revoke для ещё не отозванных; сохранить ledger, refresh verifiers/history и audit |
| Users | Повысить auth_version; не менять status/deleted/access_version, email, profile, roles или identities |
| Verification, reset, email OTP/reauthentication, email binding | Удалить одноразовые доказательства вместе с каскадной очередью доставки; binding содержит свою очередь |
| MFA login/enrollment/recovery requests | Удалить pending/approved challenges/intents; старое approval не продолжает enrollment |
| MFA recovery codes | Удалить весь восстановленный набор: backup не доказывает, какие коды уже использованы; новый набор через обычное управление MFA после TOTP login |
| TOTP | Сохранить encrypted secret/enabled_at; last_step поднять не ниже SQL current30s-step+1 (нынешнее окно +/-1), не уменьшать уже больший counter. В текущем окне код может временно не приниматься; дождаться нового, примерно до60s |
| MFA recovery notifications | Пометить ожидающие как failed/attempts5, убрать lease; сохранить запись, не выдавать это за отправку |
| Email change/report/recovery | Отменить usable states, удалить recovery authority/payload и outbox; оставить запись/историю и audit, не откатывать email самостоятельно |
| Invitations, temporary password/continuation | Удалить восстановленные credentials/outbox; оставить user/account_provisions и idempotency/reissue records. Pending пользователь требует нового приглашения/временного пароля |

В конце той же транзакции пишется `auth.restore_audit`: DB identity оператора, имя БД, время и количество затронутых users, без raw credentials/keys. Это отдельный operational event, не поддельное событие «смена пароля» для каждого пользователя. Initial source000001 содержит таблицу; новых migration files нет. Для старой установленной схемы нужен controlled upgrade, не повтор initial migration/reset. Отсутствующая таблица или несовместимая схема дают отказ, а не пропуск аудита.

Требуется session/table owner без SET ROLE; runtime отвергается до изменений. Reviewed runtime-grants дополнительно запрещают runtime INSERT/UPDATE/DELETE audit. Операция берёт existing exclusive Access advisory lock без ожидания и explicit table locks с lock_timeout5s; statement_timeout5min на statement. Это **offline полный проход**, не оптимизация горячего пути и не обещание фиксированной длительности для большой БД. Успешное получение locks не доказывает остановку fleet после commit; остановка writers и закрытый traffic остаются обязанностью оператора. Нужное окно/WAL/место измерять на разрешённой копии.

Повтор безопасен в смысле отзыва: не восстанавливает credentials, не удаляет accounts/roles/factors. Это не exact no-op: auth_version снова растёт, добавляется audit, TOTP counter не уменьшается. Не запускать регулярно и не запускать после возобновления traffic. Ошибка/timeout — оставить API остановленным, исправить причину и повторить при закрытом traffic.

## Восстановление БД

1. Закрыть внешний и внутренний traffic к Auth/resource backends; остановить все Auth instances/issuance и background delivery. Убедиться, что orchestrator не поднимет старый pod автоматически. Зафиксировать backup/time/версию схемы и конфигурации без secrets в журнале.
2. Выполнить согласованный DB restore при закрытом traffic. DB healthcheck подтверждает только работоспособность БД, не безопасность восстановленного auth state. Source000001 не является upgrade script для существующей старой схемы.
3. До старта Auth инвалидировать восстановленные cookie/API sessions, refresh families и одноразовые login/MFA/enrollment/reset/verification/invitation/email-change/provisioning credentials вместе с ожидающей доставкой. Восстановленные spent MFA recovery codes также нельзя считать неиспользованными; требуется согласованное перевыпускание/восстановление доступа. Политика не должна сбрасывать БД, роли, профили или автоматически создавать нового super-admin.
4. Убедиться в успешном commit SQL-инвалидизации и новой записи restore_audit; при ошибке исправить причину при закрытом traffic и повторить reviewed SQL, не ad-hoc DELETE. Отдельно согласовать потерянные после backup изменения постоянных паролей/TOTP, blocked/deleted статусов, ролей, contacts/identities и settings. Backup возвращает их point-in-time значения: SQL-отзыв временных credentials не может восстановить отсутствующую историю. При необходимости выполнить individual recovery/rotation/reconciliation по независимому incident record до открытия traffic; старый пароль после восстановленного password reset не объявляется автоматически забытым.
5. Создать отдельный новый signing key с новым kid вне БД. Удалить старые verification keys из authoritative JWKS **всех** Auth nodes, обновить pinned issuer verifier; исключить восстановление old manifests вместе с backup. Перезапуск с прежним JWKS оставляет local access пригодным, даже если SQL sessions уже отозваны.
6. Подтвердить новый trust у каждого consumer: controlled refresh/readiness + negative old-token probe либо restart с проверенной конфигурацией. Нет old nodes/old trust responses; нельзя отсчитывать cache window от первого обновлённого pod. Положительный healthcheck Auth не доказывает состояние consumer.
7. Проверить: старые cookie/access/refresh/одноразовые credentials не работают; service identity отдельная и валидна; новый полноценный login/MFA и strict request работают; logout/replay/revoke/fail-closed сохранены. Лишь затем отдельно разрешить запуск/traffic и delivery workers, записать evidence. NOT RUN — не разрешение открытия.

Нет предположения, что восстановленная SQL policy/UI settings отзывают скомпрометированный deployment key. Локальный JWT автономен от SQL authority и после logout сохраняет окно до expiry, если key ещё trusted; поэтому удаление old trust обязательно для выбранного restore policy.

OIDC browser flows находятся в Redis и не входят в этот SQL script: при остановленных всех writers дождаться их действующего TTL5min после последнего создания/восстановления Redis state либо выполнить отдельно согласованную изолированную очистку flow namespace. Не выполнять FLUSHDB/FLUSHALL или сброс общих лимитов. Если Redis snapshot снова восстанавливается, отсчёт/проверка выполняются заново. Доказательство этого fleet/drain шага — external gate, не SQL audit.

## Что проверено локально

`TestRestoreAuthStateSchema` требует одновременно explicit localhost auth_schema_test DB и выделенный `AUTH_RESTORE_TEST_CONTAINER=auth-j72-…`. Использует настоящий PostgreSQL18 pg_dump/pg_restore: backup до cookie logout/password reset/refresh replay/MFA consumption, затем восстановление, подтверждение возвращения старого доступа и execution **того же SQL-файла через psql**. Проверены отказ runtime/занятый Access writer, rollback при audit failure, отсутствие старых cookie/strict JWT/refresh/reset/MFA/temporary credentials, очистка всех seeded proof/outbox owners, retry/audit и неизменность accounts/roles/identities/profiles/permanent password/TOTP/provisioning. Новая current primary proof выдаёт новую family; полный реальный login/UI здесь не тестируется.

Fake-Docker wrapper test проверяет порядок restore → invalidation → healthcheck и отсутствие API restart, включая invalidation failure. Disposable drill не запускает production wrapper против рабочей среды, не переключает реальные JWT keys, не проверяет старые local JWT после fleet distrust и не измеряет capacity/WAL/GC. [Матрица](jwt-security-acceptance.md) сохраняет внешние gates открытыми.

## Компрометация key без restore

- Немедленно закрыть traffic, если допустимое окно не позволяет дождаться подтверждения всех consumers; остановить старые signers.
- Новый key/kid; убрать compromised kid из всех authoritative trust sets и pinned verifiers. Не оставлять ordinary overlap с украденным key: attacker может выпускать новые JWT.
- Consumer trust age ограничен60s, fetch attempt interval10s, но отсчёт bounded stale cache корректен только после прекращения **всех** old authoritative responses. Если node/backup/proxy снова отдаст старый keyset, это новая загрузка старого trust, а не защита от resurrection.
- До подтверждённого distrust/restart не открывать traffic. Проверить украденным/ранее подписанным synthetic token negative acceptance на стенде; actual secrets не публиковать.

Обычная planned rotation отличается: prepublish нового public key, обновление consumers, смена signing, max TTL+30s после последней старой выдачи, затем retirement. При компрометации одно ожидание TTL недостаточно. Задержки/проверка fleet — открытая внешняя приёмка, не доказанная локальным rotation unit test.
