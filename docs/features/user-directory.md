# Список и карточка пользователей — 10.6a-local

## Доступ и ручки

| Метод | Назначение |
| --- | --- |
| GET `/api/v1/admin/users` | Страница nondeleted пользователей с ограниченными фильтрами |
| GET `/api/v1/admin/users/{id}` | Карточка конкретного UUID, включая retained soft-deleted запись |

Нужно отдельное `accounts.users.read` и действующая `__Host-session` SQL-сессия active/nondeleted пользователя с актуальной auth_version. `accounts.users.manage`, управление ролями или знание UUID сами по себе не дают просмотра. Read permission не позволяет создать пользователя, назначить роль, заблокировать, удалить или восстановить аккаунт.

Чтения работают независимо от INVITATIONS_ENABLED/TEMPORARY_PASSWORD_ENABLED/MFA_ENABLED. Новый password/MFA step-up для просмотра не требуется; применённая к входу MFA policy этим не отменяется. NoRefreshAuth не продлевает сессию или freshness, Set-Cookie не выдаётся. Ответы no-store. GET без Origin допустим для CLI; переданный Origin должен быть разрешён. Авторизация и чтение выполняются одним SQL statement после session middleware; следующий запрос после committed revoke видит актуальные права. Уже начавшееся чтение не отменяется автоматически последующим отзывом.

Новая чистая установка получает восемь core permissions, включая users.read, отдельные status/delete и auth.settings.manage (backend store A6.1, ещё не settings HTTP). Existing roles не расширяются автоматически; upgrade прежней установки требует отдельного контролируемого назначения и применения индексов. Нет автоматического self-promotion или повторного setup. Изменения пользователя описаны в [административном lifecycle API](account-deletion.md#административный-api--106b-local).

## Список

```text
GET /api/v1/admin/users?status=pending&limit=50
GET /api/v1/admin/users?email=user%40example.com
GET /api/v1/admin/users?before=<nextCursor>&limit=50
```

- `limit`: 1..100, по умолчанию 50. `status`: pending/active/blocked, либо фильтр отсутствует. Soft-deleted записи всегда исключены, даже при status=blocked.
- `email`: точный нормализованный адрес через существующий domain.NewEmail, без wildcard/substring/full-text поиска. Находит owner любого сохранённого контакта. Display email предпочитает контакт password credentials, иначе первый сохранённый по UUID; поэтому при нескольких контактах найденный адрес может отличаться от display email. Полный ограниченный список контактов — в карточке.
- Порядок `created_at DESC, id DESC`, исключающий `before`. Cursor — не secret и не полномочие; передавать полученный nextCursor с теми же фильтрами. Некорректный/неканонический cursor отклоняется, размер ограничен 192 символами.
- Ответ `{users:[...],nextCursor:"..."}`. На последней странице cursor пустой. Читается limit+1 кандидатов, без OFFSET/count и запроса для каждого пользователя. При равных датах UUID даёт однозначный порядок. Межстраничный snapshot не обещается: параллельные создания/смена фильтруемых полей/удаления могут менять набор.

Строка содержит id, status, createdAt, nullable displayName/email и emailVerified выбранного display contact. Полное имя, телефон, произвольные profile fields и секреты не выгружаются. GET-фильтр email содержит PII: application logger сохраняет route pattern без raw query, прокси/аналитика также должны исключать query/тела/ответы из логов.

## Карточка

Дополнительно к summary:

- `authVersion`, `accessVersion`, nullable `deletedAt` — текущие metadata, не новая session authority. Access version не является ETag effective permissions всех ролей.
- `passwordConfigured` — сохранён постоянный credential; `temporaryPasswordRequired` — durable обязательная установка пароля ещё не завершена; `mfaEnrolled` — сохранён фактор. Это не обещание разрешённого сейчас входа: нужны status, policy, expiry и реальные proofs.
- `contacts`: email/nullable verifiedAt; `externalIssuers`: только публичные issuer identifiers, без subject; `roles`: ID/key/name/system/version, без permissions или скрытого wildcard bypass. Для effective permissions существует отдельный Access API с собственными правами.
- Контакты, внешние issuer и роли ограничены 32 записями каждый. SQL читает максимум 33 для обнаружения превышения; тогда 409 directory_conflict вместо скрытого усечения. Не использовать DTO как last-method/MFA/authorization guard.

Не возвращаются hash пароля, session/challenge tokens или hashes, encrypted factor, MFA secret, QR/recovery codes, operator credentials или external subject. Чтение soft-deleted UUID не восстанавливает профиль/контакты/методы и не выдаёт сессию; показывает только оставшееся в БД. После retention поля могут отсутствовать.

## Ошибки и ресурсы

400 invalid_query/invalid_email; 401 unauthorized; 403 forbidden/invalid_origin; 404 user_not_found только для авторизованного просмотра неизвестного UUID; 409 directory_conflict; 503 temporarily_unavailable. Неавторизованный actor получает одинаковый forbidden для существующего/отсутствующего target. Некорректный формат UUID — invalid_query. Неизвестные и повторные query parameters отклоняются.

Операция ограничена 3s и использует existing pool, без нового Redis cache, worker или read-side транзакционного advisory lock. Авторизация встроена в тот же statement, включая случай пустой страницы: отсутствие пользователей не превращает valid read в forbidden. Нет параллельной загрузки N карточек внутри списка.

В initial migration добавлены partial B-tree indexes `users_directory_page(created_at DESC,id DESC)` и `users_directory_status_page(status,created_at DESC,id DESC)` для nondeleted rows. Exact email использует existing unique user_emails_email_key, затем users PK. Подзапросы контактов/методов/ролей используют owner indexes и bounds. Индексы увеличивают стоимость записи пользователя; это целевой компромисс для ограниченного чтения больших каталогов, не cache authority. Отдельного migration file/рабочего down/reset нет: existing deployment требует согласованного upgrade.

Локально проверяются HTTP/SQL/Swagger/race, permission/session/version guards, UUID tie-break и relation overflow. EXPLAIN реальных запросов с 100000 синтетических пользователей/контактов проверяет default/status/cursor/exact-email access paths; это не HTTP throughput/RPS или full production capacity. Внешняя backend-приёмка обязательна **перед UI**, затем повторная сквозная приёмка с UI в A8. Блокировка/разблокировка/удаление через admin API — следующий отдельный подэтап 10.6b, здесь их нет.

После появления GET на /admin/users выключенная POST mutation на том же пути отвечает 405 (метод не зарегистрирован), а не прежним 404 отсутствующего пути. GET /admin/users/temporary-password сопоставляется с UUID-card route и отклоняется service как invalid_query; он не выполняет issuance. Routes с дополнительным /invitation или /temporary-password не становятся GET mutations.
