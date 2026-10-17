# HTTP и браузерная безопасность

## Origin и CORS

Все изменения `/api/v1/auth` и dev send-mail требуют один точный HTTPS `Origin` из `AUTH_ALLOWED_ORIGINS`. Проверка выполняется до JSON, session lookup, SQL/Redis и hashing. Missing/null/foreign/duplicate Origin — 403 `invalid_origin`. Небраузерный клиент передаёт Origin явно; это не credential и не замена аутентификации. GET/HEAD без Origin разрешены, с Origin — проверяются. Новые auth mutations автоматически наследуют политику; будущие provider callbacks требуют отдельного протокольного решения, а не исключения для всех методов входа.

`AUTH_CORS_ENABLED=false` сохраняет same-origin/BFF профиль. `true` разрешает credentialed CORS только точным origins из того же списка, без `*`, suffix matching или доверия Host/forwarded headers. OPTIONS допускает GET/POST/DELETE и только Content-Type, возвращает 204 без session lookup. Недопустимый preflight — 403 `invalid_preflight`; выдача preflight не доказывает существование маршрута или право его выполнить. Реальный запрос проходит обычные auth/permissions/Origin guards. Vary учитывает Origin и параметры preflight; ответы no-store. Retry-After и X-Request-ID доступны разрешённому frontend.

Cookie остаётся `__Host-session`, Secure/HttpOnly/Path=/, без Domain, SameSite=Lax. CORS не меняет SameSite: поддерживается same-site HTTPS frontend (например app.example.com → auth.example.com), не произвольный cross-site embed. Frontend использует `credentials: 'include'`. Allowlist — только origins под вашим контролем. [OWASP: CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Swagger UI того же HTTPS origin продолжает работать: браузер сам формирует Origin для POST, Swagger-параметр документирует контракт для CLI, но не позволяет JavaScript подменить этот заголовок. Добавьте origin Swagger в allowlist. Basic Auth Swagger не даёт бизнес-права, cookie для защищённых операций получают отдельным login. Generated spec проверяется автоматически; настоящая browser-приёмка ещё открыта.

## Cookie и конкурентные ответы

Session hardening AS1–AS4-local: Cookie headers разбираются строгим `http.ParseCookie`; malformed пары и несколько `__Host-session` дают 401 до SQL. Это относится ко всему Cookie header, поэтому некорректная сторонняя cookie тоже не игнорируется. Несколько корректных Cookie строк с одним session name разрешены. Logout-all/revoke/change-password/email-change request используют NoRefreshAuth; они не выполняют sliding UPDATE и не добавляют старый refresh Set-Cookie. GET me/sessions сохраняют refresh. Поздний ответ ранее начатого read всё ещё может заменить cookie после rotation/logout, но старый verifier не становится действительным; coordination/lost response/реальный browser остаются [открытой приёмкой](../planning/auth-security.md#результат-первого-блока-as1as4-local).

## Сроки административных сессий — AS5

Решение 17 октября 2026: выделен независимый admin-профиль. Он применяется при выдаче session пользователю с системной ролью `super_admin` или хотя бы одним из восьми встроенных административных permissions (Access, users, email binding, Auth settings). Имя custom role и URL входа не определяют профиль: публичный password/provider/email OTP + MFA не обходят срок. Product-only роли сохраняют обычный профиль. Добавление административных прав требует нового входа по AS6a/b, а не повышения старой session на месте.

| ENV | Default | Назначение |
| --- | --- | --- |
| `ADMIN_SESSION_IDLE_TIMEOUT` | `30m` | Окно без подтверждённого сервером сообщения об активности |
| `ADMIN_SESSION_ABSOLUTE_TTL` | `12h` | Максимум от выдачи session; не продлевается активностью/refresh/reauth/MFA/rotation |
| `ADMIN_SESSION_ACTIVITY_INTERVAL` | `1m` | Минимальный интервал между SQL-продлениями одной session, общий для tabs/instances |

Это начальные настраиваемые значения, не универсальная рекомендация для любого риска. `SESSION_TTL`/`ABSOLUTE_SESSION_TTL`/refresh threshold продолжают управлять обычными сессиями; admin-профиль имеет собственные сроки, а не наследует 7/14 дней. Fresh password (`SESSION_FRESH_AUTH_TTL`, default `5m`) и существующий fresh MFA проверяются отдельно: активность не обновляет их timestamps и не делает старое подтверждение свежим.

Значения — целые секунды: idle минимум `1m`, absolute не меньше idle, interval от `1s` до idle/10. Настройки фиксируются в session при выдаче; изменение ENV применяется после restart к новым сессиям. Уже выданные не получают новые сроки молча. Для немедленного прекращения доступа используются revoke/logout-all/block. Динамические настройки/UI — последующий A6.3/A7.

### Что считается активностью

`POST /api/v1/auth/session/activity` без тела, client timestamps или UUID. Требует действующую session cookie и разрешённый Origin; `NoRefreshAuth` не продлевает её до обработчика. Ответ `200 {"expiresAt":"…"}`, no-store; Set-Cookie только при закоммиченном продлении, с тем же verifier. Обычная session получает no-op. Неверная/истёкшая session — `401`, Origin — `403`, недоступная зависимость — `503`, без новой cookie. Другие HTTP methods не являются activity endpoint.

UI A7 отправляет запрос после реального взаимодействия (клавиатура/указатель/осознанная команда), объединяя события по interval. Не вызывать из постоянного heartbeat, background polling, автоматического обновления таблиц или просто из открытой вкладки. API-клиент сообщает активность явно; сами административные запросы не заменяют этот протокол. GET `/me`/`sessions`, NoRefreshAuth, rotation и reauth не продлевают admin idle. До подключения UI без activity наступает обычное истечение.

Сервер проверяет факт авторизованного сообщения, а не физическое присутствие человека: обладатель украденной cookie может вызывать endpoint. Поэтому idle не заменяет HttpOnly/Origin/XSS-защиту, отзыв и непродлеваемый absolute deadline. Не доверять полю «я активен» как новому MFA/fresh proof.

### Границы и нагрузка

SQL хранит idle/interval/admin absolute budget и фактические expiry/deadline; lifetime policy неизменяема обычным UPDATE. Общий issuance trigger выбирает профиль, включая MFA INSERT; вызывающий получает реальный RETURNING expiry для cookie. Проверки authority по-прежнему требуют `expires_at > now` и `absolute_expires_at > now`, то есть равенство означает истечение. Generic RefreshSession не продлевает admin session даже при прямом вызове repository.

Activity использует SQL time, ограниченный transaction deadline, current user/version и role-bound session. Условный UPDATE продлевает до `min(SQL now + stored idle, stored absolute)` лишь после интервала; конкурентные tabs/instances не создают по одному UPDATE каждый. No-op читает текущий срок и не пишет cookie; истёкшая/revoked/version-stale/role-stale session не оживает. Подтверждения primary/password/MFA и absolute deadline не изменяются.

Coalescing может завершить session **раньше**, максимум на interval относительно последнего неотправленного/неpersisted события: при defaults ориентир 29–30 минут, а не обещание точного logout на 30:00 от каждого движения мыши. Сетевые потери/фоновые ограничения браузера могут потребовать нового входа. Серверного grace после expiry нет. Синхронизация часов API/SQL обязательна: SQL остаётся конечной authority, часы API могут консервативно отказать раньше; переведённые часы не являются способом продлить SQL deadline. Для plain issuance admin deadline дополнительно ограничен SQL now + budget, даже если часы вызывающего впереди.

Обычный защищённый read не получает дополнительного touch/SQL round-trip. При создании session добавляется ограниченная проверка индексированных ролей/permissions; activity использует прежний pool, user lock и адресный token lookup, не сканирует users/sessions и не создаёт workers/cache/таймер на пользователя. Граница частоты UPDATE не равна нулевой стоимости запросов: admission/deadlines действуют, реальная multi-instance capacity и GC остаются 6.8b/c.

Изменён только source `000001`, не рабочая БД. Для ранее применённой схемы нужен контролируемый перенос schema/code/grants и отзыв прежних sessions/challenges до открытия трафика, как в AS6b. Простое добавление default колонок не классифицирует старые sessions и не считается безопасным backfill. Не запускать mixed fleet со старым refresh, не сбрасывать БД.

Приёмка A7/pre-ui/A8: реальный браузер с tabs, inactivity/interaction, sleep/resume и delayed responses; HTTPS ingress и clock discipline; multi-instance load/отказы. Локальные SQL/HTTP/MFA tests не подменяют эти проверки.

## HTTPS

Обычный режим — TLS на доверенном ingress, внутренний HTTP-порт не доступен извне. Redirect HTTP→HTTPS, HSTS, сертификаты, connection limits и исключение secrets из edge access logs настраиваются на ingress. Приложение не определяет HTTPS по произвольному X-Forwarded-Proto и не включает HSTS на localhost автоматически.

Для прямого HTTPS задайте оба `HTTP_TLS_CERT_FILE` и `HTTP_TLS_KEY_FILE`: сервер использует TLS ≥1.2 и существующий graceful shutdown. Неполная пара отклоняется при старте; ошибка загрузки сертификата не переключает сервер на plaintext. Пустая пара сохраняет внутренний HTTP для ingress.

Локальный профиль: доверенный браузером сертификат с SAN localhost, `PORT=8443`, пути к сертификату/ключу, `AUTH_ALLOWED_ORIGINS=https://localhost:8443`. Откройте https://localhost:8443/swagger/index.html. Для Docker dev файлы должны быть доступны внутри `/workspace` (например `/workspace/tmp/tls/`); ключи хранить в ignored tmp, не в Git или образе. Сертификаты автоматически не генерируются/не устанавливаются, реальные env не изменяются.

## Headers, логи и SMTP

Все HTTP-ответы получают no-store, nosniff, no-referrer и DENY framing. API CSP запрещает загрузку ресурсов; Swagger имеет отдельный CSP без default-src 'none', чтобы не сломать существующие scripts/styles. Это не полная CSP будущего UI; там её задают отдельно.

Access logger пишет route pattern, method/status/duration/request ID, не URL/query/body/Authorization/cookies. Error mapper не пишет сырые dependency errors. Panic recovery не печатает значение panic или stack arguments; ErrAbortHandler сохраняет обрыв соединения. Ingress/SMTP/operator logs также требуют собственного redaction.

Оба SMTP entrypoints используют общий SendContext: dial ≤5s, общий deadline ≤20s или меньше по context, cancellation закрывает socket; STARTTLS с проверкой hostname/certificate и TLS ≥1.2. Production требует SMTP_REQUIRE_TLS=true и не принимает downgrade без STARTTLS. Subject с CR/LF отклоняется до соединения. Implicit TLS на 465 не добавлялся. Настоящие SMTP/certificate delivery, browser/multi-tab и OIDC/linking acceptance остаются release gates.
