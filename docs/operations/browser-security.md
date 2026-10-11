# HTTP и браузерная безопасность

## Origin и CORS

Все изменения `/api/v1/auth` и dev send-mail требуют один точный HTTPS `Origin` из `AUTH_ALLOWED_ORIGINS`. Проверка выполняется до JSON, session lookup, SQL/Redis и hashing. Missing/null/foreign/duplicate Origin — 403 `invalid_origin`. Небраузерный клиент передаёт Origin явно; это не credential и не замена аутентификации. GET/HEAD без Origin разрешены, с Origin — проверяются. Новые auth mutations автоматически наследуют политику; будущие provider callbacks требуют отдельного протокольного решения, а не исключения для всех методов входа.

`AUTH_CORS_ENABLED=false` сохраняет same-origin/BFF профиль. `true` разрешает credentialed CORS только точным origins из того же списка, без `*`, suffix matching или доверия Host/forwarded headers. OPTIONS допускает GET/POST/DELETE и только Content-Type, возвращает 204 без session lookup. Недопустимый preflight — 403 `invalid_preflight`; выдача preflight не доказывает существование маршрута или право его выполнить. Реальный запрос проходит обычные auth/permissions/Origin guards. Vary учитывает Origin и параметры preflight; ответы no-store. Retry-After и X-Request-ID доступны разрешённому frontend.

Cookie остаётся `__Host-session`, Secure/HttpOnly/Path=/, без Domain, SameSite=Lax. CORS не меняет SameSite: поддерживается same-site HTTPS frontend (например app.example.com → auth.example.com), не произвольный cross-site embed. Frontend использует `credentials: 'include'`. Allowlist — только origins под вашим контролем. [OWASP: CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

Swagger UI того же HTTPS origin продолжает работать: браузер сам формирует Origin для POST, Swagger-параметр документирует контракт для CLI, но не позволяет JavaScript подменить этот заголовок. Добавьте origin Swagger в allowlist. Basic Auth Swagger не даёт бизнес-права, cookie для защищённых операций получают отдельным login. Generated spec проверяется автоматически; настоящая browser-приёмка ещё открыта.

## HTTPS

Обычный режим — TLS на доверенном ingress, внутренний HTTP-порт не доступен извне. Redirect HTTP→HTTPS, HSTS, сертификаты, connection limits и исключение secrets из edge access logs настраиваются на ingress. Приложение не определяет HTTPS по произвольному X-Forwarded-Proto и не включает HSTS на localhost автоматически.

Для прямого HTTPS задайте оба `HTTP_TLS_CERT_FILE` и `HTTP_TLS_KEY_FILE`: сервер использует TLS ≥1.2 и существующий graceful shutdown. Неполная пара отклоняется при старте; ошибка загрузки сертификата не переключает сервер на plaintext. Пустая пара сохраняет внутренний HTTP для ingress.

Локальный профиль: доверенный браузером сертификат с SAN localhost, `PORT=8443`, пути к сертификату/ключу, `AUTH_ALLOWED_ORIGINS=https://localhost:8443`. Откройте https://localhost:8443/swagger/index.html. Для Docker dev файлы должны быть доступны внутри `/workspace` (например `/workspace/tmp/tls/`); ключи хранить в ignored tmp, не в Git или образе. Сертификаты автоматически не генерируются/не устанавливаются, реальные env не изменяются.

## Headers, логи и SMTP

Все HTTP-ответы получают no-store, nosniff, no-referrer и DENY framing. API CSP запрещает загрузку ресурсов; Swagger имеет отдельный CSP без default-src 'none', чтобы не сломать существующие scripts/styles. Это не полная CSP будущего UI; там её задают отдельно.

Access logger пишет route pattern, method/status/duration/request ID, не URL/query/body/Authorization/cookies. Error mapper не пишет сырые dependency errors. Panic recovery не печатает значение panic или stack arguments; ErrAbortHandler сохраняет обрыв соединения. Ingress/SMTP/operator logs также требуют собственного redaction.

Оба SMTP entrypoints используют общий SendContext: dial ≤5s, общий deadline ≤20s или меньше по context, cancellation закрывает socket; STARTTLS с проверкой hostname/certificate и TLS ≥1.2. Production требует SMTP_REQUIRE_TLS=true и не принимает downgrade без STARTTLS. Subject с CR/LF отклоняется до соединения. Implicit TLS на 465 не добавлялся. Настоящие SMTP/certificate delivery, browser/multi-tab и OIDC/linking acceptance остаются release gates.
