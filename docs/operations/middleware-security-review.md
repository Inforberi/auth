# Source review HTTP/Auth — 4 ноября 2026

Область: middleware и подключение маршрутов standalone/operator/project/onboarding; browser cookies и SQL session validation; OAuth callback; native/introspection; JWT consumer. Это чтение исходников, не pentest, не проверка всех 990 файлов на уязвимости и не PASS runtime/security suites. Закрытие gates — по отдельному receipt Luna.

## Подтверждённые механизмы

| Граница | Реализация и наблюдение |
| --- | --- |
| Общая HTTP-цепочка | `router.baseRouter`: request logger → security headers → recoverer → bounded admission/deadline → trusted proxy IP. Health live обходит admission намеренно |
| Browser CSRF/CORS | `middleware.BrowserProtection/RequireOrigin`: мутация требует ровно один разрешённый HTTPS Origin; wildcard/Origin null не разрешаются. GET/HEAD без Origin допустимы; callback дополнительно защищён своим flow. Credentialed CORS включается явно, preflight ограничен methods/headers |
| Cookie | `session/transport/http/cookies.go`: __Host-session, Secure, HttpOnly, Path=/, без Domain, SameSite=Lax; malformed/duplicate/noncanonical tokens отвергаются |
| Session authority | SQL FindSession читает `auth.role_bound_sessions`: current auth_version, active user, revoked/absolute/rolling expiry; view проверяет role/MFA revisions и factor proof. Продление CAS не воскрешает отозванную сессию. Mutations используют NoRefreshAuth и собственные transaction guards |
| Project isolation | Runtime boundary требует TLS/точный host, сверяет Origin, получает current key; routes/session adapters проверяют выбранный key/origin и актуальность. Unknown project не выбирает запасной Auth |
| OAuth callback | Отдельные code/state без duplicates; ровно одна flow cookie, single-use Consume, PKCE/nonce проверяются в flow/client. Linking связан с неизменённой session, email не объединяет аккаунты автоматически |
| Telegram webhook | Browser headers/query запрещены; scoped budget до decoding, webhook secret проверяется decoder до обработки start. Project lease, receipt и единственная доставка сохраняют прежнюю последовательность |
| Native | Protect отвергает Origin/OPTIONS/cookie/Authorization/query, credentials только JSON; это не browser-cookie маршрут |
| Introspection | Отдельные Basic service credentials, единственный bounded Authorization; cookie/Origin/query запрещены. Проверяется current SQL authority, ошибка authority закрывает доступ |
| JWT consumer | ES256, typ=at+jwt, trusted kid; точные issuer/audience/mode, bounds времени, подпись. Strict использует online authority; local намеренно не обеспечивает мгновенный отзыв |
| Ресурсы и логи | Server header/body deadlines, MaxHeaderBytes; DecodeJSON ограничивает body и запрещает неизвестные поля/trailing object. Логи используют route pattern/request ID, не raw URL/query/токены; recoverer не выводит panic arguments |

Прямого подтверждённого обхода authentication/CSRF/project isolation в прочитанных цепочках не найдено. Это ограниченный результат source review, а не доказательство отсутствия уязвимостей.

## Уточнения и открытая приёмка

1. HTTPS — обязательное условие deployment. `server.Run` поддерживает plaintext за доверенным ingress; Basic/introspection/standalone не определяют TLS по заголовкам. Plaintext listener нельзя публиковать в недоверенную сеть. Project/onboarding требуют `r.TLS != nil`: нужен прямой TLS или re-encryption ingress→backend; простой X-Forwarded-Proto этого не заменяет. Уточнить deployment-инструкцию и проверить выбранный реальный topology до выпуска. Доверенные proxy должны очищать/корректно дополнять forwarded headers; CIDR не заменяет такой контракт.
2. HSTS сейчас не устанавливается приложением; определить его на HTTPS ingress после согласования доменов, не включать includeSubDomains/preload автоматически. Это deployment hardening, не найденный auth bypass.
3. Не добавлять единый дополнительный auth middleware на callback/webhook/native/JWKS: у каждого протокольный контракт. Публичный JWKS — ожидаемое поведение. Business permissions/fresh auth проверяются сценариями и SQL, общая проверка сессии их не заменяет.
4. JWT local допускает работу подписанного токена до expiry (документированное окно до 5 минут30 секунд); для мгновенного отзыва выбирать strict. Это настройка модели доверия, не исправлять её скрытым кешем или изменением API.
5. При review возникло подозрение о duplicate JSON в JWT. Оно не подтвердилось: `pkg/authjwt/decode.go` импортирует **go-jose/v4/json**, не encoding/json. Установленный v4.1.6 (`json/decode.go`, duplicate checks) отклоняет повторные ключи. Не переписывать parser на основании ошибочного предположения.
6. Luna проверяет текущий refactor и адресно существующие middleware/cookie/OIDC/JWT tests, а не повторяет все load/security suites. Требуемые negative cases: Origin отсутствует/null/foreign/duplicate, preflight, duplicate cookie, revoked/version-changed session, project mismatch, unavailable authority, webhook admission/secret, JWT alg/iss/aud/expiry и старый key snapshot. Из source review нельзя поставить этим тестам PASS.

## Статус рефакторинга

Первый запуск Luna по `auth-layer-boundaries-v1-au1l0lv6` остановился на unused import `projectbrowser` в `app/admin/project_http_deployment_test.go`. Import удалён, код отформатирован; повторная приёмка проводится на следующем immutable snapshot. Race/SQL/Redis первого запуска не выполнялись. Архитектурное разделение реализовано, окончательная корректность и готовность требуют PASS нового снимка.

Приёмка Luna V2 завершена: targeted security tests/lint/race и 11 SQL/HTTP roots PASS; receipt `/private/tmp/auth-layer-boundaries-v2-summary.json`. Проверки Origin/preflight, malformed/ambiguous cookies, OIDC flow/linking, JWT claims/keys/current authority и webhook admission/secret выполнены. Это подтверждает перечисленные сценарии на тестовом стенде; pentest/scan/load и реальный ingress topology в этот прогон не входили.
