# JWT middleware внешнего backend

J5.2-local: `pkg/authjwt` подключается к обычному `net/http`, без `internal/`, chi, SQL/Redis, новых зависимостей и фонового worker. Один `Consumer` создаётся при запуске на фиксированные issuer/audience/mode и переиспользуется запросами. Не создавать его в каждой ручке или по audience/issuer из входного JWT.

## Два режима

- `local`: подпись и claims проверяются локально по актуальному JWKS. Нет SQL/introspection запроса на обычное обращение. Изменение ролей, блокировка или logout учитываются только после expiry токена; по текущему контракту окно может достигать5m30s с учётом рассинхронизации часов. Не подходит для требований немедленного отзыва.
- `strict`: после такой же локальной проверки выполняется один POST в [Auth introspection](jwt-introspection.md), с отдельным service credential. Проверяются current user/session/version/family/policy/grants на стороне Auth. Положительные решения не кешируются; dependency failure никогда не переключает backend в local.

Режим задаётся оператором и должен совпадать с `avm` подписанного токена и настройкой audience в Auth. `strict` токен не принимается consumer в режиме `local`, и наоборот. Переключения клиентов без согласованной выдачи нового типа токенов недостаточно.

## Подключение в Go

```go
consumer, err := authjwt.NewConsumer(ctx, authjwt.ConsumerConfig{
    Expected: authjwt.Expectations{
        Issuer: "https://auth.example.com",
        Audience: "orders",
        Mode: authjwt.Strict,
    },
    JWKSURL: "https://auth.example.com/.well-known/jwks.json",
    IntrospectionURL: "https://auth.example.com/api/v1/internal/auth/token/introspect",
    ClientID: "orders-api",
    ClientSecret: serviceSecret,
})
if err != nil {
    return err // Не открывать traffic; не печатать config/secret.
}
defer consumer.Close()

read, err := authjwt.RequirePermissions("orders.read")
if err != nil {
    return err
}
mux.Handle("GET /orders", consumer.Middleware(read(ordersHandler)))
```

Внутри `ordersHandler`: `p, ok := authjwt.PrincipalFromContext(r.Context())`, затем `p.UserID()`, `p.SessionID()`, `p.Audience()`, `p.ExpiresAt()`, `p.Permissions()`, `p.HasPermission("orders.read_all")`. Principal создаётся только после успешной проверки; credentials в нём нет. Список permissions возвращается копией. `RequirePermissions` требует все перечисленные keys и должен выполняться **внутри** authentication middleware.

Строки/поля/ownership фильтрует backend данных, например SQL запрос по `p.UserID()`. Наличие `orders.read` не разрешает автоматически чужие строки или закрытые поля. SDK не вводит свой каталог ролей и не возвращает весь profile.

Для local: `Expected.Mode=authjwt.Local`, нужный audience, JWKSURL; **не задавать** IntrospectionURL/ClientID/ClientSecret. Лишние service credentials в local config отвергаются, а не молча игнорируются. RootCAs необязателен: по умолчанию системные CA; для частного TLS задаётся `*x509.CertPool`, который клонируется. Отключения проверки сертификатов/hostname нет.

Компилируемые strict/local примеры: [example_test.go](../../pkg/authjwt/example_test.go). Они показывают сборку, не запускают listener и не заменяют backend/server lifecycle. В приложении нужны TLS/разрешённый ingress, graceful shutdown, bounded handlers/DB pools/concurrency, ReadHeaderTimeout/ReadTimeout/WriteTimeout и MaxHeaderBytes. SDK ограничивает свою работу, не все ресурсы чужого сервера.

## HTTP-вход и ошибки

Ровно один `Authorization: Bearer <access JWT>`, без списка credentials/лишних пробелов, header ≤4103 байт/JWT ≤4096. Scheme case-insensitive. Любой Cookie отклоняется, fallback к cookie/query/body/path нет. Обычные business query разрешены до8 KiB; malformed query и keys `token`, `access_token`, `id_token`, `refresh_token`, `authorization` запрещены case-insensitive, включая percent-encoding. Не отправлять JWT в URL/body и не логировать Authorization/токены/конфигурацию/APM bodies.

| HTTP | Причина |
| --- | --- |
| 401 | Нет Bearer, invalid/expired JWT, `active:false`; WWW-Authenticate Bearer |
| 403 | Проверенный principal не имеет требуемого permission; insufficient_scope |
| 429 | Локальный admission либо лимит introspection; Retry-After60 |
| 503 | JWKS/Auth/TLS/deadline/response mismatch/ошибка service credential; Retry-After1 |

Неверный service secret на Auth даёт конечному клиенту503, не ложное «ваш JWT неверен». Ошибки не содержат URL/token/secret/dependency details. Middleware по умолчанию ставит no-store и на успешные защищённые ответы; handler не должен ослаблять эту политику для приватных данных.

Middleware **не настраивает CORS**, не обходит OPTIONS, не выключает CSRF и не меняет browser/admin cookie-маршруты Auth. При необходимом browser bearer API внешний CORS owner задаёт exact origins/methods/Authorization header, обрабатывает preflight до authentication без запуска бизнес-ручки. Не считать Origin или CORS удостоверением сервиса; browser token предпочтительно BFF/память, не localStorage/URL.

## Ключи, сеть и жизненный цикл

- `NewConsumer` получает свежие ключи до возврата; enabled startup без usable JWKS завершается ошибкой. GET только на фиксированный HTTPS URL, без discovery/jku/x5u/redirect/ENV proxy. Разрешённый internal endpoint задаёт оператор и защищает network policy; нет автоматического запрета всех private addresses.
- Один shared transport/cache на экземпляр, ≤32 admitted operations, ≤32 connections/host и≤64 idle total. Общий auth deadline3s, JWKS fetch≤2s, dial/TLS≤1s, headers≤8 KiB. JWKS≤16 KiB/4 public keys, introspection≤8 KiB; compressed/неподходящий media response отклоняется.
- Lazy refresh по запросу/`Ready(ctx)`: максимум одна fetch attempt за10s, concurrent callers объединяются, нет growing negative cache/горутин на каждый kid. Unknown kid не форсирует refresh. Без запросов/health checks фонового обновления нет; следующий запрос при due snapshot сначала попробует fetch.
- Ошибка fetch не продлевает original trust timestamp. Пока snapshot моложе60s, он ещё пригоден; после60s или future timestamp —503 даже для известного kid. После authority I/O повторно проверяются trust lifetime и expiry: ожидание сети их не продлевает.
- HTTP/1 transport с certificate verification/no redirects/no jar/no compression, bounded pool и deadlines. Strict POST не replayable (`GetBody=nil`/без Idempotency-Key); JWKS trace guard блокирует встроенную повторную отправку GET на reused connection. Нет ни application retries, ни recovery storm; это проверено закрытием TLS-соединений до ответа.
- Active introspection сверяется по `iss/sub/sid/jti/audience/expiresAt`, scope — canonical nonempty subset token scope. Неизвестные/duplicate/case/null/trailing поля, ambiguous false с metadata, неправильные типы/права/не-cache-safe ответ →503. `active:false` без metadata →401. Проверяется именно полный token, не набор UUID.
- `Ready(ctx)` проверяет/обновляет только JWKS trust, не делает fake user/introspection probe и не доказывает доступность SQL/Redis/credential/fleet. В strict ошибка настоящего authority запроса всё равно закрывает доступ. Deployment readiness требует отдельной сквозной приёмки.
- `Close()` запрещает новые операции и закрывает idle connections; активные вызовы сохраняют deadlines. Собственных background workers/timers SDK нет; transport управляет bounded connections. Нагрузочный/heap/goroutine/GC профиль пока не измерен.

Для rotation/compromise/restore соблюдать [ADR004](../adr/004-jwt-access-profiles.md#6-ключи-кеш-и-восстановление): consumer cache не лечит старые authoritative JWKS/Auth nodes. Ни local zero-delay revoke, ни мгновенный fleet key retire не обещаются.

## Чек-лист для другого языка

1. Фиксировать issuer/audience/mode/HTTPS URLs из deployment, поддержать ES256/at+jwt и строгие claims/time/size bounds текущего контракта, не просто JWT decode.
2. Ограничить shared cache/refresh/backoff/trust age, body/headers/concurrency/timeouts; unknown kid без fetch storm, нет redirects/retries/secret logs.
3. В strict предъявлять полный access JWT с отдельными per-backend credentials, сопоставлять все response identifiers/expiry и scope subset, не кешировать positive authority и не переключать режим при ошибке.
4. Из trusted result строить principal, отдельно проверять route permission и объектные/полевые права. Никакого cookie/query fallback или автоматического CSRF bypass.
5. Пройти negative/rotation/outage/expiry/cancellation tests и реальную deployment/load/GC/restore приёмку. Совместимость OAuth/OIDC/RFC7662 этим собственным wire contract не заявляется.

Локальное evidence — [history](../planning/history.md#результат-j52-local--17-октября-2026). Real ingress/multi-instance/fleet rotation/recovery/load/GC/restore остаются J7/pre-ui/A8, RPS не установлен.
