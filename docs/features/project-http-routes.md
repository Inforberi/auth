# Проектные HTTP-профили

MP5.1b, 25 октября 2026. Реализован внутренний HTTP factory/dispatcher, локальные проверки Luna V1/V2 PASS.

- Использовать готовый ProjectProfile и existing handlers, не общий router с административными маршрутами. Узкие public password/verification handlers выделить из широких handlers без копирования DTO/логики и смены API.
- Exact route allowlist из RoutePlan сопоставляется реальным handlers. Browser mutations требуют exact Origin; callback GET сохраняет state/PKCE/nonce/browser binding, native требует cookie-free JSON/no Origin, introspection — собственный service Basic transport, exchange/reauth — SQL session без продления. CORS не включать.
- Bounded resident dispatcher выбирается только NewRuntimeBoundary context. Ограничить число residents/одновременных cold builds, общий request admission/deadline один на процесс. Сборка не на каждый запрос; current key/policy проверяются перед использованием. При конфликте устаревшая запись удаляется, следующая сборка использует свежие настройки. Не кешировать разрешение пользователя или positive project authority.
- Lazy rebuilding не создаёт новых SQL/Redis pools/workers/ключей. У entries нет собственных closers; shared dependencies закрывает прежний owner после HTTP drain. Shutdown закрывает новый admission и ждёт активные запросы с context deadline, без принудительного закрытия чужих ресурсов.
- Этот блок предоставляет сборку handler/dispatcher для доверенного deployment. Не включает production opt-in автоматически, не меняет catalog phase-ready, не публикует account/MFA management или UI. Настройки deployment/config source и окончательная server integration остаются явными отдельными gates.
- Main formatter/source diff, Luna task check/affected race/security и actual SQL+TLS+Redis route acceptance. Проверить Origin/native/service/session isolation, stale policy/rebuild/suspend, concurrent cold build/bounds/cancellation/shutdown. Внешние provider/SMTP не заявлять проверенными.

## Использование и владение

`app/auth.NewProjectHTTP` принимает доверенный `ProjectProfileSource`, existing profile dependencies и `ProjectHTTPConfig`. Source возвращает operational config для переданных key/origin, не берёт проект из body/cookie/JWT. Это программная сборка для deployment: основной production router и реальные ENV этим блоком не меняются. Созданный handler нужно подключать отдельной явной настройкой сервера после полной приёмки.

`router.NewProjectRuntime` создаёт общий base middleware/admission один раз, затем exact TLS/authority boundary и resident dispatcher. `NewProjectRoutes` — внутренний leaf router, который используется за этой границей, сам по себе не является project selector. `projectHTTPRoutes` дополнительно проверяет совпадение immutable selection с профилем. В нём нет setup/admin/link/unlink/MFA management/account CRUD endpoints; отсутствующий обработчик или неизвестный protection не превращается в открытый fallback.

Широкие legacy password/account handlers сохраняют существующие конструкторы и API. Публичные методы вынесены во встроенные `PublicPasswordHandler`/`VerificationHandler` с узкими интерфейсами. DTO, Swagger annotations и обработка ошибок остаются прежними. Проектные адаптеры только сопоставляют существующие названия методов, не реализуют бизнес-правила повторно.

## Защита маршрутов

| Профиль | Подключение |
| --- | --- |
| browser | Existing BrowserProtection с единственным exact project origin; mutation без Origin запрещена, CORS выключен |
| callback | Тот же browser guard допускает GET без Origin; actual OIDC handler проверяет scoped state, PKCE/nonce и browser binding |
| session_no_refresh | BrowserProtection, затем existing NoRefreshAuth и project SQL session validation; cookie не продлевается |
| native | Existing NativeHandler.Protect запрещает Origin/OPTIONS и Cookie/Authorization/query credentials |
| service | Existing introspection Inspect сам запрещает browser transport и проверяет собственные Basic credentials |
| public_keys | Existing JWKS response, но public bytes получаются через project current guards на каждый запрос |

Для session validation берётся session config готового browser метода, reauth-only OTP либо native profile. Только JWT-only exchange без такой конфигурации требует явный `SessionValidation` fallback в HTTP operational config. Он валидируется; duration defaults не изобретаются. Validation происходит внутри bounded registry lease, с current catalog guards и SQL `FindSession` authority. Сессию блокированного/удалённого пользователя, stale auth_version и revoked/expired session отвергает существующий слой.

На HTTP hot path используется уже разрешённый boundary key: повторного exact-origin lookup нет. Проверка полного SQL policy snapshot и финальный catalog guard сохранены. Это не кеш разрешений. Уже начатые операции завершаются в ранее согласованном admission window; распределённый rollback не обещается.

Email routes и регистрация с verification дополнительно проверяют, что delivery runner продолжает работать. Возобновление внешнего SMTP/Redis не считается мгновенно проверенной доставкой; ошибки actual operations остаются fail-closed.

## Кеш сборок и завершение

`RuntimeDispatcherConfig` ограничивает `MaxProfiles` (1..256), `MaxBuilding` (1..MaxProfiles), `BuildTimeout` (>0..30s), `MaxAge` (1s..5m). Это explicit deployment значения, новых ENV не добавлено. Общий HTTP admission/deadline задаётся прежним CapacityConfig и ограничивает также ожидающие SQL операции. Source/loader обязан соблюдать context.

Записи immutable после публикации. Кеш ограничен по числу residents; LRU удаляет только готовые записи и не закрывает общие зависимости. Ссылки активных запросов могут пережить eviction до их bounded завершения — их число ограничивает общий admission. Cold build резервирует слот; parallel build того же origin или исчерпание build capacity возвращает503 без очереди. Loading entry не вытесняется другим поколением. Mutex не удерживается во время SQL/Redis/factory вызовов.

Перед каждым dispatch проверяется policy/current key. Конфликт возвращает404 и удаляет только ту запись, которую проверяли; следующий запрос собирает свежую. Dependency failure —503 без сырых ошибок/секретов, также удаляет запись. Boundary проверяет suspend на каждом запросе, независимо от кеша. MaxAge заставляет повторять локальную readiness, чтобы ранее отсутствовавшие credentials/dependencies не оставались недоступны навсегда. Изменение operational source применяется не позднее следующей сборки/MaxAge; этот кеш не является моментальным UI configuration push.

`ProjectHTTP.Close(ctx)` прекращает admission и ждёт активные запросы/сборки. При deadline возвращает context error, не закрывает SQL/Redis/HTTP clients под активным запросом. Повторный Close может дождаться drain. Порядок владельца: server drain → ProjectHTTP.Close → delivery/registry/shared owners; в основной app lifecycle эта новая сборка пока не подключена автоматически.

## Проверки и открытые границы

Добавлены unit route-protection/allowlist tests, cache reuse/eviction/stale policy/age, cold-build capacity/cancellation/shutdown. В actual command fixture добавлен TLS HTTP login с реальным SQL пользователем, host-only Secure/HttpOnly cookie, no-Origin/foreign-Origin отказ, SQL session без refresh, block, stale policy/rebuild и suspend. Synthetic SQL state восстанавливается, только свои Redis keys удаляются.

Main: formatter и targeted source review. Luna: task check, API contract, targeted race, security и actual полный TestPrepareCommandSQL на Linux ARM64/TLS/SCRAM/Redis стенде. V1: API/security/actual полный SQL PASS, task check/router race FAIL на nil legacy handler, lint QF1008. Исправлены optional public binding guard и избыточный selector; V2 task check/router race PASS; manifest24 совпал после прогона и с main. Полная two-project cookie/token/role matrix, внешний Google/Telegram/SMTP, server opt-in/lifecycle wiring, catalog phase-ready, management routes, fleet/GC/RPS и UI остаются открытыми. Существование тестов не считается PASS.
