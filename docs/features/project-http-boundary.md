# Выбор проекта по HTTP authority

MP5.0, 25 октября 2026. Первый подэтап HTTP isolation перед публикацией Auth. Код и локальные проверки Luna завершены успешно.

- Добавить restricted exact-origin resolver: одна индексная выборка private catalog reader возвращает только validated runtime Key, не DSN/password/ciphertext. Переиспользовать runtime profile и snapshot predicate; ready/enabled/version/generation/physical binding нужны одновременно. Не искать проект через PageRuntimes, slug/header/body/token и не кешировать positive admission.
- Добавить HTTP boundary для уже явно собранного handler: прямой TLS, exact canonical registered Host, исключённый platform Origin, отсутствие forwarded-host fallback; абсолютная request authority не должна противоречить Host. Immutable request context selection, без process-global current project. Origin при наличии обязан совпадать; полноценная browser/service/callback защита остаётся в явном профиле маршрута.
- Resolver проверяет canonical origin до SQL. HTTP проверяет форму request authority, а не повторяет domain validation. Не менять shared BrowserProtection/CORS/CSRF и не разрешать universal Origin bypass. Unknown/disabled/incomplete project —404, dependency failure —503, без раскрытия metadata.
- Lookup bounded existing3s, ограничение на HTTP concurrency/deadline остаётся у outer process admission. Не создавать новый SQL pool/cache/worker или отменять исходный handler context после lookup.
- Это не feature-readiness: catalog ready сам по себе не доказывает capabilities/providers/SMTP/token routing. Не регистрировать public Auth routes и не публиковать ready по этому helper. Следующий отдельный блок — coherent readiness/profile и resident handler lifecycle, затем полная issuer/cookie/callback matrix/MP7. UI не начинать.
- Main formatter/diff; Luna task check, affected race/security и actual restricted-reader SQL + TLS HTTP selection/isolation/suspend/profile tests на disposable fixtures. Новых deps/schema/grants/ENV нет.

## Реализация

`RuntimeCredentialReader.ResolveRuntime(ctx, origin)` проверяет canonical origin до SQL, затем делает одну выборку по уникальному `platform.projects.origin`. В том же statement проверяются restricted reader profile и существующий runtime snapshot predicate. Результат — typed Key с binding/version/generation; ciphertext/DSN/credential reference не выбираются. Ready/enabled без согласованных preparation/secrets/schema/physical identifiers не допускается. Нет discovery scan, retry, кеша admission или новой связи с Auth SQL.

`NewRuntimeBoundary(platformOrigin, resolver, next)` возвращает только middleware-границу. Platform origin задаёт доверенная сборка; handler также является доверенной явно собранной зависимостью. Boundary не создаёт routes, capabilities или app/runtime cache и не означает, что переданный handler готов к публикации.

- Только direct TLS, без forwarded-host fallback. Platform Host исключён. Absolute URL с другим Host/scheme и opaque request target отклоняются. Resolver проверяет canonical Host; transport повторно не валидирует domain-правила.
- При наличии `Origin` применяется существующий exact-origin validator. Отсутствие Origin не считается разрешением browser mutations: соответствующий профиль обязан подключить прежний BrowserProtection/CSRF. Service Basic/native/callback routes сохраняют собственные явные контракты; универсального bypass не добавлено. CORS headers boundary не выдаёт.
- `RuntimeFromContext` отдаёт immutable per-request selection (`Key()`, `Origin()`). Header/body/cookie/JWT не выбирают этот ключ; context key и поля selection закрыты. Параллельные запросы не меняют общую переменную проекта.
- Lookup имеет timeout3s и отменяется до вызова next. В next передаётся исходный request context с selection, а не уже отменённый lookup context. Outer process HTTP admission/deadline остаётся обязательным; новый pool/semaphore/queue не создаётся.
- Unknown/disabled/incomplete origin —404 без информации о причине; SQL/profile/timeout failure или невалидный key от source —503. Все ответы no-store, без fallback. Каждый запрос разрешается заново; сами feature operations обязаны использовать текущие Key guards до/после SQL-сценария. Уже допущенную операцию boundary не откатывает распределённо.

## Проверки и границы

Добавлены unit authority/TLS/platform/Origin/absolute/opaque/dependency mapping, lookup cancellation и32 параллельных выбора двух ключей. Actual command fixture проверяет resolver на restricted reader с лишним UPDATE grant, неизвестный/неcanonical origin/cancel, настоящий TLS diagnostic handler с выбором правильного SQL runtime, отказ forwarded-host/header подмены, foreign Origin/platform host и suspend/resume без positive cache. Diagnostic handler возвращает только204, не публикует Auth или пользовательские данные.

Main formatter/diff/read-only source review выполнены; Luna: task check/lint0, affected race, security и Linux ARM64 actual full TestPrepareCommandSQL PASS. Fixture подтвердил TLS, SCRAM deny при неверном пароле и RedisDB15. Security: вызываемых кодом уязвимостей нет; одна в dependency недостижима по scanner. Manifest5 совпал до/после и с main; собственные containers/network/certificates/test binary удалены. Cookies, issuer/callback/redirect матрица, согласованная feature-readiness, publication/handler lifecycle и полноценная two-project MP5/MP7 приёмка остаются открыты. Existing public/server routes и реальные ENV/БД не изменены.
