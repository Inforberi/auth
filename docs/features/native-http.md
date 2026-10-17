# Native JWT API

J4b.2c.3-http-local, 17 октября 2026. Подключены App, HTTP и Swagger для password/email OTP → MFA/enrollment → access JWT + opaque refresh. Это не browser-cookie вход и не private admin API. Прямой native Google/Telegram handoff — отдельный J4c; существующий browser provider flow может использовать session exchange. Strict consumer с актуальной SQL authority — J5; одна проверка подписи не обеспечивает немедленный отзыв.

## Включение

По умолчанию `JWT_ENABLED=false`, `JWT_NATIVE_ENABLED=false`. Для native нужны оба флага, `MFA_ENABLED=true`, существующие signing/resource files и [совместимые lifetime/cleanup budgets](refresh-storage.md#настройки-native--j4b2c3-config). MFA capability не заставляет каждого пользователя подключать фактор: это определяют текущие фактор/роль/policy в SQL. Email OTP подключается при готовом адаптере и разрешённой публичной policy; выключенный метод не обходится native-входом. Root/config/ключи остаются deployment, UI policy — будущий J6.

App использует один token service/signer/admission/JWT Redis client, уже существующие password hasher/limits, MFA coordinator и email OTP/outbox/delivery. Отдельных SQL pools, workers, SMTP pipelines, повторной реализации password/MFA нет. Typed App results передают реально используемые сервисы и handlers, не вытаскивают технические зависимости через чужие сервисы. Отсутствие обязательного компонента — ошибка сборки.

Новая версия source000001 разрешает metadata audit event `refresh_audit.logged_out`. Отдельной миграции нет, рабочая DB не менялась: контролируемый schema/grants upgrade обязателен до включения. Existing profile/target/checkpoint tables/seeds также обязательны.

## Общий транспорт

- Клиент — native HTTP/OS клиент без `Origin`, `Cookie`, `Authorization` и query string. Даже пустой Origin, испорченный Cookie или разрешённый для browser origin отклоняются. Все credentials только в JSON, не URL. Native refresh хранить в защищённом OS storage, не localStorage.
- Browser CORS не наследуется. Native OPTIONS всегда 403, без CORS headers; GET/HEAD/DELETE не выполняют POST-операции. Cookie exchange/admin routes сохраняют прежние Origin/CSRF/auth правила; native не является Bearer fallback для них. Browser/BFF использует cookie профиль/session exchange.
- `application/json`, максимум **8192 bytes**, один объект. Дубликаты, неизвестные поля, case aliases, null, trailing JSON отвергаются до service. Форму проверяет HTTP, предметные правила — existing services/domain, текущую authority — SQL transaction.
- Все ответы операций — `Cache-Control: no-store`, без `Set-Cookie`, в том числе отказы. В DTO нет клиентского user/session UUID, PrimaryProof, administrative intent, assurance или выбора weaker JWT mode. IP берётся из общей trusted-proxy обработки; User-Agent — из HTTP header.
- Ошибки используют общий HTTP mapper с локальными правилами фичи. SQL/Redis/signing errors/credentials не попадают в response/log. 429 сопровождается Retry-After: 30 для ранней rotation, 60 для budget denial; 503 — 1. Это консервативная задержка, не время точного восстановления зависимости.

## Методы

Префикс всех путей — `/api/v1/auth`, метод **POST**.

| Путь | JSON input | Успех |
| --- | --- | --- |
| `/native/password/login` | `email`, `password`, `audience`, `scope:[permission keys]` | 200 native result или 202 restricted challenge |
| `/native/email/request` | `email`, `audience`, `scope` | 202 `{status:"accepted",binding,expiresAt}` |
| `/native/email/confirm` | `binding`, `code` | 200 native result или 202 restricted challenge |
| `/native/mfa/complete` | `challenge`, `binding`, `code`, необязательный `recovery:false` | 200 native result |
| `/native/mfa/enrollment` | `challenge`, `binding` | 200 `{token,secret,uri,expiresAt}` |
| `/native/mfa/enrollment/confirm` | `challenge`, `binding`, `token`, `code` | 200 `{codes:[10 recovery codes]}` |
| `/token/refresh` | `refreshToken` | 200 native result с одним successor |
| `/token/logout` | `refreshToken` | 204 без body |

Native result: `accessToken`, `tokenType:"Bearer"`, `expiresIn`, `expiresAt`, `audience`, space-delimited `scope`, `refreshToken`, `refreshExpiresAt`. Raw выдаётся только после успешного commit. RefreshExpiresAt — абсолютная граница family; более ранний idle/административный deadline продолжает действовать. Не путать access JWT с refresh или browser token.

Restricted response 202: только `challenge`, `binding`, `expiresAt`, `nextStep:"mfa"|"enrollment"`. Ни access, ни refresh, ни пользовательский UUID не выдаются. Scope/target уже связаны на сервере; completion не принимает новый audience/scope. Binding защищает конкретный flow, не service identity.

### Пароль и MFA

`NativePasswordLogin` сначала проверяет resource request, затем вызывает общий `PasswordService.Authenticate` с прежними compare/rehash/limits/policy и передаёт server-owned proof общему NativeLogin. Финальная SQL transaction снова проверяет текущие reference/version/account/grants/verification/provisioning/MFA guards — это защита актуальности, не повторная HTTP-валидация.

При `nextStep=mfa` вызвать `/native/mfa/complete`. Обычный TOTP: recovery отсутствует либо false. Для одного recovery-кода поставить true. Browser/private-admin challenges не подходят. Factor consume, challenge removal, API ledger/family, signing и audit коммитятся вместе. Неверные попытки сохраняются, dependency/sign/audit failure не выдаёт credentials.

При `nextStep=enrollment` сначала получить enrollment token/secret/URI, затем подтвердить первый TOTP. Secret не продлевает исходный login challenge. Подтверждение возвращает recovery codes один раз, повышает auth_version и отзывает старый контекст. **После него нужен новый primary login**, затем MFA: старый challenge не становится полноценным входом. Потеря всех факторов — existing browser/operator recovery, не native bypass.

### Email-код

Это основной метод входа, не email verification и не второй фактор. Код отправляется только eligible существующим аккаунтам; неизвестный/неподходящий аккаунт получает тот же accepted/binding ответ без письма. Pending/temporary activation и external-only onboarding не обходятся.

Сохранить binding из request и передать с кодом в confirm. Target хранится в SQL. Общие SMTP/outbox, cooldown/лимиты, одноразовый code и предел попыток сохранены; browser/native namespaces раздельные. Успешное потребление email-кода и последующая issuance — два workflow: при сбое после consume нужен новый код с обычным cooldown, без повторной выдачи/grace. Внешняя доставка SMTP этим локальным тестом не подтверждается.

### Refresh, выход и список сессий

Refresh single-flight: первый generation0 можно обновить сразу, далее ≥30s, максимум4096 credentials/family. Audience/scope нельзя расширить, absolute lifetime и assurance не продлеваются; API refresh не admin activity. Два одновременных refresh не получают два независимых successors: один может получить 200, другой распознаётся как replay и отзывает family. После этого successor первого тоже не renews. Потерянный успешный ответ нельзя безопасно повторить старым credential — нужен новый вход, grace нет.

Logout принимает известный current **или spent** credential и атомарно отзывает только его family и API session, с metadata-only audit. Повторный или неизвестный корректно сформированный opaque credential возвращает нейтральный 204. Некорректный формат — 401 invalid_refresh; budget/dependency failure — не ложный 204. История spent verifiers не удаляется; аудит/commit failure откатывают отзыв и возвращают 503. Browser session и чужие API families не затрагиваются.

`GET /api/v1/auth/sessions` по-прежнему требует browser cookie, но возвращает оба собственных профиля с `credentialProfile:"browser"|"api"`. Можно отозвать конкретную API-сессию существующей own-session ручкой. Revoke/reset/block/delete и auth_version остаются общей authority. Strict consumer должен проверять актуальность online; local JWT после logout живёт до своего опубликованного expiry/skew окна.

## Проверки и оставшиеся gates

Локально проверены HTTP DTO/whitelist/bounds/disabled/Origin/Cookie/Authorization/preflight/no-store/Retry-After, restricted output, App shared owner с disposable Redis; полный SQL/race-suite включает password→refresh→replay/logout, mixed profile list, parallel HTTP refresh, email request/consume, enrollment→fresh primary→recovery MFA. Logout audit/commit rollback, forged owner hint, spent/repeated own-only revoke и refresh race проверены на PostgreSQL18.6.

Реальные HTTPS/ingress/OS client storage/SMTP/provider/fleet rollout/lost-commit-reply/load/GC/restore — NOT RUN, не production sign-off. Throughput/capacity не установлены; startup arithmetic не заменяет measured drain/storage. J4c/J5/J6/J7 и pre-ui/A8 сохраняют свои gates. Наличие выключенных операций в Swagger не означает их доступность в экземпляре.
