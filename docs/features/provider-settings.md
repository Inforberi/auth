# Настройки Google и Telegram — A6.3c.2-local

Backend хранит Client ID/Secret для двух фиксированных OIDC-провайдеров. Публичные методы/регистрация включаются отдельно через [Auth policy](auth-settings.md). Общий OAuth server, произвольные issuers и plugin framework не добавлены.

## Хранение и deployment

`auth.provider_settings`: provider (`google`/`telegram`), независимая version, Client ID, encrypted Client Secret и presence flag. Secret шифруется существующим AES-GCM с разными purposes `provider-google:v1` / `provider-telegram:v1`; ciphertext нельзя переставить между providers. GET и audit не содержат secret/ciphertext/маску. Root key остаётся `ACCOUNT_ENCRYPTION_KEY`, не настройка UI.

На **новой** установке ENV Client ID/Secret — seed, а не override. Disabled provider может получить пустую пару; включённый provider с неполной парой не сохраняет неготовую запись. После seed изменение ENV не меняет сохранённые credentials. Concurrent initializers получают одного winner. Потеря записи после initialized setup marker, невозможность decrypt или SQL outage не разрешают повторный импорт/fallback на ENV. Ошибка root key требует deployment recovery; plaintext/ciphertext не возвращаются для «восстановления» через API.

Callback URI, issuer/endpoints, admission budgets и root key остаются deployment configuration. Issuers/token/JWKS endpoints фиксированы кодом, пользовательский URL через settings API не принимается. Callback URI должен быть валидным HTTPS и **точно** зарегистрированным у provider. Перед включением нового метода нужны operational callback/budgets на всех экземплярах; валидные credentials сами этого не обеспечивают. При изменении callback/deployment contract нужен согласованный rollout/invalidation pending flows, не mixed fleet.

`availableMethods` теперь описывает локально собранные adapters по operational callback/budgets, не наличие credentials и не внешнюю health-проверку. Если adapter доступен, но saved Client ID/Secret пусты, включение метода через Auth policy отклоняется `409 auth_method_not_ready`. Startup также не принимает сохранённый enabled provider без credentials. Ненастроенный отключённый метод не делает provider network calls; на собранном route runtime SQL policy даёт `method_disabled`.

## API

GET/POST `/api/v1/admin/auth/settings/providers/{provider}`, где provider — строго `google` или `telegram`. Live session, разрешённый HTTPS Origin и current `auth.settings.manage`; no-store/no-refresh. Actor UUID/hash не принимаются из JSON. GET не требует fresh proof; POST дополнительно требует fresh password+MFA и enrolled factor в транзакции, route публикуется только при deployment MFA enabled.

GET:

```json
{
  "provider": "google",
  "version": 1,
  "clientId": "example.apps.googleusercontent.com",
  "clientSecretSet": true
}
```

POST:

```json
{
  "expectedVersion": 1,
  "clientId": "example.apps.googleusercontent.com",
  "clientSecret": "NEW_SECRET"
}
```

Client ID обязателен в JSON (может быть пустой строкой для неготовой отключённой записи), expectedVersion положительный. Google ID — web client ID `.apps.googleusercontent.com`; Telegram ID — положительное каноническое десятичное число. Secret до 1024 bytes без CR/LF/NUL; пустой/отсутствующий секрет не считается настройкой enabled method. Неизвестные JSON поля/типы, null/пропуск clientId, лишние JSON values → `400 invalid_json`. HTTP не повторяет domain-проверки.

- Secret пропущен/null — сохранить прежний. Неизменённый Client ID и текущая version дают no-op без version/audit bump.
- Secret явно непустой — заменить и повысить version. Повтор того же значения также считается rotation: digest для сравнения секретов не сохраняется.
- Secret `""` — очистить только при выключенном public method. Это не удаляет linked identities или существующие sessions.
- Изменение Client ID требует explicit secret и выключенного метода. Если уже есть хотя бы одна identity этого issuer (включая soft-deleted владельцев), ответ `409 provider_client_bound`: тихая подмена OIDC application может изменить namespace/принадлежность subject. Для неё нужен отдельно согласованный migration, не unlink/delete всех пользователей ради обхода guard.

Порядок write transaction: Access → current actor/session/proofs → public policy SHARE → provider row/version → state-dependent validation → update+audit → commit. Public final transactions используют user → policy SHARE → provider SHARE; новые user locks после этих locks не берутся. Ошибка аудита откатывает credentials/version. Optimistic conflict не перезаписывается автоматически. Audit содержит previous/next non-secret snapshots, очищается прежним bounded/indexed security retention.

Ошибки: `400 invalid_provider_settings`; `401` session; `403 forbidden`/`fresh_auth_required`/Origin; `409 provider_settings_conflict`/`provider_client_bound`/`auth_method_not_ready`; `503 temporarily_unavailable` без внутренних деталей. Успех POST имеет безопасный формат GET. Сохранение не доказывает, что внешний provider принял secret; фиктивного endpoint «проверить secret без входа» нет — нужен настоящий authorization-code/browser flow.

## Rotation и незавершённые входы

Каждый start/link и callback получает current SQL credentials snapshot. Encrypted single-use Redis flow содержит **providerVersion**, purpose/PKCE/nonce/browser binding и session owner binding для link, но не Client Secret. Если версия сменилась до callback, state уже single-use и вход нужно начать заново; обмен кода со смешанной конфигурацией не выполняется.

После token exchange revision проходит вместе с verified identity/primary proof. Финальные SQL identity creation/link/session issuance сверяют и удерживают current provider revision до commit. Если rotation закоммичена первой — старый proof отклоняется; если final transaction получила SHARE первой — она заканчивается до rotation. Раздельные account/session commits остаются: корректно созданный linked account может сохраниться без session, если rotation произошла между ними; это не orphan user и следующий новый вход использует того же владельца.

MFA challenge хранит revision primary proof; normal completion, required enrollment и lost-factor recovery используют тот же current-primary SQL guard. Rotation не выдаёт session, не обходится старым MFA challenge и не расходует recovery code при отказе проверки revision. Раннее несовпадение flow даёт `400 invalid_login`, финальный revision guard — `400 login_restart_required`. Публичный disabled method по-прежнему отклоняется независимо от revision.

Уже выданные sessions **не отзываются** сменой client secret: обычные status/auth_version/role revisions/revoke/deadlines остаются authority. При компрометации credential оператор отдельно отзывает secret у внешнего provider и нужные sessions существующими средствами. API не знает, когда внешний provider прекратил принимать старый secret; rotation согласовать с ним. Старые credentials/flows server-side не держатся «на всякий случай»; pending state истекает по прежнему TTL, restart login ожидаем.

## Производительность и проверка

Один shared HTTP transport + долгоживущий JWKS cache на provider, per-operation immutable OAuth/audience-verifier view. Нет нового transport/key cache/context timer на каждую version, polling, workers, process-wide mutable credentials или unbounded map старых версий. Shutdown закрывает владельца HTTP/keyset lifetime прежним resources lifecycle. Дополнительный SQL read+decrypt приходится только на start/callback; indexed revision SHARE — на финальные auth transactions, **не на каждый session middleware request**. Existing admission/operation deadlines/Redis bounds не ослаблены. Согласованные keys/callbacks/budgets/версии кода на fleet — deployment prerequisite, SQL source не доказывает внешнюю готовность каждого узла.

Trusted standalone/static test adapters могут использовать revision=0 только при отсутствии всех managed rows **и** initialized setup marker. Production App до traffic инициализирует обе managed rows; там zero/missing/stale revision запрещены. Это не recovery/fallback после потери managed data. Existing source `000001` дополнен provider settings/audit и provider_version у MFA challenge; рабочая БД не мигрировалась. Уже установленному сервису нужен controlled schema/grants/encrypted bootstrap/legacy pending invalidation до traffic; maintenance upgrade CLI в этом блоке не реализован, reset setup marker/БД не является upgrade.

Локальные unit/HTTP/crypto/SQL/Redis/race tests не заменяют реальные Google/Telegram/browser/link/MFA/secret rotation/fleet/dependency-fault workflows pre-ui/A8. Performance capacity, memory/GC и restore здесь не измерены.
