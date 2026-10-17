# JWT-профили в API настроек

J6.1/J6.2-local: существующий settings API возвращает **read-only** `tokenProfiles` и сохраняет два независимых переключателя в `policy.tokenIssuance`. Новых ручек/таблиц/workers нет. UI пока не реализован.

## Сохраняемые переключатели

Полная policy в `POST /api/v1/admin/auth/settings` теперь обязательно включает:

```json
"tokenIssuance": {
  "sessionExchange": true,
  "native": false
}
```

Это фрагмент `policy`, не самостоятельное тело запроса: нужны прежние `expectedVersion`, `methods`, `registration`, `passwordEmailVerification`. Оба boolean обязательны, включая `false`; пропуск/null/неверный тип — `400 invalid_json`, без Update. GET и успешный POST возвращают сохранённые значения в `policy.tokenIssuance`.

| Поле | Что разрешает | Что не отключает |
| --- | --- | --- |
| `sessionExchange` | Новую выдачу JWT из завершённой browser cookie-session | Cookie login/admin, существующие access tokens, native flow |
| `native` | Первую native выдачу после password/email OTP/MFA и последующий refresh | Cookie exchange, introspection, JWKS, logout и session revocation |

Native работает при `sessionExchange=false`. Primary methods отдельно разрешаются в `policy.methods`; required email verification и MFA сохраняются. Первая установка берёт `sessionExchange=JWT_ENABLED`, `native=JWT_ENABLED && JWT_NATIVE_ENABLED`; рестарт/новый ENV не перезаписывают сохранённую policy. Deployment — верхняя граница: включение неподготовленного JWT/native adapter даёт `409 auth_method_not_ready`. После снятия capability можно сохранить switch=false. Конфигурация instances требует согласованного rollout; metadata одного узла этого не доказывает.

Запись использует existing cookie/Origin/permission/fresh-password/MFA/version/audit guards; no-op не меняет revision/audit. Отключение JWT не закрывает cookie admin и не требует резервного JWT administrator. Last-admin guard для закрытия primary methods сохранён.

Final SQL читает policy под shared lock, конфликтующим с settings UPDATE: exchange перед signing, native перед созданием session/family, MFA перед consumption, refresh перед renewal/signing. Используется уже читаемая policy, без второго lookup/новых pools/remote I/O под locks. При отказе refresh промежуточная rotation откатывается. **Spent refresh reuse коммитит revoke до issuance switch**, даже при native=false.

Отключённый exchange/разрешённый по времени, но запрещённый refresh — `403 forbidden`; native первичная/MFA выдача — `404 method_disabled`. Прежние credential/proof/deadline guards продолжают действовать раньше: неизвестный refresh — `401 invalid_refresh`, слишком ранний — `429 refresh_too_early`. Disable не отзывает токены: для этого нужен logout/revoke. Introspection игнорирует issuance switches, сохраняя текущие user/session/family/version/grants checks. Local JWT живёт до expiry.

Switch ограничивает выдачу, не всю подготовительную работу: password hashing, email OTP delivery или подготовка существующего enrollment могут выполняться по своим bounded правилам. Завершённая JWT session при native=false не создаётся; неиспользованный MFA recovery code/challenge после отказа не теряется. Дублирующий early login pipeline не добавлялся.

В исходной `000001_init.up.sql` добавлены два NOT NULL boolean с безопасным DEFAULT false. Новых миграций нет, рабочая БД не менялась. Для установленной старой схемы нужен согласованный upgrade до запуска нового binary, не reset/повтор initial migration.

## Пример ответа

Остальные поля `version`, `policy`, `availableMethods` сохраняются. Новая часть:

```json
{
  "tokenProfiles": {
    "managedBy": "deployment",
    "scope": "instance",
    "changesRequireRollout": true,
    "browserAdminTransport": "cookie",
    "jwtEnabled": true,
    "sessionExchangeEnabled": true,
    "nativeEnabled": false,
    "introspectionEnabled": true,
    "issuer": "https://auth.example.com",
    "accessTtlSeconds": 120,
    "resources": [
      {
        "audience": "orders",
        "mode": "strict",
        "permissions": ["orders.read"],
        "revocation": "online"
      }
    ]
  }
}
```

- `managedBy=deployment`: эти поля нельзя отправлять в POST policy, редактировать через UI или считать SQL-настройками. `changesRequireRollout=true` — конфигурация загружается при запуске, не hot reload.
- `scope=instance`: ответ относится к обслужившему запрос экземпляру, **не** проверяет fleet/внешние backends. `version` относится только к сохраняемой публичной policy, не является версией key manifests/deployment.
- `jwtEnabled`/`sessionExchangeEnabled`: JWT owner и обмен cookie-session в access JWT загружены. `nativeEnabled`/`introspectionEnabled` описывают реально собранные handlers, не просто наличие ENV-строк. Это deployment capabilities, **не эффективные SQL switches**: issuance требует capability=true и соответствующий `policy.tokenIssuance`=true. Native API cookie-free; административный transport всегда `cookie`.
- `issuer`, `accessTtlSeconds` и audience/mode/permissions — не секретные ограничения выдачи. Resources и permissions отсортированы; default mode показан как фактический `strict`, а не пустая строка.
- `revocation=online` требует strict consumer и доступной корректно настроенной introspection для своего audience. `token_expiry` означает local stale-access window до expiry; немедленного user/session/role revoke этот профиль не даёт. Подробности — [consumer](jwt-consumer.md).
- При выключенном JWT flags=false, issuer="", TTL=0, resources=[]; не читаются или не публикуются неиспользуемые JWT files. При включённом JWT invalid configuration по-прежнему fail-start, а не «исправляется» этим projection.

`introspectionEnabled=true` не доказывает, что конкретный backend имеет credential/allowed audience, что SQL/Redis доступны или что все Auth nodes согласованы. Нет поля `fleetReady`, автоматического connection test или обещания production readiness.

## Защита и нагрузка

Действуют существующие cookie session/Origin/`auth.settings.manage` guards. Bearer не заменяет cookie. Нет открытого endpoints для metadata, session refresh, дополнительного SQL/Redis/remote lookup на чтение. Если settings read запрещён или SQL недоступен, нельзя вернуть статический metadata fallback.

Snapshot строится после успешной token assembly, копируется и сортируется при сборке HTTP handler. На запросе только существующий authorized settings read и сериализация immutable projection. Размер resources ограничен действующими deployment limits (32 audiences/256 permissions на audience, исходный bounded resource file); это административный ответ, не добавка к каждому login/session/JWT запросу.

Нет private/signing keys, file paths, root material, service client IDs/secrets/verifiers или исходного config object. Все успешные settings ответы no-store/no Set-Cookie. POST принимает полную policy с tokenIssuance; top-level/nested tokenProfiles/JWT_ENABLED/mode и deployment поля отвергаются400 до Update. Existing permission/fresh password/MFA/version/audit/usable-admin checks не обходятся.

## Сохранённые ограничения J6

Реализованы только необходимые выключатели session exchange/native issuance. Hard deployment ceilings остаются внешними; mode/key material/service credentials не превращаются в произвольные runtime UI поля.

Сохраняются различия операций:

- Запрет новой выдачи/refresh — не logout, не отключение browser-admin и не автоматический revoke всех выданных JWT. Introspection/JWKS/logout/управление сессиями должны оставаться доступны; local уже выданный токен живёт до expiry.
- `sessionProof` сейчас общий для issuance и introspection: не добавлять в него безусловный issuance-disable guard, иначе скрыто изменится revocation policy.
- Final SQL exchange/native/MFA/refresh должны видеть текущую policy в своей транзакции, не кешированный UI/ENV snapshot. Native MFA использует уже заблокированную public policy; не создавать duplicate lookup/pipeline.
- Spent refresh reuse должен по-прежнему коммитить family revoke до отказа, даже если новая issuance выключена. Не ставить общий disable guard перед этой гарантией. Pending MFA/factor consume при запрете выдачи не должен терять recovery code из-за частичного commit.
- Не ослаблять last-admin/fresh-MFA или переключать consumer в local при outage. Один UI switch в Auth не меняет Expected.Mode уже работающего backend: audience/mode/key retire требуют согласованного rollout по [ADR004](../adr/004-jwt-access-profiles.md).

Локальные проверки — [history](../planning/history.md#результат-j62-local--17-октября-2026). Внешняя fleet/CORS/SMTP/browser/load/GC/restore приёмка остаётся открытой; consumer mode требует согласованного deployment обоих концов, не hot switch в Auth.
