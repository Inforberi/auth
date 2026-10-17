# Online-проверка access JWT

J5.1: Auth проверяет полный подписанный токен и актуальную session authority. Это backend-to-backend API, не новый способ входа. Consumer middleware/JWKS cache — следующий блок J5.2; один `VerifySignature` не обеспечивает немедленный отзыв.

## Настройка

Нужны `JWT_ENABLED=true`, signing keys/resources и файл `JWT_INTROSPECTION_CLIENT_CONFIG_FILE`. Без файла ручки нет; выключенный JWT его не читает. Невалидный manifest/config при включении останавливает startup. Native-профиль для browser-session exchange не обязателен.

Manifest — deployment-owned JSON, максимум32 KiB/32 клиента. Шаблон (placeholder заменить):

```json
{
  "clients": [
    {
      "id": "orders-api",
      "secretHashes": ["<64 lowercase hex characters>"],
      "audiences": ["orders"]
    }
  ]
}
```

`id` — 1–64 символа `A-Za-z0-9_-`. Секрет backend: случайные32 байта из CSPRNG → canonical base64url без padding (43 символа). Manifest содержит **SHA-256 от этих43 ASCII-символов**, lowercase hex, не сам секрет и не hash декодированных байт. Basic передаёт исходную43-символьную строку. Хранить её в secret manager/runtime secret mount, не в браузере/native app/UI/Git/логах/URL.

До двух различных verifiers/клиента для ротации: добавить новый → обновить Auth fleet → переключить backend → удалить старый → обновить fleet. Файл читается при startup, automatic reload/немедленного fleet revoke нет. Audiences должны существовать в resource config. Unknown fields, aliases, duplicates и null запрещены.

Только HTTPS либо разрешённый TLS ingress перед Auth по deployment-правилам. Backend проверяет сертификат/фиксированный endpoint, не следует redirects и не делает automatic retries. Origin/IP/forwarded headers не являются service identity.

## API

`POST /api/v1/internal/auth/token/introspect`

```http
Authorization: Basic <base64(client-id:secret)>
Content-Type: application/json

{"token":"<full access JWT>"}
```

Ровно один Authorization ≤256 байт; Cookie, любой Origin, query string и OPTIONS отклоняются. Не browser CORS endpoint. Body ≤8 KiB, только строковое поле `token`; aliases/duplicates/null/trailing запрещены. JWT ≤4096 байт. Service auth до JSON, admission/Redis до crypto и SQL. Нельзя прислать только UUID/claims/флаг «уже проверен».

Активный ответ содержит `active:true`, `iss`, `sub`, `sid`, `jti`, `audience`, `expiresAt` (Unix seconds), `scope` (effective permissions через пробел). Consumer сопоставляет metadata с **тем же локально проверенным токеном**, scope — с его scope; mismatch/timeout/неоднозначный ответ означает отказ. Consumer-код — J5.2. Собственный JSON protocol, не RFC7662.

Невалидный/истёкший/неактивный токен: HTTP200 и только `{"active":false}`, без PII/причины отзыва. Все ответы no-store, без Set-Cookie; positive authority caching запрещён.

| HTTP | Значение |
| --- | --- |
| 400 | Некорректный JSON |
| 401 | Неверный/неоднозначный service credential; WWW-Authenticate Basic |
| 403 | Запрещённый транспорт либо подписанный токен audience вне allowlist клиента |
| 429 | Admission/rate limit; Retry-After |
| 503 | Redis/SQL/policy/deadline/commit failure; без local fallback |

## Authority и нагрузка

- Existing JOSE parser: ES256/at+jwt/kid/signature/issuer/configured audience/mode/time/claims/proof bounds. Непроверенные claims не выбирают URL/ключи/доверенную policy.
- `IssuerVerifier` использует deployment-pinned issuer keyset без network/фиктивного fetch timestamp. Это **не remote consumer cache**: retire требует rollout. У обычного `Verifier` сохраняется maximum remote trust age60s.
- SQL lock order: Access shared → active/nondeleted user/version → точная session sub/sid → API family → policy. Общий issuance `sessionProof` проверяет revoke/deadlines/role revisions/provisioning/temporary password/required email verification/MFA. Disable метода входа сам по себе не logout.
- Primary method/auth_time/MFA time/auth_version относятся именно к предъявленному токену; изменённый proof требует нового токена. API family активна, имеет тот же audience и покрывает исходный token scope.
- Effective scope = token scope ∩ resource allowlist ∩ current SQL grants. Новая роль не расширяет старый token scope. Revision-bound invalidation может дать более строгий отказ всей сессии при изменении роли.
- Один bounded SQL transaction/decision с несколькими индексными чтениями, не один SELECT. Нет N+1 по permissions, sliding UPDATE, credentials rotation, per-invalid-token audit INSERT или таблицы каждого access JWT. Locks не удерживаются на время работы внешнего backend; decision относится к моменту snapshot.
- Admission32/instance, authority deadline3s. Один atomic Redis Lua client/project decision, minute TTL/no retries. Ключи только для authenticated manifest IDs. Existing JWT Redis pool общий с issuance; новых pools/workers/dependencies/schema нет.
- `JWT_INTROSPECTION_CONSUMER_LIMIT_PER_MINUTE=60000` — отдельный счётчик на каждого backend; `JWT_INTROSPECTION_PROJECT_LIMIT_PER_MINUTE=60000` — суммарный предел. Диапазон1–1000000. Это лимиты, не измеренный RPS; issuance/cleanup budgets ими не подменяются.

## Приёмка

Evidence — [history](../planning/history.md#результат-j51-local--17-октября-2026). SQL проверки: binding/proof/version/revoke/block/delete/MFA/grants, неизменность ledger, concurrent revoke и independent family revoke; HTTP проверяет service auth/transport/safe response. JWT выключен в ENV-примерах; working DB/ENV/secrets не меняются.

J5 целиком открыт: следующий блок consumer middleware/JWKS lifecycle/strict response correlation/примеры. Real TLS ingress/credentials rotation/fleet/outage/load/GC/restore не заменяются fixtures и остаются release gates.
