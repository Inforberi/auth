# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j51-local--17-октября-2026). Commits/staging проверять через Git.

## Последний результат — J5.1-local

- [Auth introspection](../features/jwt-introspection.md): POST `/api/v1/internal/auth/token/introspect`, отдельные service Basic credentials/hash manifest/allowed audiences, full JWT crypto + current SQL user/session/version/proof/family/policy/grants. Inactive200 только active:false, no-store/no credentials fallback, HTTP DTO отдельно от service result. Scope только token∩resource∩current grants; role revision может отозвать всю сессию.
- Existing issuance sessionProof/Access locks/verification/MFA/provisioning guards и JWT Redis pool общие. Admission32/deadline3s/atomic client+project counters, без renewal/per-token audit write/N+1/remote I/O под locks. Issuer pinned keys не маскируют remote cache freshness: обычный VerifySignature по-прежнему crypto-only/max trust age60s.
- Formatter/task check/lint0, полный SQL/race, Redis/App/service/crypto/router race, Swagger reproducibility/security scan локально PASS; ограничения/исправленные промежуточные failures — history. Новых dependencies/schema/workers/pools нет. Рабочие DB/ENV/secrets не менялись, commit только по запросу.
- Без JWT_INTROSPECTION_CLIENT_CONFIG_FILE ручки нет; invalid enabled manifest fail-start. JWT/native выключены в ENV-примерах. Service Basic только по deployment HTTPS/TLS ingress contract; реальный ingress/fleet/rotation не проверен fixtures.

## Следующий блок — J5.2

По [JWT-плану](../planning/jwt-access.md#подэтапы-j5) и [ADR004](../adr/004-jwt-access-profiles.md): reusable middleware в pkg/authjwt без internal imports/chi coupling. Fixed HTTPS JWKS/introspection URLs, shared bounded transport/cache/coalesced refresh/backoff/max age60s; exactly one Bearer/no cookie/query fallback. Strict: один online decision, полная response correlation/scope subset, no positive cache/local fallback. Typed principal + explicit permission middleware, local/strict Go примеры и negative/outage tests.

J5 целиком открыт; **strict consumer ещё не готов**. Browser/admin не принимают Bearer. Direct native Google/Telegram handoff — J4c; пока browser provider flow → session exchange. Затем J6 settings/UI contract → J7 → pre-ui-backend → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants и logged_out CHECK требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
