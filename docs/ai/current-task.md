# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), evidence — [history](../planning/history.md#результат-j52-local--17-октября-2026). Commits/staging проверять через Git.

## Последний результат — J5.2-local

- [Consumer middleware](../features/jwt-consumer.md) в pkg/authjwt без internal/chi imports и новых dependencies: fixed issuer/audience/mode/HTTPS URLs, shared verified TLS transport/cache, fresh JWKS до traffic, coalesced lazy refresh/backoff10s/max trust age60s. Admission32/deadline3s/fetch2s/bounded bodies/headers; unknown kid без storm, no retries/redirect/ENV proxy/background worker. Ready проверяет key trust, не полную strict fleet/SQL readiness.
- Local проверяет подпись/claims без authority, с опубликованным окном отзыва; strict выполняет один запрос к [J5.1](../features/jwt-introspection.md) с service credentials и проверяет response/token metadata/scope subset. Без positive cache/local fallback; authority I/O не продлевает trust/expiry. Bearer-only request policy, immutable principal в context/explicit permission middleware; object/field filtering принадлежит data backend. Browser/admin Auth не принимают Bearer, CORS/CSRF не менялись.
- Formatter, финальный task check/lint0, TLS crypto/cache/middleware/router race, bounded response fuzz и security scan PASS. Есть consumer → real Auth router/JWKS/signing/introspection service/DTO test со stub repository/budget; SQL/Redis заново не запускались и не подменены этим тестом. Swagger/routes/DTO Auth не менялись. Scope/examples/языковой checklist — feature doc, ошибки/ограничения — history. Новых schema/pools Auth/workers/ENV/dependencies нет; DB/secrets/containers не затронуты, commit только по запросу.

## Следующий блок — J6

По [JWT-плану](../planning/jwt-access.md): configuration/UI contract JWT профилей, допустимые сочетания cookie/browser/bearer/service transport и безопасные переключения. Сначала проверить существующих settings owners и ограничения, не копировать deployment key material в SQL/UI и не вводить новый policy framework. Сохранить permission/fresh password/MFA/version/audit и доступность последнего административного входа. Profile/mode не выбирается пользователем ради ослабления проверки.

J5-local реализован, но J7/pre-ui/A8 не закрыты. Direct native Google/Telegram handoff — отдельный J4c; пока browser provider flow → session exchange. Далее J6 → J7 → pre-ui-backend → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- JWT/native остаются выключенными в ENV-примерах. Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants и logged_out CHECK требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
