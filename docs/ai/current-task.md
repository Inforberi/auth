# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j1-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J1-local

- Пользователь подтвердил standard Bearer JWT, session exchange и native/API профиль; [ADR 004](../adr/004-jwt-access-profiles.md) фиксирует J1-контракт S1–S10. Strict online default; per-audience local opt-in с default TTL 2m/ceiling 5m/без exp grace, maximum local revocation delay 5m30s при clock difference ≤30s. JWKS freshness ≤60s означает bounded периодический I/O, не полную offline-автономность. Cookie/admin authority не ослаблена.
- Выбран ES256/existing go-jose/v4; patch v4.1.4→v4.1.6 по опубликованному RSA JWK DoS advisory. Context7 docs + установленный source проверены. Изменены только dependency pin/checksums и документы; JWT runtime/routes/schema/ENV/packages/Swagger пока не добавлены. Native первым получает password/email OTP+MFA, direct provider native handoff — отдельный J4c; existing browser provider + session exchange сохраняется.
- `task check` PASS/lint 0 issues, OIDC integration/service/HTTP `-race` PASS. `task check:security`/verbose: 0 affected symbols/imported packages; одна module-only GO-2026-5932 в неимпортируемом x/crypto/openpgp, fixed N/A, не удалять x/crypto, нужный Argon2. Подробности — history. SQL/Redis/external/provider-native/key/fleet/load/GC/restore приёмка не выполнялась и не закрыта. Реальные env/secrets/DB не трогались, коммит только по запросу.

## Следующий блок — J2

Signing/key/claims foundation по [JWT-плану](../planning/jwt-access.md) и ADR 004: ES256, fixed alg/type/key trust, bounded strict parser, expiry/issuer/audience, public-only JWKS, private key lifecycle и негативные/fuzz/race tests. Перепроверить dependency advisories перед реализацией. Не публиковать issuance/native/introspection routes без их SQL/limits/MFA prerequisites, не создавать универсальные wrapper/framework/пустые пакеты.

Затем J3 issuance → J4 native/refresh → J5 verifier/introspection middleware → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
