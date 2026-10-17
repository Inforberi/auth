# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j2-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J2-local

- [Crypto/key foundation](../features/jwt-keys.md): internal/auth/token/signing — ES256 owner/PKCS#8 loader/signing с ID/expiry metadata для audit без raw serialization; pkg/authjwt — strict compact/JWKS/claims и crypto-only VerifySignature без internal/DB/private keys. Existing go-jose v4.1.6 теперь direct dependency, версии не обновлялись. Task formatter/architecture guard включают pkg.
- Public-only immutable keys, atomic ReplaceKeys без сброса admission, reject out-of-order observedAt, trust age ≥60s/future fail-closed. Fixed ES256/type/issuer/audience/mode, bounds/duplicates/null/unknown rejection, no expiry grace, MFA proof times не повышаются. 8 signatures/32 verifications на owner, без очереди/network/workers; shared instance/fleet budgets/resolver — следующие этапы.
- Formatter/final task check PASS/lint 0 issues, new packages race PASS (1.431s/1.241s). FuzzVerifier/FuzzPublicKeys requested 5s/parallel2 PASS, не performance/capacity/audit. Security scan: 0 affected symbols/imported packages, 1 module-only finding (предыдущая детализация OpenPGP — J1 history). Только synthetic test keys/temp dirs, реальные key files/ENV/DB не трогались. Коммит только по запросу.
- Main App/HTTP/ENV/schema/Swagger не подключены: published JWT issuance/refresh/online middleware пока нет. VerifySignature не current authorization; J1 strict default/per-audience local window и guards сохранены. Remote/fleet/emergency trust/restore/load/GC gates открыты. Native password/email OTP+MFA первым, direct native provider handoff J4c, browser provider→session exchange в scope J3.

## Следующий блок — J3

Transaction-owned session→JWT issuance по [JWT-плану](../planning/jwt-access.md) и ADR 004: reuse signer, current live role-bound session/user/version/grants/audience policy, bounded issuance limits, clamp exp к idle/absolute deadline, audit/commit до возврата. Issuance не refresh/activity/fresh MFA. Продумать минимальную config/App границу и disabled behavior; ничего не публиковать без SQL/limits/MFA prerequisites. Для strict consumer ещё нужен J5 online resolver/introspection/middleware, не называть crypto-only проверку полноценной авторизацией.

Затем J3 issuance → J4 native/refresh → J5 verifier/introspection middleware → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
