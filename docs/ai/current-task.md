# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j3a-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J3a-local

- [Ядро session exchange](../features/jwt-exchange.md): internal/auth/token service/domain + feature-owned PostgreSQL/Redis repositories. Immutable resource/catalog allowlist, strict default/per-audience local opt-in без core admin grants, 8-operation admission/3s deadline, один Redis budget decision до SQL. Shared Access advisory → user/session SHARE: live role-bound session/user/version/grants/MFA/provisioning, local signing, clamp exp, audit/commit before raw result. Issuance не refresh/activity/fresh proof.
- Переиспользован [J2 signer/verifier](../features/jwt-keys.md), dependencies не менялись. `amr=mfa` честно обозначает подтверждённый фактор: existing session не хранит различие TOTP/recovery. Не выдумывать более сильный/конкретный proof. Исторические J2 crypto/fuzz/security результаты — history, crypto-only VerifySignature не current authorization.
- Source 000001 + token_issuance_audit/index/existing retention; новой миграции/worker/cache нет. Formatter/final task check PASS/lint 0 issues, full SQL schema -race PASS 16.277s, final targeted JWT SQL -race PASS 2.269s; real Redis -race PASS 1.276s, service/signing/verifier race PASS. Только disposable PostgreSQL/Redis/synthetic keys; рабочие ENV/secrets/DB не менялись. Коммит только по запросу.
- Main App/HTTP/ENV/Swagger не подключены: J3a — внутренний сценарий, не published API. Runtime JWT policy/config readiness, Origin/NoRefreshAuth wiring, общего владельца и bounded Redis client/no retries подключить J3b. Audit storage/cleanup sizing перед sustained traffic остаётся gate: default batch 100/min не гарантирует drain при 3000 issuances/min.

## Следующий блок — J3b

Disabled-by-default startup config/ENV + bounded resource/key loading, shared App owners и JWT Redis budgets без retry storm; cookie POST exchange с exact Origin/NoRefreshAuth/no-store, mapper/Swagger и public-only JWKS. Проверить runtime policy/readiness, disabled profiles, verification/MFA prerequisites и negative HTTP tests до публикации. Details — [JWT-план](../planning/jwt-access.md) и [feature contract](../features/jwt-exchange.md). Для strict consumer ещё нужен J5 resolver/introspection/middleware; не называть signature-only полноценной авторизацией.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
