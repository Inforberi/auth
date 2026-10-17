# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2c3-http-local--17-октября-2026). Commits/staging проверять через Git.

## Последний результат — J4b.2c.3-http-local

- [Native HTTP](../features/native-http.md) подключён disabled-by-default: password/email request-confirm/MFA/enrollment/refresh/logout. Общие password Authenticate/hasher/limits, MFA/email/outbox owners и один token service/signer/admission/Redis pool; нет browser-session перепаковки, новых pools/workers/дублирования primary pipelines. JWT/native сборка внутри одного owner, typed App results без service accessors.
- Exact native routes не ослабляют browser/admin Origin/CSRF/unknown-path/preflight. Native отвергает любой Origin/Cookie/Authorization/query, OPTIONS403/no CORS, strict JSON8KiB/whitelist/duplicates/case/null/trailing; no-store/no Set-Cookie, restricted202 без credentials, safe errors/Retry-After. Logout по own current/spent refresh коммитит API session/family revoke+audit; repeat/unknown well-formed нейтральны, history сохранена, audit/commit failure503 без ложного успеха. Own session list возвращает credentialProfile browser/api.
- Formatter/final task check/lint0, полный SQL/race22.734s и Redis App/HTTP/service race, Swagger/API reproducibility/security PASS. Full SQL включает HTTP password/email/enrollment/recovery-MFA, concurrent refresh/replay, mixed profile list и logout rollback/race/own-only guards. govulncheck:0 reachable/0 imported-package findings; module-only GO-2026-5932 относится к неимпортируемому openpgp в x/crypto, fixed version N/A. Логи/начальные исправленные failures — в history. Рабочие DB/ENV/secrets не менялись; source000001 audit CHECK расширен, новой миграции нет.
- Native остаётся выключенным в ENV-примерах. Для enable нужны JWT/MFA readiness, session-bounded lifetimes и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не пройдёт. Не тюнить автоматически TTL/batch/лимиты. Source profile/target/refresh/checkpoint tables/seeds/grants и logged_out CHECK требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: measured fleet/drain/storage/HTTP-client/fault/load/GC/restore отсутствуют.

## Следующий блок — J5

По [JWT-плану](../planning/jwt-access.md) и [ADR004](../adr/004-jwt-access-profiles.md): strict online consumer/introspection и удобный reusable middleware в pkg/authjwt. Проверять полный token signature/type/issuer/audience/time и актуальную SQL session/version/family/policy/grants authority, current permissions только в пределах token scope/resource. Consumer service identity — отдельные deployment credentials/allowed audiences, не user token/Origin/proxy header. Fail-closed, bounded requests/deadlines/admission/cache; никакого bearer fallback на cookie/admin routes или копирования issuance pipelines.

Текущий VerifySignature проверяет криптографию, не немедленный отзыв. До J5 нельзя объявлять strict consumer готовым. Direct native Google/Telegram handoff — отдельный J4c; пока browser provider flow → session exchange. Затем J6 settings/UI contract → J7 → pre-ui-backend → UI A7 → A8. Реальные provider/SMTP/browser workflows и 13.1d.4 recovery drill проверить перед UI, fixtures не заменяют их.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
