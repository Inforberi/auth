# Краткий отчёт по проверкам

17 октября 2026. Ветка `feat/register-ai`, HEAD `a01f581` **с незакоммиченными изменениями** J7.1–J7.4. Один локальный `auth-sandbox`: production App, PostgreSQL18.6, Redis8.2, Mailpit, прямой HTTPS с проверкой CA. Не production sign-off.

| Проверка | Результат |
| --- | --- |
| Auth baseline J7.3 | PASS: register, первый admin/email/TOTP, cookie/password/MFA, email verification/email OTP с Mailpit, admin/ordinary rights, hostile Origin, logout и Redis fail-closed/recovery |
| JWT issuance J7.4 | PASS: отдельные ES256/JWKS/service verifier; cookie exchange и native password/MFA дают credentials только после нужных proofs; outputs no-store, без Set-Cookie |
| Consumer и права | PASS: strict/local, read разрешён/write запрещён, повреждённый token/mode mismatch/cookie ambiguity отклоняются; неверный service secret даёт503, не user401; Bearer не заменяет cookie Auth |
| Refresh и отзыв | PASS: rotation, слишком ранний refresh429, replay401 отзывает family и successor; logout204/idempotence; strict после logout401, local до expiry остаётся действителен |
| Policy | PASS: switches через private admin password/TOTP + versioned settings API; disable issuance закрывает новые выдачи, не introspection/logout; после проверки оба=true |
| Отказы зависимостей | PASS: real stop только sandbox PostgreSQL/Redis, readiness503/live200/strict503/native503; local работает по актуальным ключам; после start strict снова204 без restart API. Не измерение recovery SLA/partition storm |
| Реальное expiry | PASS: оба режима дают401 после опубликованного срока; test JWT TTL1m. Все10 live сценариев PASS,121.17s с ожиданиями TOTP/expiry, не RPS benchmark |
| Restore J7.2, предыдущий блок | PASS-local: disposable pg_dump/restore + SQL invalidation/rollback/audit/runtime denial. Production/fleet/key distrust/account-state reconciliation NOT RUN |
| Автоматические проверки | PASS: formatter, task check (Go tests/contract + lint0), targeted race pkg/authjwt + deploy/scripts, task check:security:0 reachable/0 imported-package findings;1 известная module-only находка остаётся |

Ключи/секреты не коммитятся; runtime mounts readonly и только для необходимых файлов. Настоящие ENV/БД/secrets/чужие контейнеры не менялись. Native budget P60/B200/I1m проходит startup guard, но measured cleanup throughput ещё не установлен. Обычный `go test` не запускает live sandbox/fault tests; SQL integration suites, отмеченные предыдущими блоками, не выдаются за заново выполненные здесь.

**NOT RUN:** native email OTP live в этом прогоне; остальные administrative pre-ui сценарии (invite/temporary credentials/role mutations и т. п.) не выдаются за заново проверенные live. Также не выполнены реальный браузер/UI/ingress/CORS deployment, Google/Telegram callbacks, внешний SMTP/человеческий authenticator/operator drill, отдельный deployment data-backend, fleet/emergency rotation/key distrust, JWKS outage на этом sandbox, lost-reply/partition/fleet races, mixed/hostile/soak load, cleanup/storage capacity, RSS/GC/leaks и end-to-end fleet restore. RPS сервиса не установлен; перечисленное не закрыто локальным PASS.

Стенд оставлен работающим; команды/адреса/синтетические доступы — [sandbox](local-sandbox.md). Детали текущего прогона — [history J7.4](../planning/history.md#результат-j74-local--17-октября-2026), security gates — [матрица S1–S10](jwt-security-acceptance.md). Коммит в этом блоке не выполнялся.
