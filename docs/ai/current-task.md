# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), evidence — [history](../planning/history.md#результат-pre-ui-admin-local--17-октября-2026), краткий [отчёт](../operations/acceptance-summary.md). Commits/staging проверять через Git.

## Последний результат — pre-ui-admin-local

- `task sandbox:admin` на существующем [sandbox](../operations/local-sandbox.md#пользователи-и-роли--pre-ui-admin-local): PASS62.51s с `-race` для test-client/SDK, не server binary. Приглашение/Mailpit→activation/replay, temporary provision/idempotency→mandatory setup→login, custom role grant/edit/revoke, directory/cursor, block/unblock/stale versions и last-admin block/delete/revoke denial прошли через HTTPS API, без SQL-подмен. Unfinished MFA и public admin login не заменяют private fresh proof.
- Role expansion отзывает cookie/strict JWT; pure reduction сохраняет вход, но убирает permission. После unblock сохранённая старая cookie и JWT не оживают; свежий login работает. Runtime/API/schema/dependencies не менялись: дефектов в проверенных сценариях не воспроизведено. Новые synthetic users/roles оставлены без назначенных прав.
- Cleanup вернул invitations/temporary-password=false, sandbox-1/TTL1m/7 readonly mounts без admin source; readiness200/public JWKS sandbox-1/no d, все4 контейнера работают, dependencies healthy. Formatter/task check lint0/live client race/security PASS (0 reachable/imported-package,1 known module-only). 18 октября тесты J7.5 и admin acceptance зафиксированы отдельными коммитами; подробности проверок — в history.

## Следующий блок — оставшиеся pre-ui gates

Продолжить на том же стенде без сброса данных: отдельный lifecycle блок invitation/temporary reissue и actual delete обычного synthetic account с отказом старым credentials. Fresh-proof aging/role-required MFA — по соответствующим gates, не выдавать за текущий PASS. Затем измеряемые mixed load/storage/cleanup/память/GC по существующим планам. Не добавлять новые рабочие механизмы ради тестов. Selective JWKS-only partition/normal planned TTL-drain/fleet/emergency/operator/providers/SMTP/browser/ingress остаются отдельными gates, при отсутствии условий — NOT RUN. Capacity/production budgets пока не измерены.

Постоянные тестовые зависимости уже работают — не создавать очередные ephemeral fixtures вместо этого стенда без конкретной нужды. Не повторять однообразные unit suites формально. Real browser/ingress/providers/external SMTP/human authenticator/operator/fleet/rotation/load/GC — отдельные NOT RUN gates, а не причина скрыто объявить local эквивалентом внешнего. Рабочие restore/secret rotation/ENV/DB только по отдельному разрешению.

Traffic и ручной/orchestrator startup закрыты до SQL invalidation, reconciliation потерянных после backup постоянных passwords/status/roles/TOTP/identities/settings, Redis flow drain (OIDC TTL5min, writers остановлены), нового deployment key/kid/удаления old trust/подтверждения consumers. Wrapper выполняет только SQL часть и локальную остановку, не global fence/ротацию. Не FLUSHDB/FLUSHALL, не ослаблять strict на local. Hardware/profile/latency/error targets определить перед mixed/hostile/soak/load-rest/shutdown/GC; capacity не установлена.

J6 целиком/J7/A6.4/pre-ui/A8 открыты. Real HTTPS/fleet/rotation/fault/load/GC/restore требуют разрешённого стенда/synthetic data и оператора; при отсутствии условий — NOT RUN, не выдуманная capacity. UI — после pre-ui backend gate.

J7.1 SQL/HTTPS consumer, J7.2 restore SQL/drill, J7.4 JWT baseline и J7.5 rotation/outage выполнены локально, [recovery runbook](../operations/jwt-recovery.md) и [матрица](../operations/jwt-security-acceptance.md) остаются обязательными. J7.5 — early distrust, не planned TTL-drain/fleet sign-off. Direct native Google/Telegram handoff — отдельный J4c. Далее оставшиеся pre-ui/external gates → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- JWT/native остаются выключенными в ENV-примерах. Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants/logged_out CHECK и settings columns требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
