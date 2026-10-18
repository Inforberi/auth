# Текущий шаг

Обновлено 18 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), evidence — [history](../planning/history.md#результат-pre-ui-freshness-mfa-local--18-октября-2026), краткий [отчёт](../operations/acceptance-summary.md). Commits/staging проверять через Git.

## Последний результат — pre-ui-freshness-mfa-local

- `task sandbox:security`: PASS348.71s с `-race` для test-client/SDK, не server binary. Actual optional→required role MFA отзывает прежнюю cookie/неистёкшие strict JWT/native authority; enrollment browser-bound/limited/без session, новый login требует TOTP, required factor нельзя отключить. При ослаблении policy factor остаётся включённым; финальный test factor и assignment сняты штатно.
- Реальные5min fresh-auth: обычный read доступен, mutation403; password-only reauth недостаточно, после отдельного MFA step-up та же mutation200. Runtime/API/schema/dependencies/лимиты/таймеры не менялись. Первый FAIL на cleanup429 — штатный MFA user budget5/min; добавлен real61s test pacing, не повышение квоты. Диагностический synthetic account остался roleless/enrolled, secret/codes не сохранялись; финальный account roleless/без factor. Previous lifecycle evidence/fixture leftovers сохранены в history.
- Cleanup вернул invitations/temporary-password=false, sandbox-1/TTL1m/7 readonly mounts без admin source; readiness200/public JWKS sandbox-1/no d, все4 контейнера работают, dependencies healthy. Gofmt/final task check lint0/live client race PASS; scanner не повторялся для test-only изменений, прежняя1 module-only находка не закрыта. 18 октября lifecycle и freshness/MFA tests зафиксированы отдельными коммитами; актуальные HEAD/staging проверять через Git.

## Следующий блок — оставшиеся pre-ui gates

Далее подготовить на том же sandbox измеряемый профиль mixed load/storage/cleanup/память/GC по существующим планам: сначала hardware/concurrency/маршруты/latency/error targets и достаточная безопасность эксперимента. Native email OTP live/special super-admin/exact expiry boundary/clock-skew/fleet и external gates текущими двумя сценариями не закрыты. Не добавлять новые рабочие механизмы ради тестов. Selective JWKS-only partition/normal planned TTL-drain/emergency/operator/providers/SMTP/browser/ingress остаются отдельными gates; нет условий — NOT RUN. Capacity/production budgets пока не измерены.

Постоянные тестовые зависимости уже работают — не создавать очередные ephemeral fixtures вместо этого стенда без конкретной нужды. Не повторять однообразные unit suites формально. Real browser/ingress/providers/external SMTP/human authenticator/operator/fleet/rotation/load/GC — отдельные NOT RUN gates, а не причина скрыто объявить local эквивалентом внешнего. Рабочие restore/secret rotation/ENV/DB только по отдельному разрешению.

Traffic и ручной/orchestrator startup закрыты до SQL invalidation, reconciliation потерянных после backup постоянных passwords/status/roles/TOTP/identities/settings, Redis flow drain (OIDC TTL5min, writers остановлены), нового deployment key/kid/удаления old trust/подтверждения consumers. Wrapper выполняет только SQL часть и локальную остановку, не global fence/ротацию. Не FLUSHDB/FLUSHALL, не ослаблять strict на local. Hardware/profile/latency/error targets определить перед mixed/hostile/soak/load-rest/shutdown/GC; capacity не установлена.

J6 целиком/J7/A6.4/pre-ui/A8 открыты. Real HTTPS/fleet/rotation/fault/load/GC/restore требуют разрешённого стенда/synthetic data и оператора; при отсутствии условий — NOT RUN, не выдуманная capacity. UI — после pre-ui backend gate.

J7.1 SQL/HTTPS consumer, J7.2 restore SQL/drill, J7.4 JWT baseline и J7.5 rotation/outage выполнены локально, [recovery runbook](../operations/jwt-recovery.md) и [матрица](../operations/jwt-security-acceptance.md) остаются обязательными. J7.5 — early distrust, не planned TTL-drain/fleet sign-off. Direct native Google/Telegram handoff — отдельный J4c. Далее оставшиеся pre-ui/external gates → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- JWT/native остаются выключенными в ENV-примерах. Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants/logged_out CHECK и settings columns требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
