# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), evidence — [history](../planning/history.md#результат-j74-local--17-октября-2026), краткий [отчёт](../operations/acceptance-summary.md). Commits/staging проверять через Git.

## Последний результат — J7.4-local

- На существующем [auth-sandbox](../operations/local-sandbox.md#jwt-профили--j74-local) включены JWT/native: отдельный ES256 key/public JWKS/resources/service identity, strict/local audience, access TTL1m, native P60/B200/I1m. Обычные ENV-примеры unchanged. Тестовая роль SQL fixture даёт Ивану только sandbox.records.read; существующие accounts/password/TOTP/volumes сохранены. Capability — JWT override, сохранённые switches включены через admin HTTPS + fresh password/TOTP.
- `task sandbox:jwt`: 10 live сценариев PASS, 121.17s (ожидания TOTP/expiry, не benchmark). Cookie exchange, consumer/scope/mode/credentials, native password/MFA/refresh/replay/logout, settings switches, actual SQL/Redis stop→fail-closed503/live200→recovery и реальный expiry strict/local401. Consumer handler in-process, JWKS/introspection к actual production App по TLS с явным CA; не внешний data-backend/ingress. No runtime Go/API/dependency/schema changes в этом блоке.
- Sandbox оставлен работающим с JWT/native и обоими issuance switches=true. Task sandbox:up возвращает базовый deployment без JWT override, не перезаписывая saved policy; sandbox:down сохраняет volumes. В API монтируются только нужные readonly TLS/JWT/catalog files, не raw consumer secret/admin TOTP/cookie artifacts. Реальные ENV/DB/secrets/чужие контейнеры не тронуты. Полный отчёт и команды — по ссылкам выше; коммит только по запросу.

## Следующий блок — оставшиеся pre-ui gates

Продолжить на том же стенде без сброса данных: локальная приёмка key/JWKS outage/rotation/stale trust, остальные administrative/session pre-ui сценарии, затем измеряемые mixed load/storage/cleanup/память/GC по существующим планам. Выбрать конкретный риск и минимальный сценарий до следующей реализации; не добавлять новые рабочие механизмы ради тестов. Fleet/emergency distrust, реальные providers/SMTP/browser/operator и ingress остаются отдельными gates, если нет условий — NOT RUN. Capacity/production budgets пока не измерены.

Постоянные тестовые зависимости уже работают — не создавать очередные ephemeral fixtures вместо этого стенда без конкретной нужды. Не повторять однообразные unit suites формально. Real browser/ingress/providers/external SMTP/human authenticator/operator/fleet/rotation/load/GC — отдельные NOT RUN gates, а не причина скрыто объявить local эквивалентом внешнего. Рабочие restore/secret rotation/ENV/DB только по отдельному разрешению.

Traffic и ручной/orchestrator startup закрыты до SQL invalidation, reconciliation потерянных после backup постоянных passwords/status/roles/TOTP/identities/settings, Redis flow drain (OIDC TTL5min, writers остановлены), нового deployment key/kid/удаления old trust/подтверждения consumers. Wrapper выполняет только SQL часть и локальную остановку, не global fence/ротацию. Не FLUSHDB/FLUSHALL, не ослаблять strict на local. Hardware/profile/latency/error targets определить перед mixed/hostile/soak/load-rest/shutdown/GC; capacity не установлена.

J6 целиком/J7/A6.4/pre-ui/A8 открыты. Real HTTPS/fleet/rotation/fault/load/GC/restore требуют разрешённого стенда/synthetic data и оператора; при отсутствии условий — NOT RUN, не выдуманная capacity. UI — после pre-ui backend gate.

J7.1 SQL/HTTPS consumer и J7.2 restore SQL/drill выполнены локально, [recovery runbook](../operations/jwt-recovery.md) и [матрица](../operations/jwt-security-acceptance.md) остаются обязательными. Direct native Google/Telegram handoff — отдельный J4c. Далее local JWT acceptance → оставшиеся pre-ui/external gates → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- JWT/native остаются выключенными в ENV-примерах. Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants/logged_out CHECK и settings columns требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
