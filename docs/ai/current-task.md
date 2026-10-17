# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), evidence — [history](../planning/history.md#результат-j62-local--17-октября-2026). Commits/staging проверять через Git.

## Последний результат — J6.2-local

- [JWT settings](../features/jwt-profile-settings.md): обязательные независимые `policy.tokenIssuance.sessionExchange/native` в existing GET/POST/version/audit с permission/fresh password/MFA/deployment ceilings. First-install seed из ENV, рестарт сохраняет SQL policy. Read-only tokenProfiles — capability instance, не effective switch/fleet readiness; keys/mode/credentials остаются deployment.
- Final exchange/native/MFA/refresh используют уже прочитанную locked policy, без лишнего SQL/Redis/новых pools. Disable не закрывает introspection/JWKS/logout/cookie admin и не отзывает существующие JWT. MFA recovery/challenge сохраняются после отказа; refresh rollback и committed reuse revoke проверены. Source000001 дополнен двумя safe-default boolean; рабочая DB не менялась, старой схеме нужен controlled upgrade, не reset.
- Formatter, полный disposable SQL/race, targeted settings/token/MFA/App/config/router race, `task check`/lint0, Swagger/API reproducibility и security scan PASS. 0 reachable/0 imported-package findings,1 known module-only finding. NOT RUN: отдельный Redis integration и real ingress/fleet/browser/load/GC/restore; skips не считать PASS. Evidence — history. Коммит только по запросу.

## Следующий блок — J7

По [JWT-плану](../planning/jwt-access.md#приёмка-безопасности-и-производительности): сверить S1–S10/security matrix с реализацией и существующими доказательствами, определить оставшиеся локально проверяемые пробелы, выполнить необходимые негативные/интеграционные проверки. Не перезапускать одинаковые suites формально и не закрывать external gates local fixtures. Не менять consumer mode, включать JWT или трогать реальные ENV/secrets/рабочую DB без разрешения.

J6 целиком/J7/A6.4/pre-ui/A8 открыты. Real HTTPS/fleet/rotation/fault/load/GC/restore требуют разрешённого стенда/synthetic data и оператора; при отсутствии условий — NOT RUN, не выдуманная capacity. UI — после pre-ui backend gate.

Direct native Google/Telegram handoff — отдельный J4c; пока browser provider flow → session exchange. Далее J7 → pre-ui-backend → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- JWT/native остаются выключенными в ENV-примерах. Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants/logged_out CHECK и settings columns требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
