# Текущий шаг

Обновлено 18 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), последний результат — [runtime split/history](../planning/history.md#результат-mp23-runtime-split--18-октября-2026), прежние измерения — [отчёт](../operations/acceptance-summary.md). Commits/staging проверять через Git.

## Последний результат — MP2.3-runtime-split

- `app/auth/app.go` — standalone resources/shared hasher/server; `realm.go` — feature assembly из borrowed dependencies с собственным clients cleanup; `run.go` — workers lifecycle без listener. Сохранены API/SQL authority/server drain → workers join → realm clients → process dependencies. Исправлен typed-nil email OTP worker при выключенном адаптере.
- Formatter, targeted router contracts, final `task check` PASS/lint0, targeted race App/hasher PASS. Новые tests — fake workers/hasher, не live multi-realm. Docker/SQL/Redis/HTTPS/load в этом блоке NOT RUN, ENV/схемы/рабочие данные не менялись. [Operator foundation](../features/platform-operators.md) и MP2.1 SQL закрыты ранее; результат operator SQL0.26s — предыдущий блок, не повторялся. Актуальные commits/staging проверять через Git.

## Согласованный следующий этап — multi-project

Далее закончить MP2.3–MP2.4: отдельные origin/cookie/Redis/key namespaces и grants, минимальный operator profile существующего Auth и защищённые setup/password/MFA routes, login/recovery SQL/HTTP приёмка. Runtime split — prerequisite, не завершённый platform runtime: assembleRealm пока private, JWT no-retry client всё ещё realm-owned, process-wide admission/общие client budgets и fleet scheduler не реализованы; полный App.New на каждый realm не запускать. Затем MP2.2/MP2.5–MP2.7: transitions и management API, одна platform session по [ADR005](../adr/005-independent-projects.md). Bridge закрыт до SQL authority/audit/receipt/revoke tests; AuthorizeRead их не заменяет. Затем provisioning/изоляция/эксплуатация → cross-project приёмка → предельный RPS/ресурсы MP8 → UI A7. SSO отложен, пользователей не объединять.

## Ограничения приёмки — не отменены новым порядком

Два bounded load/rest наблюдения выполнены; по просьбе пользователя не продолжать третий формально. Полный soak/retained heap/allocations/GC CPU/fault/fleet по6.8b/c остаётся открытым, выполняется на итоговой архитектуре в MP8; не выдавать50RPS за максимум. Текущий450+450 bounded drain не заменяет other audit/contact/outbox/native history/fleet/fault/peak cleanup приёмку. Не reset рабочие данные и не менять retention/GC ради цифр. Native email OTP live/special super-admin/exact expiry boundary/clock-skew/fleet и external gates открыты. Selective JWKS-only partition/planned TTL-drain/operator/providers/SMTP/browser/ingress отдельно; нет условий — NOT RUN. Product SLO/resource budgets/max capacity ещё не подтверждены, UI — после pre-ui backend/projects/capacity gates.

По уточнению18 октября **последним нагрузочным блоком до UI** выполнить открытый [pre-ui-capacity](../operations/performance.md#поиск-предельного-rps--обязательно-перед-ui): реальный2vCPU/4GiB профиль с явным бюджетом Auth-only/всего стека, ступени до нарушения заранее заданных критериев, repeated steady-state и отдельные successful-RPS результаты session/roles/JWT/login/mix. Генератор/quota/safety ceiling не выдавать за resource maximum. A7 зависит от отчёта; capacity пока только в плане, текущий cleanup run его не выполнял.

Постоянные тестовые зависимости уже работают — не создавать очередные ephemeral fixtures вместо этого стенда без конкретной нужды. Не повторять однообразные unit suites формально. Real browser/ingress/providers/external SMTP/human authenticator/operator/fleet/rotation/load/GC — отдельные NOT RUN gates, а не причина скрыто объявить local эквивалентом внешнего. Рабочие restore/secret rotation/ENV/DB только по отдельному разрешению.

Traffic и ручной/orchestrator startup закрыты до SQL invalidation, reconciliation потерянных после backup постоянных passwords/status/roles/TOTP/identities/settings, Redis flow drain (OIDC TTL5min, writers остановлены), нового deployment key/kid/удаления old trust/подтверждения consumers. Wrapper выполняет только SQL часть и локальную остановку, не global fence/ротацию. Не FLUSHDB/FLUSHALL, не ослаблять strict на local. Hardware/profile/latency/error targets определить перед mixed/hostile/soak/load-rest/shutdown/GC; capacity не установлена.

J6 целиком/J7/A6.4/pre-ui/A8 открыты. Real HTTPS/fleet/rotation/fault/load/GC/restore требуют разрешённого стенда/synthetic data и оператора; при отсутствии условий — NOT RUN, не выдуманная capacity. UI — после pre-ui backend gate.

J7.1 SQL/HTTPS consumer, J7.2 restore SQL/drill, J7.4 JWT baseline и J7.5 rotation/outage выполнены локально, [recovery runbook](../operations/jwt-recovery.md) и [матрица](../operations/jwt-security-acceptance.md) остаются обязательными. J7.5 — early distrust, не planned TTL-drain/fleet sign-off. Direct native Google/Telegram handoff — отдельный J4c. Далее оставшиеся pre-ui/external gates → pre-ui-projects и актуальный capacity → UI A7 → A8.

## Сохраняемые ограничения native и приёмки

- JWT/native остаются выключенными в ENV-примерах. Native требует JWT/MFA readiness, session-bounded TTL и cleanup guard `2×P×(I+5s)≤B×1m`; default P3000/B100/I1m не проходит. Не тюнить автоматически. Source profile/target/refresh/checkpoint/grants/logged_out CHECK и settings columns требуют controlled upgrade, не reset. J4/J4b.2c целиком не закрыты: fleet/drain/storage/HTTP-client/fault/load/GC/restore не измерены.
- AS5-external/AS6 целиком/A6.3/pre-ui/A8 открыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load6.8b, память/GC6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
