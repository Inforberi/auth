# JWT из действующей сессии

J3a-local, 17 октября 2026: реализовано внутреннее ядро выдачи. **HTTP-ручки, App/ENV и публичного JWKS пока нет.** Это следующий блок J3b, а не готовый интеграционный API. Strict online consumer требует J5; криптографическая проверка сама не проверяет актуальные права.

## Границы и порядок

`internal/auth/token/service/exchange.go` — один сценарий; `config.go` — immutable allowlist ресурсов; `repository/postgres/exchange.go` — SQL authority/commit; `repository/redis/limits.go` — распределённые бюджеты. Ключи/ES256 переиспользуют [J2](jwt-keys.md). Новых workers, caches и библиотек нет.

1. Будущий cookie-handler получает user UUID, публичный session UUID и verifier из проверенного Auth context, IP — из существующей trusted-proxy обработки. Клиент сможет передать только audience и scopes, не principal/session/MFA/mode. Публикация требует Origin и NoRefreshAuth; это ещё не подключено.
2. Service проверяет principal, IP, запрошенные audience/scopes; копирует и сортирует scope без изменения входного slice. Ресурс по умолчанию strict; local только из server configuration, без client downgrade. Ключи должны существовать в Access catalog и allowlist ресурса. Local-конфигурация с core admin permissions отклоняется.
3. До Redis/SQL — nonblocking admission максимум 8 выдач на один Service. Общий deadline операции 3s; ожидание освобождения SQL locks входит в него. После отмены rollback имеет отдельный cleanup deadline до 3s. Владельцы Service/Signer должны быть общими для экземпляра, не создаваться на запрос; fleet budgets считаются суммарно.
4. Один Redis Lua-вызов проверяет actor, стабильный session ID, IP и project. Окно — счётчик 60 секунд от первого принятого запроса, не sliding window. По умолчанию соответственно **30/10/30/3000 в минуту**; constructor требует positive bounded budgets. Меньший лимит побеждает. При отказе все счётчики остаются прежними, новые ключи не создаются, TTL не продлевается. Принятый бюджет не возвращается при последующем SQL-отказе. Hash slot общий, identifiers/IP защищены переданным keyed digester; Redis на проект отдельный. Ошибка/недоступность — отказ, не unlimited fallback.
5. SQL Read Committed: shared Access advisory lock → active/nondeleted user FOR SHARE → role-bound session FOR SHARE. Shared lock допускает параллельные выдачи, но исключает Access mutations с тем же exclusive lock. После ожидания user lock отдельный statement видит committed version/session/factor changes. Проверяются user/hash/sid/version, idle/absolute/revoked, immutable role revisions, все requested grants, завершённая activation/смена временного пароля и действующее MFA-требование/фактор. Нет проверки прав отдельным запросом на каждый scope.
6. Подпись ES256 выполняется локально под этими locks; callback не делает сеть, Redis или KMS. Claims используют SQL proof snapshot и время БД. `exp=min(now+TTL,idle deadline,absolute deadline)`, с округлением вниз до Unix seconds. Primary/MFA proof timestamps не повышаются. Issuance не refresh, reauthentication или admin activity.
7. Audit insert с финальной проверкой expiry → commit → возврат raw JWT. Ошибка подписи, отмена, audit или commit не возвращают токен. После неоднозначного результата commit audit может существовать без доставленного ответа; at-most-once доставка не обещается. Повторный вызов — новая выдача и новый бюджет, не retry loop.

Source `000001` содержит `auth.token_issuance_audit`: user/session UUID, random token ID, audience, scope, mode и expiry/time. Нет raw JWT, cookie/hash, email, IP или refresh credential. Session UUID без FK к sessions: аудит должен пережить очистку ledger. Retention использует существующие security audit дни (default 180) и indexed bounded batches.

## Proof и отзыв

Primary: password → `pwd`, emailotp → `emailotp`, внешний OIDC (включая Telegram) → `oidc`. Существующая session хранит факт MFA, но не различает TOTP/recovery-code при её создании. Поэтому exchange выдаёт честное общее `amr=mfa` с исходным `mfa_time`, а не выдумывает `otp`/`recovery`. Verifier поддерживает эти три factor labels, но один токен может содержать только один фактор. Это уточнение ещё не опубликованного J2/J3 контракта, не изменение session schema.

Revoke/reset/block/role mutation, завершившийся до получения соответствующего lock, не оставляет устаревший issuance snapshot. Если issuance получила locks первой, она может commit до последующего revoke; это корректный порядок, не обещание «все уже выданные JWT исчезают». Затем strict consumer обязан проверить current authority в J5. Local JWT сохраняет [согласованное окно](../adr/004-jwt-access-profiles.md#2-strict-и-local) до exp, а не немедленный отзыв.

Config сейчас передаётся constructor и копируется; это не сохраняемая/UI политика. Правила primary login и существующие cookie routes не менялись. Переключение login-method settings не трактуется автоматически как logout: JWT enabled/resource configuration и их runtime актуальность должны быть явно подключены J3b/J6. До этого сервис в main App не доступен.

## Следующий блок J3b / ограничения приёмки

- Disabled-by-default startup config, bounded resource file, trusted key loader и единые владельцы в App; disabled не читает keys/resources и не публикует flow.
- JWT Redis client с context deadlines/no automatic retries и учётом суммарных connection pools; новый limiter нельзя подключить к client с неограниченными ожиданиями или скрытым retry storm.
- Cookie exchange POST с exact Origin/NoRefreshAuth, bounded JSON, безопасный mapper, no-store; public-only JWKS, Swagger/интеграторский контракт и негативные HTTP-тесты. Native/refresh/introspection остаются J4/J5.
- Проверить SQL policy/config readiness до включения, отсутствие обхода email verification/MFA и disabled profiles; согласовать с сохраняемой политикой J6 без подмены её ENV fallback.
- До sustained traffic рассчитать скорость audit cleanup и storage: default retention batch 100/interval 1m не является гарантией очистки при постоянных 3000 issuances/min. Измерить drain rate/время bounded batch и подобрать существующие deployment budgets; не заявлять RPS/отсутствие backlog по одним лимитам.
- SQL/Redis integration/race покрывают локальные гарантии. Browser/ingress, реальные provider proofs, fleet settings/key rotation, failure/restore, mixed load/GC/soak остаются открытыми pre-ui/J7/A8 gates.
