# JWT и сессии: матрица приёмки J7

17 октября 2026, J7.1/J7.2/J7.4-local. Это карта проверяемых гарантий, а не pentest, нагрузочный отчёт или разрешение production traffic. Требования — [S1–S10](../planning/jwt-access.md#проверка-проекта-по-безопасности--обязательные-условия-реализации), контракт — [ADR004](../adr/004-jwt-access-profiles.md).

`PASS-local` означает только указанную проверенную границу. При наличии `NOT RUN` весь S-пункт/релиз автоматически не закрывается. Подробные команды/результаты — [history](../planning/history.md#результат-j71-local--17-октября-2026).

J7.4 дополняет нижние repository/router evidence настоящим [постоянным HTTPS sandbox](local-sandbox.md#jwt-профили--j74-local): production App + SQL/Redis + отдельный signing key/public JWKS/service credential. В `task sandbox:jwt` consumer middleware исполняется в test handler, а JWKS/introspection идут к работающему Auth по настоящему TLS. Это не отдельный deployment внешнего data-backend или ingress. Live logout/replay/MFA/transport/policy/SQL/Redis/expiry результаты и команды — [history J7.4](../planning/history.md#результат-j74-local--17-октября-2026); первоначальные NOT RUN ниже для network faults относятся к J7.1, не отменяют этот дополнительный локальный прогон. Fleet/rotation/нагрузка/GC и прочие указанные внешние границы остаются открытыми.

| Требование | Локальная реализация и evidence | Что остаётся |
| --- | --- | --- |
| S1: token ↔ authority | PASS-local: issuer verifier, полный JWT в service Basic introspection; exact sub/sid/version/primary/MFA/family и response correlation. `TestIntrospectionAuthenticationAndAuthority`, `checkJWTIntrospection`, `TestConsumerIntrospectionCorrelation`, новый `checkConsumerSQLAuthority` | NOT RUN: реальная цепочка ingress/backend/Auth/SQL и сетевые fault tests |
| S2: scope не растёт | PASS-local: configured resource/token/current grants intersection; `TestConsumerModesAndCurrentAuthority`, `checkJWTIntrospection`, refresh use-case regression. Сквозной read token не проходит write middleware, role revoke запрещает следующий strict запрос | Object/field authorization выполняет backend данных; его deployment acceptance NOT RUN. Role revision может инвалидировать session целиком, не только сузить scope |
| S3: refresh reuse | PASS-local: `checkRefreshStorage`, `checkRefreshUseCase`, `checkRefreshFailures`, `checkTokenIssuancePolicy`. Сквозной replay отзывает исходный и обновлённый strict access, следующий refresh не работает; ordinary rotation сама не является logout | NOT RUN: потерянные ответы/конкурентность на реальном fleet и длительная очистка/history under load. Local access не получает немедленный revoke |
| S4: rotation/compromise | PASS-local primitives: `TestPublicRotation`, `TestConsumerJWKSFailureAndRotation`, `TestConsumerLifetimesAcrossAuthorityIO`; неизвестный/retired kid, stale/future trust, bounded refresh. Max trust age60s/attempt interval10s заданы в consumer | NOT RUN: planned/emergency rollout на нескольких Auth/consumer instances, закрытие old trust sources, аварийное открытие трафика. [Recovery runbook](jwt-recovery.md) обязателен |
| S5: restore не оживляет доступ | PASS-local SQL: `TestRestoreAuthStateSchema` с pg_dump/pg_restore до logout/reset/replay/MFA consume и тем же owner SQL через psql. Revoke/proof/outbox/recovery/TOTP-window/audit/retry/rollback/runtime deny/Access-busy проверены; accounts/roles/factors сохранены. Wrapper инвалидирует до healthcheck и не запускает API | NOT RUN: реальные fleet/key distrust/local JWT/Redis flows и account-state reconciliation после backup. Production restore не выполнялся. SQL audit/healthcheck не закрывают эти gates |
| S6: служебная identity | PASS-local: отдельный client/verifier/audience allowlist, `TestIntrospectionClientValidationAndRotation`, `TestIntrospectionServiceTransport`; cookie/Origin/чужой audience не заменяют service identity | NOT RUN: real secret mount/rotation/revoke и proxy/APM redaction; wire contract собственный, не полный RFC7662 |
| S7: assurance/admin | PASS-local: proof timestamps не обновляются refresh/exchange; current MFA/version/session guards. SQL lifecycle, native MFA/recovery/required-enrollment, settings/last-admin tests; Bearer не заменяет cookie admin | NOT RUN: реальный authenticator/admin-only/browser flow, multi-tab/sleep-resume и операторский recovery drill |
| S8: parser/environment | PASS-local: `TestClaimsAndVerification`, `TestSignedAmbiguousPayloads`, `TestCompactHeaders`, `TestPublicKeys`, issuer verifier и middleware transport tests. Fixed expected issuer/audience/mode, strict JSON/header/claim bounds, без token-supplied discovery URLs | NOT RUN: раздельные реальные prod/staging keys/issuers, ingress duplicate-header handling и fleet configuration consistency |
| S9: ограниченность ресурсов | PASS-local: admission/timeout/size bounds, coalescing/backoff/cancellation/no-retry consumer tests; invalid signature в новой SQL chain не доходит до repository, valid strict не кешируется. J5/J6 evidence для Redis budgets и indexed cleanup сохранено | NOT RUN в J7.1: отдельная Redis fixture, multi-instance mixed/hostile/soak, RSS/GC/goroutines/pools/saturation/SQL plans под реальной нагрузкой. Нет подтверждённого RPS или доказательства отсутствия утечек |
| S10: browser/утечки | PASS-local: router token/native/introspection contracts, browser/Origin/security headers и log redaction tests; failures no-store, no cookie↔bearer fallback. Restore guard не трогает browser policy | NOT RUN: browser + real ingress/CORS/CSP/Swagger/UI и redaction всей proxy/APM/analytics цепочки. UI CSP уточняется по фактическим ресурсам |

## Новая сквозная проверка

`internal/auth/methods/password/repository/postgres/jwt_consumer_sql_integration_test.go` использует настоящие native issuance/refresh/logout services, подпись, TLS server, Auth router/JWKS/service Basic/introspection, PostgreSQL authority и reusable consumer/permission middleware. JWT keys/credentials и пользователи синтетические; SQL schema disposable. Счётчик оборачивает реальный repository, не заменяет его результат.

- Два запроса с одним access token выполняют два SQL authority decisions; разрешение write нельзя получить из read scope.
- Повреждённая подпись не вызывает SQL introspection.
- Обычная refresh rotation сохраняет доступ исходного JWT до его срока; replay старого refresh коммитит revoke и прекращает оба strict access.
- Logout, auth_version increment и role revoke отражаются на следующем запросе, без positive cache.
- Закрытие отдельного authority pool даёт503 при сохранённых signature keys; fallback не возникает. Это проверка **closed pool**, не имитация сетевого partition/долгих locks/timeout storm.

Redis limiter в этой цепочке — существующий synthetic budget; его атомарность/распределённость здесь не проверяется. Issuance/refresh вызываются через service, не native HTTP; native HTTP отдельно проверен существующими contract/SQL tests. Новый TLS server локальный, без reverse proxy/реального клиента приложения. Короткий тест не измеряет capacity и не заменяет soak/GC.

## Порядок оставшихся работ

1. J7.2-local SQL/drill выполнены ([evidence](../planning/history.md#результат-j72-local--17-октября-2026)); до traffic отдельно подтвердить account-state reconciliation, Redis flow drain и новый trust всех Auth/consumers. SQL audit не доказывает distrust старого key.
2. J7/pre-ui: разрешённый HTTPS стенд, browser/native/backend integration, Redis/SQL/Auth/JWKS fault и fleet rotation/recovery acceptance. Не включать JWT ради проверки на рабочей среде.
3. A8: agreed hardware/profile/latency/error targets, mixed/hostile/soak/load-rest/shutdown; CPU/RSS/heap/GC/goroutines/SQL/Redis pools и storage drain. Записать measured capacity только по результатам.

Критичный FAIL блокирует traffic. NOT RUN оставляет gate открытым; переключение strict в local или отключение security guards не считается исправлением.
