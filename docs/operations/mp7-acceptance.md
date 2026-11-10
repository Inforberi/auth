# MP7 — итоговая функциональная/security приёмка

Статус: локальные gates MP7 приняты 5 ноября2026; внешняя release acceptance NOT RUN. Исходный production code baseline — `557b1a0`; цель — закрыть MP7.1–.7, переиспользуя принятые проверки неизменённых зависимостей. Новые тесты требуют отдельного snapshot. Наличие теста в исходниках не означает PASS.

## Матрица требований

| Требование | Существующие сценарии и evidence | Приёмка |
| --- | --- | --- |
| MP7.1: два проекта, одинаковые email/UUID, отдельные настройки/роли/MFA и lifecycle | `TestTwoProjectHTTPIsolationSQL`, `TestTwoProjectEmailHTTPIsolationSQL`, `TestTwoProjectEmailMFAHTTP`, `TestTwoProjectAccessIsolationSQL`, `TestTwoProjectDirectoryIsolationSQL`; onboarding/managed nested drills в `TestPrepareCommandSQL` | V2 покрывает HTTP/email/MFA/Prepare; остальные roots и границы bootstrap сверить по MP7 receipt |
| MP7.2: credential A → B | SessionLifecycle, EmailHTTP, EmailMFARecovery, Token, OIDC, EmailOTP, IdentityManagement и MFARecovery isolation roots; собственный credential после негативной проверки должен работать | V2: sessions/email/MFA; Token/OIDC/OTP/Identity требуют актуального execution evidence; collision kid и self-promotion проверяются дополнительными assertions |
| MP7.3: admin boundary, stale proofs/versions, last-admin, host/header, no default fallback | OperatorProfileSQLHTTPS, role assignment nested drills, origin/auth configuration fixtures, DependencyRecovery, router security tests | V2 покрывает operator/host/session; остальные reused либо выполняет Luna. Production Compose evidence отдельно от real ingress |
| MP7.4: concurrent provisioning/replay/fault/restart | PrepareCommandSQL, StoragePreparationSQL и preparation schema/journal/credential/activation tests | Prepare V2 reuse; явно указать реальные crash/network случаи отдельно от injected failures; миграционный fleet из MP6 не считать реализованным тестом |
| MP7.5: pending flows/settings versions, rotation, eviction, cancellation, faults | DependencyRecoverySQL, OIDC revision/callback, runtime registry/pool/sync tests, platform lifecycle root | Lifecycle V2 reuse; остальные актуально проверить. Ошибка проекта A не открывает B, common dependency fails closed |
| MP7.6: ordinary Auth/MFA/access, immediate strict revoke, worker cleanup/leases | Auth SQL schema roots, MFA security notice concurrent claim/lease reclaim/stale ack tests, retention pages и refresh-history tests; runtime delivery fairness | Обычные DB suites — отдельный bounded runner Luna. Несколько repository/worker объектов над общей БД проверяют coordination; это не production fleet |
| MP7.7: отчёт | Snapshot+commit, command/exit, RUN/PASS/SKIP, schemas/grants/cleanup и scope re-use в receipt | Открыт до evidence всех строк |

Несколько существующих roots совместно покрывают требование: единый монолитный тест не нужен. Review helpers не являются evidence исполнения. V2 содержит ровно11 SQL roots; Token/OIDC не приписываются ему автоматически. Исторические утверждения «не реализовано» сверяются с текущим source, но не удаляются из истории.

## Переиспользование

`/private/tmp/auth-layer-boundaries-v2-summary.json` и snapshot `/private/tmp/auth-layer-boundaries-v2-7da4k02g`: targeted/security tests, lint0, race и11 SQL/HTTP roots. Production source и tests baseline совпадают с557b1a0; после receipt менялась итоговая документация. Иные исторические receipts принимаются только после сверки closure (production code, tests, SQL schema/grants/config/version), не по одному названию root.

Deployment V4 проверял synthetic Compose env, раздельные owner/runtime credentials, read-only API files/fs, закрытые SQL/Redis ports. Перед re-use сверить asset identity; иначе выполнить адресный существующий `sandbox/tests/security.TestProductionComposeSeparatesCredentials`. Local image build не доказывает реальный ingress.

## Условия и ограничения

- Только синтетические данные и retained R5 fixture. Unixsocket LinuxARM64 SQL runner, никаких broad reset/flush/чужих ролей и контейнеров. SKIP в credential-free Go phase не равен SQL PASS.
- Mock TLS providers/SMTP и injected Redis errors проверяют локальный протокол/ошибки, не внешнюю доставку/реальный network partition.
- Реальные Google/Telegram/SMTP/browser/ingress/fleet проверки требуют условий, которые пока не предоставлены. Они остаются NOT RUN и не закрываются source review. MP7.7 требует явно согласовать недоступный внешний gate до UI; общий запрос на MP7 не считается таким согласованием.
- Production capacity, предельный RPS, длительный GC/heap/goroutine профиль относятся к MP8. MP7 не добавляет UI, SSO, оплату, fleet migrations или destructive API.

## Выполнение

Luna получила baseline557b1a0 и instructions для недостающих roots, retained fixture и re-use. Ожидаемый receipt `/private/tmp/auth-mp7-v1-summary.json`. Основной агент не запускает executable проверки. Найденные дефекты исправляются до завершения, после code delta повторяется лишь затронутая область.

Промежуточный MP7 receipt выявил дополнительные незакрытые local gates: actual remaining roots при отсутствии совпадающего старого closure, synthetic production Compose config, StoragePreparationSQL lost-DDL/replay и ordinary Auth retention/outbox/refresh-history. Luna получила указание закрыть их реальным исполнением. Retained R5 teardown не требуется: стенд намеренно сохраняется, прежние role settings не являются новым test residue и не изменяются. Только own test cleanup; реальный fleet по-прежнему NOT RUN.

## Дополнительные assertions

В `TestTwoProjectTokenIsolationSQL` fixture задаёт одинаковый kid в scoped encrypted project bundles, сохраняя разные private keys; JWKS test явно подтверждает collision, прежние cross-rejection и own-success assertions сохраняются. Fixture меняет только synthetic test catalog. Production APIs/keys не меняются.

В `TestTwoProjectAccessIsolationSQL` project manager пытается выдать самому себе system administrator через защищённый HTTP API; проверяются403 и отсутствие super_admin assignment в БД. Общий запрет законного self-assignment не вводится.

Оба дополнения ещё требуют compile/lint и actual SQL PASS на отдельном snapshot. Production source остаётся557b1a0, baseline results можно переиспользовать вне test delta.

5 ноября: baseline receipt подтвердил отдельные новые local PASS; delta V1 не компилировалась (тип AuthVersion и повторный :=). Исправления переданы Luna в deltaV2, PASS пока не получен. Автоматическое approval review отклонило role create/drop в StoragePreparation fixture и запуск provider alias runner container в retained network; обход не выполняется. Это ограничения verification environment, не доказанные ошибки production. Для закрытия локальных gaps нужно уточнить разрешение на собственные synthetic roles/container; реальные и чужие ресурсы остаются неприкосновенны.

5 ноября пользователь разрешил завершить локальные gates, включая создание/удаление только собственных synthetic SQL-ролей и свой provider runner container. Прежние запреты на retained роли/реальные данные/чужие Docker сохраняются. Test delta V2 принят (compile/lint и actual Token/Access PASS), ошибки V1 устранены. В existing16claimer test используются два независимых repository объекта на общей SQL-БД: это проверяет DB lease coordination, не production multi-process fleet. Новый test-only delta требует проверки только затронутого MFA recovery root.

## Итог локальной приёмки — 5 ноября2026

Luna final receipt `/private/tmp/auth-mp7-final-summary.json`: LOCAL PASS для MP7.1–.7 в пределах synthetic/local матрицы. Дополнительно выполнены actual OIDC/Identity с локальными TLS aliases, StoragePreparationSQL lostDDL/replay/foreign guards и MFARecoveryCompletion delivery (16 claimers/2 repository objects). DeltaV2 same-kid Token и HTTP selfpromotion Access PASS. Baseline production557b1a0 не изменён. Main сверил Go files с worker snapshot (drift0),23 exit evidence0, RUN/PASS/noSKIP оставшихся OIDC/Identity/Storage roots.

Retained R5 остаётся healthy, own temporary roles/DBs/runner files очищены, RedisDB15 keys0, прежние retained role attributes сохранены. Собственный provider runner удалён после прогона. Запрещённые до уточнения действия выполнены только после прямого разрешения пользователя.

Локальный результат не доказывает real powerloss/network partition, работу реальных Google/Telegram/SMTP, browser/UI, production ingress, multi-process fleet или RPS/GC. Эти release gates остаются NOT RUN; MP8 — отдельный следующий этап. Общая MP7 checklist не является unconditional production PASS. Изменения тестов и документации пока не закоммичены.

Автоматическое approval review отклонило обратную отправку сообщения Luna в основной чат, поскольку не смогло подтвердить direct user authorization. Основной агент получил результат безопасным read-only чтением receipt и статуса чата; запрет не обходился повторной отправкой.
