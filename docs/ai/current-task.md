# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4a-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — J4a-local

- [Refresh storage/profile foundation](../features/refresh-storage.md): immutable browser/api profile на общем session ledger; cookie operations и J3 exchange исключают API verifier. Family/verifier history/audit, immutable bindings/deadline, one-current/one-generation SQL constraints, consume/successor/reuse primitives, 30s между rotations и ceiling4096 credentials. Existing worker дренирует expired verifiers до family/ledger без массового cascade.
- Reused — результат, не ошибка: внешний owner обязан commit отзыва до401. Это проверено тестовым owner, runtime owner ещё не подключён. Storage не подписывает JWT, не renews idle и не заменяет current grants/policy/verification/MFA/provisioning guards. Нет native HTTP/login output/новых ENV/dependencies/workers; JWT_ENABLED включает только существующий J3 exchange/JWKS.
- Formatter/task check/lint PASS; full SQL -race PASS17.457s, final refresh SQL -race PASS2.252s; targeted domain/service/session HTTP -race PASS. Проверены concurrency/replay, rollback/audit failure, profile isolation, idle clamp/cap и bounded cleanup. Disposable PostgreSQL18.6 удалён; рабочие DB/ENV/secrets не менялись. Изменена source000001 без новой миграции: до deploy нужен controlled schema/grants upgrade, не reset рабочей БД.

## Следующий блок — J4b

Transaction-owned refresh по [JWT-плану](../planning/jwt-access.md)/ADR004: admission/Redis до SQL, Access→user/session/family locks, current grants∩family scope∩audience/policy/verification/MFA/provisioning, допустимый idle renew без admin activity, clamp access expiry/local signing/audit/commit. Reused commit до401; raw credentials только после commit. pgx transaction не выходит из repository. Затем cookie-free password/email OTP+MFA credential output/restricted challenges без копирования primary pipelines. До native publication — SQL/API negative/concurrency tests, management profile label, retention candidate-scan/held-ledger eligibility/backlog/drain/storage checks. Не добавлять bearer fallback на cookie/admin routes; direct native providers — J4c, strict consumer — J5.

Затем J4 native password/email OTP+MFA/refresh (direct native provider handoff — J4c) → J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
