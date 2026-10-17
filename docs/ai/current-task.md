# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), checks — [history](../planning/history.md#результат-a63a-local--17-октября-2026). Это передача контекста, не архив.

## Последний результат — A6.3a-local

- Existing role API сохраняет mfaRequired. Omission/null на update не снимает policy; enable повышает role session_revision, OR нескольких ролей, current actor/proof/version/audit и fixed admin guards сохранены. Policy/metadata-only update не переписывает permissions; fan-out по пользователям нет.
- Required role без factor получает только browser-bound limited enrollment через включённый primary. Existing ledger/limits/shared activation, purpose login, current primary/state recheck, исходный TTL/attempts. Confirm возвращает recovery codes, не session; затем новый primary + MFA login. [Контракт/ограничения](../features/mfa.md#обязательная-mfa-по-роли--a63a).
- Issuance получает policy и role bindings одним SQL snapshot; direct INSERT не обходит MFA. Startup MFA-off отклоняет required роли; local readiness не доказывает fleet readiness.
- Formatter/task check/Swagger contracts PASS, lint 0 issues; full PostgreSQL 18.6/race/up-down-up PASS 35.048s. Non-owner SQL/HTTP/TOTP/rollback/replay/concurrent winner/late issuance и Google/Telegram/email OTP primary fixtures проверены локально, не живые внешние providers/SMTP.
- AS5-local (admin idle/absolute), AS6a/b-local (grant/permission elevation) уже реализованы. Source 000001 изменён, рабочие DB/ENV/secrets не трогались; controlled upgrade/invalidation прежних sessions/challenges до трафика остаётся обязательным. Коммит текущего блока — только по запросу.

## Следующий блок — A6.3b

1. Usable-admin/profile transitions и last reachable protected admin; self-status/policy для UI.
2. Сейчас private administrative login требует уже enrolled factor. Первичный limited enrollment требует включённого public primary; для нового custom-admin в admin-only профиле подготовить factor заранее. Выбрать безопасный конкретный onboarding до расширения private flow, не ослаблять preflight автоматически.
3. Соблюдать [матрицу совместимости](../planning/implementation.md#совместимость-настроек-и-безопасные-переключения--a63--a7), проверить concurrent toggles и pending/existing flows.

Затем A6.3c integration secrets/SMTP/providers/connection tests/rotation/runtime/fleet/retention; root/deployment keys остаются ENV. Родитель A6.3 открыт. Далее A6.4 [JWT](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. Cookie/session — default; strict online authority сохраняется, local-only JWT требует отдельного ADR. Следующая реализация и коммит — по запросу пользователя.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3b/c/pre-ui/A8 не закрыты. Только разрешённый изолированный HTTPS-стенд с synthetic data: browser/ingress/multi-tab/interaction-vs-polling/sleep-resume/SMTP/provider/authenticator/admin workflows, fleet settings и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений.
