# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), checks — [history](../planning/history.md#результат-a63b-local--17-октября-2026). Это передача контекста, не архив.

## Последний результат — A6.3b-local

- Ограничение public login через settings требует usable system super_admin: password/verified credential email/TOTP/status/provisioning readiness под existing Access lock; без fan-out. `409 last_administrator` не меняет policy/version/audit. No-op/открытие метода не блокируют recovery. [Правила и границы](../features/auth-settings.md#безопасные-переходы-и-подготовка-администратора--a63b-local).
- Owner GET `/api/v1/auth/mfa/status`: factor/role/admin policy, recovery count/contact/proof flags. Один SQL snapshot, общие predicates с sensitive mutations, Origin/live session/no-refresh/no-store, без secrets/cookie/audit/guessing counters. [Контракт](../features/mfa.md#статус-mfa-для-владельца--a63b).
- Новый администратор готовит password/verified email/TOTP/codes до закрытия public primary; temporary public opening — project-wide с закрытой регистрацией. Private login не ослаблен; при запрете такого opening нужен отдельно согласованный restricted private onboarding, не direct SQL.
- Formatter/Swagger/task check PASS, lint 0 issues; full PostgreSQL 18.6/race PASS 30.565s, targeted non-owner profiles/settings/status PASS. Новых ENV/schema/dependencies/workers нет, рабочая DB/secrets не менялись. Коммит — только по запросу.

## Следующий блок — A6.3c

Integration secrets/SMTP/providers: определить минимальный versioned protected update и masked reads; secrets не возвращать, network connection tests вне SQL locks. Rotation/lifecycle/runtime propagation и fleet consistency, затем retention/runtime settings; root/deployment keys остаются ENV. Не создавать пустые поля/adapters. Родитель A6.3 открыт; [матрица совместимости](../planning/implementation.md#совместимость-настроек-и-безопасные-переключения--a63--a7) и внешняя приёмка остаются обязательными.

Далее A6.4 [JWT](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. Cookie/session — default; strict online authority сохраняется, local-only JWT требует отдельного ADR. Код определяет поведение; фактические commits/staging проверять через Git.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый изолированный HTTPS-стенд с synthetic data: browser/ingress/multi-tab/interaction-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only workflows, fleet settings и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Source 000001 изменён предыдущими блоками; controlled upgrade/invalidation старых sessions/challenges до трафика обязателен, не reset/mixed fleet. Не включать cache/GC tuning без измерений.
