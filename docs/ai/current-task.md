# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-a63c3-local--17-октября-2026). Это передача контекста, не архив; commits/staging проверять через Git.

## Последний результат — A6.3c.3-local

- [Retention settings](../features/retention-settings.md): три срока в SQL singleton/version; ENV только initial seed, protected GET/POST/current permission/fresh password+MFA/no-op/audit rollback, explicit confirmation сокращения. Значения в днях 1..106751; defaults 30/30/180.
- Worker читает current SQL snapshot перед каждой партией, без cache/new timers/pools/workers. Read failure отменяет очистку без ENV fallback; общий deadline 5s включает read. In-flight партия может использовать прежние сроки до deadline. Batch/interval остаются deployment, действующие session deadlines не меняются. SQL/race проверяет seed/update races, rollback, authority и реальную очистку/сохранность активных sessions.
- Formatter/Swagger/task check PASS/lint 0 issues; full PostgreSQL 18.6/race PASS 34.930s, targeted SQL/race PASS 1.783s и service/HTTP race PASS. Disposable PG на bounded tmpfs; рабочие DB/ENV/secrets не трогались. Source 000001 дополнен без рабочей migration, controlled schema/grants/seed rollout обязателен. Maintenance upgrade CLI не добавлен, mixed old/new fleet недопустим. Подробности проверок/cleanup — history. Коммит только по запросу.

## Следующий блок — A6.4

JWT по [согласованному плану](../planning/jwt-access.md): сначала конкретный подэтап/границы, cookie/session default и strict online SQL authority без ослабления ADR 002. Сохранить текущие SMTP/provider/retention contracts и fixed admin protection; не превращать settings в каталог всего deployment ENV. A6.3c/A6.3 остаются открытыми по внешней приёмке.

Затем pre-ui-backend → UI A7 → A8. Реальные provider/SMTP secrets и браузерные сценарии проверять перед подключением UI, не подменять локальными fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
