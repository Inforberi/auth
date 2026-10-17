# Текущий шаг

Обновлено 17 октября 2026. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), проверки — [history](../planning/history.md#результат-j4b2c3-config--17-октября-2026). Commits/staging проверять через Git.

## Последний результат — J4b.2c.3-config

- [Native deployment policy](../features/refresh-storage.md#настройки-native--j4b2c3-config) подключена к App token service: `JWT_NATIVE_ENABLED=false`, refresh idle/absolute defaults7/14d в пределах session ceilings. Требуются JWT/MFA capability; обязательность факторов остаётся SQL policy. Disabled native не добавляет prerequisites cookie exchange.
- Startup guard `2×P×(I+5s)≤B×1m`: один cleanup worker с явным запасом, общий P issuance ceiling, тот же batch deadline, что в Purge. Нет auto-tuning TTL/batch/лимитов или replica multiplier. Default P3000/B100/I1m не пройдёт native enable, оператор должен согласовать deployment budgets. Guard не доказывает measured drain/backlog/storage capacity.
- Formatter/task check/lint0 PASS; ENV, dependency flags, lifetimes/admin bounds, budget arithmetic boundaries/overflow range, immutable snapshot/disabled compatibility и отказ JWT assembly до files/pool проверены. SQL/Lua/HTTP/dependencies не менялись; real Redis native assembly/full SQL/внешние/load/GC/restore повторно NOT RUN. Рабочие DB/ENV/secrets не трогали. Новых native HTTP маршрутов нет; J4b.2c.3/parent J4b.2c открыты.

## Следующий блок — J4b.2c.3-http

По [JWT-плану](../planning/jwt-access.md): App HTTP coordination с переиспользованием existing primary/MFA/email cores. Password/email request-confirm/MFA/enrollment/refresh/logout, no-store/conflicting credentials/safe errors/Retry-After, management profile label/Swagger и negative/concurrent API tests. Не принимать клиентский PrimaryProof/user/assurance/admin intent; не добавлять bearer fallback на cookie/admin routes. Не создавать второй password/email/MFA pipeline, лишние pools/workers или service accessors ради технических зависимостей. Logout core требуется проверить/реализовать вместе с owner SQL guards, не превращать неизвестный refresh в чужой logout-all. Lost-all-factors остаётся browser/operator recovery, не native bypass.

Native config уже формирует constructor policy, но HTTP не опубликован. Source000001 profile/refresh/checkpoint columns/tables/seeds/grants нужны binary независимо от native flag; рабочая DB не мигрировалась. [Bounded cleanup](../features/refresh-storage.md#ограниченный-обход--j4b2c2-local) локально проверен, physical lag включает sweep/drain; fleet/storage/fault/load приёмка открыта. Default budgets не менять автоматически. Direct native providers — J4c, strict consumer — J5.

Затем J4c/J5 → J6 config/UI contract → J7 → pre-ui-backend → UI A7 → A8. Текущие SMTP/provider/retention contracts и fixed admin guards сохранены; A6.3c/A6.3 внешне открыты. Реальные provider/SMTP/browser workflows проверять перед UI, не подменять fixtures.

## Открытая приёмка

AS5-external/AS6 целиком/A6.3/pre-ui/A8 не закрыты. Только разрешённый HTTPS-стенд/synthetic data: browser/ingress/multi-tab/activity-vs-polling/sleep-resume/SMTP/provider/authenticator/admin-only/fleet/rotation/egress и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS. Mixed/multi-instance load 6.8b, память/GC 6.8c и shutdown/backup/restore обязательны; capacity не установлена. Не включать cache/GC tuning без измерений; source upgrades не равны рабочей migration.
