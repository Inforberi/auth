# Текущий шаг

Обновлено 16 октября 2026. Это передача контекста, не история. Статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), checks — [history](../planning/history.md#результат-as6a-local-и-lifetime-regression--16-октября-2026).

## Последний результат — AS6a-local

- Новое обычное/system назначение роли активному пользователю атомарно повышает auth_version: старые sessions/stale refresh не наследуют grant. Нужен новый login с действующим MFA. No-op не разлогинивает, revoke уменьшает live permissions без logout-all, pending сохраняет invitation/activation version.
- Использованы существующие UPDATE users/ordered locks/audit/session authority. Нет новых schema/ENV/dependencies/hot-path calls, fan-out UPDATE или cache. [Решение](../planning/auth-security.md#решение-as6a-новое-назначение-роли), [контракт](../features/roles-permissions.md).
- Formatter/task check (lint 0 issues), access/session race, полный SQL/race suite до финального pending исключения и финальные targeted system/HTTP/access/onboarding regressions PASS; условия в history. Synthetic new-login fixture не заменяет настоящий primary/MFA/browser E2E. Тестовый контейнер/данные удалены, рабочие ENV/БД/secrets/defaults не менялись.
- AS5 regression подтверждает persisted absolute deadline и неизменность primary/MFA timestamps при refresh. Отдельный admin idle/absolute профиль пока не реализован; нынешние 7/14 дней не объявлены подходящими admin defaults.

## Следующий backend-блок

1. AS6b: повышение permissions через edit уже назначенной роли. Выбрать и проверить session authority binding без массового UPDATE всех владельцев роли; новый grant покрыт AS6a, role edits пока сохраняют прежнее live-поведение.
2. AS5: согласовать admin inactivity/absolute сроки, смысл активности и погрешность bounded touch; не менять defaults без решения/тестов. Учесть existing sessions и NoRefreshAuth.
3. A6.3: совместить с MFA по custom roles/enrollment-required; затем integration secrets/SMTP/provider rotation/connection tests, retention и runtime propagation. Root/deployment secrets остаются вне UI.

Далее A6.4 [JWT J1–J7/S1–S10](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. JWT не реализован: cookie/session — default, strict online authority сохраняется; local-only требует отдельного ADR с принятым окном отзыва. Следующие изменения приложения и коммит — по запросу пользователя.

## Открытые условия приёмки

- AS5/AS6b/A6.security целиком не закрыты. AS1–AS4-local уже выполнен, browser/ingress/multi-tab/lost-response gates остаются открытыми.
- До UI — разрешённый изолированный HTTPS-стенд с synthetic data: реальные SMTP/provider/authenticator/admin workflows, fleet settings consistency и [13.1d.4 recovery drill](../operations/mfa-recovery-acceptance.md). Нет credentials/оператора — NOT RUN, не PASS; автоматически включать реальные методы нельзя.
- Финальные A8/A8-admin-e2e, mixed/multi-instance load 6.8b, память/goroutines/GC 6.8c, shutdown/backup/restore открыты. Capacity всего сервиса не установлена.
