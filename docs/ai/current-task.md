# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Email MFA](../features/email-mfa.md).

## Завершён A6.3m.6c.4a — HTTP-адаптеры

EmailHandler: password→email challenge/complete, preparation/confirm, status/enable/disable. Отдельные файлы операций; proof только из context, отдельная Secure HttpOnly binding cookie, duplicate-cookie/unknown JSON rejection, cookie rotation/clear после успешной операции, no-store и существующий mapper. EmailMFAHandler policy Read/Update сохраняет expectedVersion/allowed; readiness и actor не берутся из JSON. Domain rules остаются в service/SQL.

Router/startup/profile/generated Swagger ещё не подключены, app эти constructors не вызывает; CheckCapability остаётся закрытым. SQL/services/runtime/ENV/dependencies/worker не менялись. Новых публичных ручек нет.

## Следующий шаг

A6.3m.6c.4b — scoped factories/readiness/SMTP/Redis/config budgets, явный выбор метода, forced native MFA без plain fallback, project/realm rewriting новой cookie, routes/Swagger и actual two-project/strong/role-transition/last-admin/recovery acceptance до публикации. Admin/platform matrix отдельно; UI только после предупреждения и согласования.

## Проверки

Luna: task check и targeted race обоих HTTP packages PASS; manifest19/19, temporary caches cleanup подтверждены. SQL/Docker не запускались для transport-only изменения. Main сверил рабочие файлы со снимком до обновления Markdown; Go не менялся.

Снимок `/private/tmp/auth-email-mfa-http-v1.w6nln1wl`, manifest/metadata рядом, base 7777c07d2021c2736456afdcb66eba6b02ad44fe. Luna thread 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:53. Все executable checks выполняет Luna; evidence — в [history](../planning/history.md).
