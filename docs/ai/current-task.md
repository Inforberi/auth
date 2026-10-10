# Текущий шаг

Обновлено 11 октября 2026. Это рабочая заметка, не дубликат полного плана. При смене задачи обновлять её после фактического результата; не выдавать устаревшую заметку за авторитетнее кода и implementation.

Уточнение 11 октября: по запросу пользователя в roadmap/implementation добавлен 5.7c — optional временный пароль с TTL, безопасной однократной выдачей и backend-enforced обязательной сменой через ограниченное полномочие. Приглашение остаётся основным способом, verification/MFA не обходятся. Только документы; runtime/env/schema не менялись, проверки кода повторно не запускались, `git diff --check` пройден.

- Текущий результат: реализован и локально проверен 5.7a — внутренний idempotent provisioning/pending account и optional POST password activation, без ролей/сессии/grants. Owner/version/expiry/audit и activation marker атомарны, Redis/shared hash budgets сохранены, доставка/GC через текущие workers. Config disabled по умолчанию; admin endpoint отсутствует. [Контракт](../features/invitations.md).
- Уточнение плана: производительность и bounded ресурсы входят в приёмку каждой следующей фичи сразу; постоянное правило закреплено в roadmap/implementation и AGENTS.md. SQL-only результат и защитные лимиты не объявляются capacity полного API; 6.8b открыт. В этом уточнении изменены только документы, `git diff --check` пройден; runtime-проверки повторно не запускались.
- Предыдущие backend-результаты: 5.6a deletion/5.6b-worker и 6.4a/6.8a оптимизация. Полные статусы — [implementation, раздел 5](../planning/implementation.md#5-emailpassword-lifecycle); бюджеты и ограничения нагрузки — [performance](../operations/performance.md).
- Следующий шаг: 5.7b — перевыпуск invitation для прежнего pending UUID с заменой token, отдельной idempotent командой, cooldown/limits/audit. Admin transport после 10/13.1, UI в конце; non-password activation после 7/8. Mixed/multi-instance 6.8b, restore/ban-erasure и внешняя SMTP/browser приёмка открыты; release и полное PII erasure не заявляются.
- Ограничения: дерево Auth сохранено; secrets и рабочая БД не меняются; до первого release схема редактируется в исходной 000001, без новых промежуточных миграций и reset БД.
- Проверки: SQL correctness/concurrent refresh, EXPLAIN на 100000 rows, короткий SQL-only read benchmark, Redis shared quota/failure, targeted race, Swagger generation/drift, `task check` (тесты и lint, 0 issues), formatter и diff check. Тестовые контейнеры удалены; подробности в history. Это не mixed API load и не production acceptance. Рабочая БД/secrets не тронуты.

Проверки 5.7a: `go test ./...`, formatter/lint 0 issues, targeted race services/router, Swagger generation/drift и полный disposable SQL suite. SQL concurrency 16 requests — один activation/один созданный UUID, rollback и invalidation/delivery/GC; HTTP origin/errors/no-cookie/disabled/GET/Swagger проверены. Подробности — history. Тестовый PostgreSQL удалён с синтетическими данными; рабочая БД и secrets не менялись, изменения 5.7a не закоммичены.

Следующую реализацию начинать только по запросу пользователя, после сверки соответствующего пункта плана. Коммит — только по отдельному запросу.
