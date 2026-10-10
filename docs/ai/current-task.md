# Текущий шаг

Обновлено 10 октября 2026. Это рабочая заметка, не дубликат полного плана. При смене задачи обновлять её после фактического результата; не выдавать устаревшую заметку за авторитетнее кода и implementation.

- Текущий результат: по разрешению пользователя исправлены узкие места аудита в 6.4a/6.8a — shared hash/login/HTTP budgets, deadlines/proxy/cookie bounds, CAS refresh/no-op, отдельный bounded GC и indexed stable cutoffs, coalesced readiness. Настройки, измерения и ограничения — [performance](../operations/performance.md).
- Уточнение плана: производительность и bounded ресурсы входят в приёмку каждой следующей фичи сразу; постоянное правило закреплено в roadmap/implementation и AGENTS.md. SQL-only результат и защитные лимиты не объявляются capacity полного API; 6.8b открыт. В этом уточнении изменены только документы, `git diff --check` пройден; runtime-проверки повторно не запускались.
- Последний backend-результат: [5.6a deletion](../features/account-deletion.md), локальная приёмка 5.5e выполнена. Полные статусы — [implementation, раздел 5](../planning/implementation.md#5-emailpassword-lifecycle).
- Следующий шаг: согласовать измеримый mixed/multi-instance load profile 6.8b либо продолжить provisioning/invitations 5.7; 6.4/6.8 и release целиком не закрыты. Restore reconciliation и отдельная policy для blocked reservations остаются открытыми; UI в конце, внешняя SMTP/browser-приёмка открыта. Reservation использует существующие контакты, не HMAC storage; не обещать полное PII erasure.
- Ограничения: дерево Auth сохранено; secrets и рабочая БД не меняются; до первого release схема редактируется в исходной 000001, без новых промежуточных миграций и reset БД.
- Проверки: SQL correctness/concurrent refresh, EXPLAIN на 100000 rows, короткий SQL-only read benchmark, Redis shared quota/failure, targeted race, Swagger generation/drift, `task check` (тесты и lint, 0 issues), formatter и diff check. Тестовые контейнеры удалены; подробности в history. Это не mixed API load и не production acceptance. Рабочая БД/secrets не тронуты.

По отдельному запросу пользователя изменения разделены на коммиты: конкурентное продление сессий, sampling логов, защита ресурсов/фоновая очистка и документация. Runtime-код при подготовке коммитов не менялся; использованы уже выполненные проверки, дополнительно проверен staged diff.

Следующую реализацию начинать только по запросу пользователя, после сверки соответствующего пункта плана. Коммит — только по отдельному запросу.
