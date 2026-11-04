# Текущий шаг

4 ноября 2026. Согласованный [план границ app](../planning/app-boundaries-audit.md#закрытие-плана) и дополнительная корректировка слоёв после R8 реализованы и приняты Luna V5. MP6R корректировка закрыта. Код закоммичен по запросу пользователя: `f0cefe8 refactor(app): разделил сборку и проектные сценарии`. Актуальный staging/commit смотреть через Git.

Snapshot `/private/tmp/auth-app-boundaries-v5-9ljmu5zm`, base8e3f7de; receipt `/private/tmp/auth-app-boundaries-v5-summary.json`. Main подтвердил0 runtime/source drift и0 ошибок13 SQL/Redis root exit/RUN/PASS markers. Targeted tests, lint0, affected race,11 SQL roots и2 Redis roots PASS. Это affected-only приёмка с reuse, не новый full task-check PASS. После snapshot изменена только итоговая документация. [Подробные границы/ограничения](../operations/acceptance-summary.md#границы-app-и-корректировка-слоёв--приёмка-v5-4-ноября-2026).

App — constructors/lifecycle/deployment source; project adapters — auth/project и access/project; preparation sequence — admin/projects/preparation/service. HTTP routes/handlers/middleware — transport/http/projects; закрытые profile и Sessions — auth/project/profile; Endpoints не раскрывает pools/cipher/rootconfig/state. Архитектура и карта содержат актуальные owners.

Следующий шаг — MP7 по основному плану; затем MP8 RPS/память/GC. UI только после отдельного предупреждения/согласования. Не повторять успешные проверки без delta. Проверки выполняет Luna 01a16eab-c777-78a0-a815-47b45ff0860d.

Retained R5 `/private/tmp/auth-r5-retained-fixture.json` сохранять. Required SQL roots прошли Linux ARM64/Unix socket; дополнительные host/TCP race replays Prepare/Operator несовместимы с passwordless fixture и не приняты. Real ENV/data, retained роли и чужой Docker не менять; default Docker named-volume capacity остаётся прежним отдельным ограничением deployment. Полные logs/exit — в receipt, не в текущем контексте.
