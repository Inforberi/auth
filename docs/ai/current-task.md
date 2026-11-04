# Текущий шаг

4 ноября 2026. Весь R7 завершён и принят Luna; зафиксирован отдельным коммитом после PASS по разрешению пользователя. База R6 `a12ff58`; актуальный hash и staging смотреть через Git. Не повторять переносы R7 и его успешные проверки без нового затронутого изменения.

Root `internal/app` владеет процессом/ресурсами/HTTP; `auth.Assemble` возвращает borrowed Runtime. Проектные группы — `app/projects/{runtime,profile,browser,methods,account,mfa,native,access,settings,delivery,onboarding}`. Private crypto/limiters и прежние SQL/Redis guarantees сохранены; schema/routes/ENV/dependencies не менялись. [Архитектура](../architecture.md), [R7/R8](../planning/readability-refactor.md#r7-завершение-сборки-приложения-и-lifecycle).

Полная приёмка V5 `/private/tmp/auth-r7-final-v5-p4mvajgb`, manifest350 main сверил без расхождений. `task check` tests/lint0 PASS, affected race PASS, 15 SQL roots и RealmRedisIsolation actual RUN/PASS без skips, API PASS. Повторялось только затронутое, остальное evidence V3/V1 переиспользовано. [Сводка/evidence](../operations/acceptance-summary.md#r7-сборка-приложения--приёмка-4-ноября-2026); итог `/private/tmp/auth-r7-final-v5-summary.json`. После снимка менялись только документы статуса.

Следующий блок — R8: сквозное ревью безопасности/читаемости/владения ресурсами и сверка сохранённых suites/docs, исправлять конкретные дефекты отдельно от структурного переноса. Не объявлять весь MP7/MP8 выполненным: security/live gates, RPS/память/GC остаются. UI начинать только после отдельного согласования с пользователем.

Все исполняемые проверки/стенд — Luna `01a16eab-c777-78a0-a815-47b45ff0860d`; main пишет/форматирует/генерирует. Полные этапы передавать после реализации, не дробить ради промежуточной приёмки. Переиспользовать свой `auth-r5-retained` по `/private/tmp/auth-r5-retained-fixture.json`, очищать только свои данные. При проблеме tool report не обходить review, читать итог/evidence. Не трогать реальные env/БД/чужие Docker resources, новых зависимостей без разрешения не добавлять.
