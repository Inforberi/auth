# Документация Auth

- [Архитектура](architecture.md), [схема](schema.md) и [модель угроз](threat-model.md) — решения и границы проекта.
- [API-контракт](api/contract.md) — текущее поведение ручек. `api/generated/` содержит только generated Swagger; источник — DTO/аннотации в коде. Генерация: `task swagger`, проверка drift: `task check:api`.
- [Фичи](features/) — verification, recovery, смена email и удаление аккаунта.
- [Roadmap](planning/roadmap.md) — согласованные этапы и scope; [implementation](planning/implementation.md) — конкретные задачи и статусы; [history](planning/history.md) — прошлые результаты проверок, не инструкция следующего шага.
- [ADR](adr/) — причины архитектурных решений; [template-adoption](template-adoption.md) — происхождение инфраструктуры.
- [Навигация для AI](ai/index.md) и [текущий шаг](ai/current-task.md) — компактные указатели на первоисточники, не копия документации.

Документы описывают в том числе будущие возможности. Поддержку функции подтверждают её статус, код и проверки; наличие пункта в плане не означает реализацию.
