# ADR 001: самостоятельный single-app шаблон и переносимость

Статус: принято, 6 октября 2026. Реализация: 4, 7, 14.

## Решение

Каждый проект получает свой экземпляр, DB, Redis namespace, users и secrets. User UUID принадлежит этому экземпляру; fork не создаёт общий аккаунт между проектами. Один app scope — базовый профиль. Multi-app, организации и общий SSO включаются отдельным решением с проверкой issuer/subject/audience/ownership, не подразумеваются существующей схемой.

Браузер — HTTPS cookie/BFF, без долгоживущего JWT как единственного источника актуальных прав. Native/API token access проектируется отдельно, когда выбран клиент. Сохраняем существующие service/repo/transport и явную DI; бизнес-расширения реализуются в проекте, не через динамическую загрузку plugins.

Уточнение структуры: `internal/modules/auth` организован по фичам, без общего `core` и слоя `featers`; технические зависимости — в узких `internal/infra` пакетах, wiring — в `internal/app`. Ownership типов, правила зависимостей и лимит 150 строк для рукописных исходников/tests зафиксированы в [архитектуре](../architecture.md). Перенос — отдельный behavior-preserving подэтап 4.0 до новых schema/security изменений.

## Последствия

Перенос требует новых module/name/secrets, собственных каталогов ролей и функций, писем и provider registrations. Секреты и реальные пользовательские данные не входят в template. В 14.4 disposable sample product доказывает независимый старт с custom permission/plan и без оплаты. В 14.5 — pinned dependencies, changelog, отдельные проверяемые upgrades и перенос upstream security fixes; никакой слепой замены go.sum.

После первого production релиза схема изменяется новыми миграциями. Пока сохраняется правило редактирования текущих up/down SQL и проверки только отдельной disposable DB. Исходный go-template больше не требуется: provenance в [template-adoption](../template-adoption.md).
