# Текущий шаг

2 ноября 2026. R1 карта переносов подготовлена; R2 sandbox локально принят Luna на `/private/tmp/auth-r2-sandbox-v2-d95ul626`: manifest78,13 roots/skip gates/assertions сохранены, чистый task check/lint0 и sandbox race PASS, formatter без изменений. V1 Compose config/образ приняты по эквивалентности. [Итоги](../operations/acceptance-summary.md#mp6r-r2-перенос-sandbox--2-ноября-2026). Live readiness и TestPrepareJWT NOT RUN: существующий auth-sandbox чужой, не изменять его контейнеры/данные. Это отдельный открытый live gate, не доказательство production capacity.

Следующий рабочий блок R3 — общая панель/проекты/cmd, включая [миграции Auth/admin](../planning/readability-refactor.md#миграции-и-подготовка-бд). Действовать по карте R1: фича/tests/callers/docs вместе, сохранять SQL names/версии/checksum/permissions/crypto scopes и транзакции. Новые функции и зависимости не добавлять. Source backend до R3 не менялся. Все исполняемые проверки — отдельному чату Luna на неизменяемом снимке. UI только после отдельного предупреждения и согласования.

План/архитектура:43e0a38; Telegram final:58714c1. Source initial migration prerelease, без новой миграции ради рефакторинга; controlled upgrade и внешние Telegram/SMTP/ingress gates отдельно. Коммиты/staging сверять через Git.
