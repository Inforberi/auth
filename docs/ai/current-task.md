# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Матрица приёмки email MFA](../operations/acceptance-summary.md#сверка-email-mfa-4b--1-ноября-2026) · [Реализация](../planning/implementation.md).

## Завершена сверка .4b

.4b.1–.3 приняты Луной: recovery prerequisites, проектный browser/native email MFA и manifest/ENV opt-in default-off. Последний кодовый коммит `0e574f2`; снимок `/private/tmp/auth-email-mfa-deployment-v2.uZ7dUVWW`, manifest20/20, task check/affected race/actual manifest-backed HTTP/SQL PASS с cleanup. Evidence Luna: turn `01a19694-19dd-7501-89d8-45c500342cbd`, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:62`; подробности — в [history](../planning/history.md).

Сверка уточнила границы компонентных и HTTP проверок, убрала устаревший общий запрет проектного email MFA из описания текущего состояния. Expiry, concurrency, role transitions и strict-proof уже подтверждены; повтор полного набора не нужен. Код/config не менялись, новые исполняемые проверки не запускались.

## Далее — .4b.4

Два недостающих интеграционных сценария, не найденные runtime-баги:

1. Actual HTTP browser/native completion при отказе Redis admission: без consume/выдачи credentials/plain fallback; после восстановления — ограниченный повтор и один результат.
2. Actual HTTP recovery именно email-only аккаунта без TOTP при потере/suspension email: recovery next-step/binding, независимое DB operator approval, новый TOTP, отзыв/replay/cross-project denial, без автоматического входа.

Использовать существующие fixtures/ручки, проверки передать отдельному чату «Проверки Auth — Luna». Shared Redis outage не предполагает доступность соседнего проекта. Общий .4b остаётся открытым до приёмки этих веток.

Внешний SMTP/browser/provider, MP6 upgrade, fleet/capacity/длительные GC проверки — отдельные gates. UI не начинать без предупреждения и отдельного согласования пользователя.
