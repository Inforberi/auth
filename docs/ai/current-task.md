# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Матрица приёмки](../operations/acceptance-summary.md#сверка-email-mfa-4b--1-ноября-2026) · [Контракт](../features/email-mfa.md#завершение-приёмки--a63m6c4b4-pass-luna).

## Завершён .4b.4 — Luna V2 PASS

Расширен TestTwoProjectEmailMFAHTTP: реальный Redis counter fault при browser/native completion без credentials/consume/SQL attempts; после восстановления TTL/budget и одна сессия, replay. Новый TestTwoProjectEmailMFARecoveryHTTP: suspended email-only без TOTP, recovery next-step/binding, runtime self-approval denial, независимое operator approval, новый TOTP/recovery codes без auto-login, отзыв/replay/neighbor isolation и последующий вход.

Luna V2: manifest8/8, task check и оба actual HTTP/SQL/Redis roots с race/count1 PASS без SKIP; DB/roles/schemas/Redis DB15, containers/certificates/caches очищены. Снимок `/private/tmp/auth-email-mfa-acceptance-v2.73yhniq0`, base a9d8628; evidence turn `01a196b9-5b12-7e11-b749-eabf73dc45b7`, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:64`. V1 compile FAIL исправлен в operator fixture вызовом SQL через existing pgx.Conn. Подробности — в [history](../planning/history.md).

Main сверил8/8 до обновления только Markdown, исполняемые проверки не запускал. Runtime/schema/config/API/dependencies не менялись. Локальная .4b завершена; пользователь разрешил коммит после PASS.

## Далее

Выбрать следующий согласованный pre-UI блок по implementation, не расширять закрытый .4b. Email MFA project-only/default-off; Redis counter fault не доказывает network partition. Внешний SMTP/browser/provider, MP6 upgrade, fleet/capacity/длительный GC остаются отдельными gates. UI не начинать без предупреждения и отдельного согласования пользователя.

Локальный исследователь Luna (`gpt-6-luna`, Jason, `01a196ae-b5d3-7313-acb1-b14dad3aa9b6`) выполнил read-only recovery navigation. Проверочный чат отдельно: «Проверки Auth — Luna», `01a16eab-c777-78a0-a815-47b45ff0860d`, host local. Поиск и исполнение проверок не смешивать.
