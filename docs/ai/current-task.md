# Текущий шаг

Обновлено 16 октября 2026. Краткая передача контекста; статусы — [implementation](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui), результаты проверок — [history](../planning/history.md).

## Последний результат

Упорядочены AGENTS, карта проекта и выбор проверок. Исторические записи убраны из заметки: результаты сохраняются в history, контракты — в профильных документах. Новых инструментов, RAG, зависимостей и изменений приложения нет; измеренная экономия токенов не установлена.

Последний backend-блок — AS1–AS4-local: строгие session cookies, lifecycle mutations без sliding refresh, route guardrail и SQL/HTTP ordering. Код — 4b70654, планы — 6526c8e. Это локальные проверки, не закрытие A6/pre-ui/A8.

## Следующий backend-блок

AS5 — отдельная admin lifetime policy; AS6 — повышение прав и изменение факторов, вместе с A6.3 MFA/custom roles/enrollment. Конкретные сроки выбрать до изменения defaults, SQL authority/немедленный отзыв/fresh proofs сохранить. Затем A6.4 [JWT](../planning/jwt-access.md) → pre-ui-backend → UI A7 → A8. JWT пока не реализован, local-only требует отдельного ADR.

## Открытые условия

Реальные browser/ingress/multi-tab/SMTP/provider/authenticator/operator сценарии, fleet consistency и [13.1d.4 drill](../operations/mfa-recovery-acceptance.md) остаются открытыми. Проверять на разрешённом изолированном HTTPS-стенде с synthetic data; отсутствие credentials/оператора — NOT RUN, не PASS. A8-admin-e2e, mixed load 6.8b, память/GC 6.8c, shutdown/backup/restore обязательны. Capacity всего сервиса не установлена. Следующая реализация и коммит — по запросу пользователя.
