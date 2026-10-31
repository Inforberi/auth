# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Email MFA](../features/email-mfa.md).

## Завершён A6.3m.6c.2 — внутреннее управление email-фактором

EmailMFA policy и EmailFactors Status/Enable/Disable: общий version/permission/audit, verified owned email proof + fresh password/current strong MFA, binding FK/suspension, auth_version/revoke/pending cleanup и финальные deadlines. Смена email/report/protected recovery приостанавливают старую привязку, deletion удаляет; потеря канала/optional mode не дают password-only bypass.

HTTP/ENV/startup сборки не подключены. CheckCapability закрывает email-enabled runtime до .6c.3. Email-only login/step-up/recovery и окончательные правила последнего фактора ещё не готовы; удаление email пока требует strong proof, удаление TOTP при email binding закрыто. Новых зависимостей/worker нет. Исходные up/down изменены, реальные DB/ENV не трогались, upgrade MP6 отдельно.

## Следующий шаг

A6.3m.6c.3 — bound email second-factor browser/native issuance, метод/assurance/JWT/introspection, email-only lifecycle/recovery и совместимость primary/factor. .6c.4 — profiles/readiness/protected HTTP/two-project gates до публикации. UI отдельно после предупреждения и согласования.

## Проверки

Luna: task check, affected race, TestEmailFactorLifecycleSchema, TestEmailFactorPreparationSchema, TestPostgresSchema, TestMFAPolicyEnforcementSchema и TestTwoProjectEmailHTTPIsolationSQL — PASS. Manifest 25/25 и cleanup подтверждены. Main сверил рабочие файлы до обновления Markdown, тесты не повторял.

Снимок `/private/tmp/auth-email-factor-lifecycle-v1.9__n4oih`, manifest/metadata рядом, base 0805b082694cc629188f0d06b43061943b744826. Luna thread 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:48. Evidence — в [history](../planning/history.md).
