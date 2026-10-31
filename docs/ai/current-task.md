# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [A6.3m.6b](../features/mfa-policy.md#строгий-proof-для-критических-действий--a63m6b). Git/staging проверять по факту.

## Завершён A6.3m.6b — Luna V1/V2 PASS

Critical SQL guards используют strong_mfa_verified_at только для known TOTP/recovery. Ordinary session/optional password-only сохранены; historical NULL требует existing step-up для strict operations. External JWT RequireStrongMFA(maxAge) после Consumer.Middleware и вместе permissions проверяет known fresh factor; Principal передаёт immutable AMR/time. Ordinary JWT/introspection/localTTL прежние. Новых factor flows/settings/deps нет, real DB/view upgrade отдельно MP6.

V1 task check/affected race/core schema/platform operators/two-project Access PASS; V2 targeted app/auth lint0/operator HTTPS race PASS. Штатный cleanup/manifest36 подтверждены, main сверил все36 файлов/base HEAD перед итоговым обновлением Markdown, Go/SQL не менялись. V1 offline guard failure исправлен ownfixture password для SCRAM без ослабления production guards. Snapshot /private/tmp/auth-strong-mfa-v2.3fythd53, manifest/metadata siblings, base39bd7da5a91e01d1906e75ec20cd9aea4783fd49. Evidence/ограничения — history и Luna turn01a19389-655a-7e40-8d7d-ba34493a362e. Пользователь разрешил коммит после PASS.

## Следующий шаг

Email second factor: permitted primary/second combinations, verified channel binding, challenge/consume/issuance atomicity, runtime policy/личный выбор. Затем Telegram, templates, security/refactor, MP7/MP8 ресурсы/maxRPS. Не расширять просто enum/CHECK, считая любой timestamp строгим. UI только после предупреждения и отдельного согласования.

## Проверки

Только «Проверки Auth — Luna» 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:46. Main tests/lint/SQL не запускает и не ждёт полный прогон. Go1.27.3/lint2.14.0; own disposable PG18.6/Redis8.2/TLS/SCRAM/readonlysrc. Realdata/env/DNS не менять; повторять только затронутые guarantees.
