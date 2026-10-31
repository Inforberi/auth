# Текущий шаг

Обновлено 31 октября 2026. [Карта](index.md) · [A6.3m.6a](../features/mfa-policy.md#метод-подтверждения--a63m6a). Git/staging проверять по факту.

## Завершён A6.3m.6a — Luna V1/V2 PASS

Новые TOTP/recovery proofs записывают Method/VerifiedAt в одной SQL transaction browser/native/step-up. Session validation/context сохраняют method; JWT/refresh используют otp/recovery, introspection сверяет точный метод+время. Исторический NULL — неизвестный coarse mfa, не автоматически TOTP. Исходная prerelease migration получила nullable mfa_method/CHECK и strong-class view filter; email/Telegram/unknown labels запрещены, текущие enrollment/freshness/role/recovery guards прежние. Реальные DB/ENV не менялись, existing DB upgrade/rolling отдельно MP6.

Luna V1 task check/affected races/core TestPostgresSchema/two-project HTTPS PASS; V2 targeted platform lint/TestPlatformOperatorsPostgres SQL race PASS. Штатный cleanup/manifest42 подтверждены; main сверил все42 файла/base HEAD со снимком перед итоговым обновлением Markdown, Go/SQL не менялись. Snapshot /private/tmp/auth-mfa-method-v2.wkgv9v1n, manifest/metadata siblings, base734a430e76ec51727ba103ebbb60a7d4eae2c2d0. Evidence /private/tmp/auth-mfa-method-v1-* и v2-*. V1 platform lock test FAIL устранён изоляцией canceled revoke probe explicit transaction/rollback; production guards не ослаблялись, подробности history. Пользователь разрешил коммит после PASS; новых dependencies/endpoints/settings/UI нет.

## Следующий шаг

A6.3m.6b: method-aware requirements для слабых почтовых/Telegram proofs на login/step-up/native/JWT/critical operations, до разрешения новых методов в SQL/API. Далее сами новые факторы/настройки, templates, security/refactor, MP7/MP8 ресурсы/maxRPS. Реальные external/fleet/full restart gates отдельно. UI только после предупреждения и отдельного согласования.

## Проверки

Только «Проверки Auth — Luna» 01a16eab-c777-78a0-a815-47b45ff0860d, host local, cursor 944a6e9d-49fe-49f7-8ff5-48acb6c615a1:44. Main tests/lint/SQL не запускает и не ждёт полный прогон. Go1.27.3/lint2.14.0. Core SQL и actual two-project roots отдельными процессами на своём disposable PG18.6/Redis8.2/TLS/SCRAM стенде; без real data/env/DNS изменений. Принятые suites повторять только при затронутых гарантиях.
