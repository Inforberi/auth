# Текущий шаг

Обновлено 28 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Завершённый блок — MP5.1p project SMTP settings

[Контракт](../features/project-smtp-settings.md). Local SMTP GET/POST/test, default-off manifest smtpSettings/browser prerequisite, optional ProjectProfileConfig.SMTPSettings allowlist. Metadata read без Redis/MFA/SMTP; write/test readyMFAmanagement/Redis/validallowlist, NoRefresh/exactOrigin/SQLauth.settings.manage/freshpwdMFA/version/audit. Existing DTO/service/crypto/SQL сохранены. Missing row GET403 по существующему readguard, не seed/ENVfallback.

ProjectSMTPSettingsRepository берётonelease5s/pre-post binding наSQLoperations; persistentSMTPservice.TestConnection освобождаетAuthorizeSMTPTest lease перед network. Scoped cipher/root/limits existingprojectSMTP; exact allowlist existingprojectDeliveryENV captured/copy onlyonexplicitUUIDflag. SharedSMTPTestGate2 наProjectHTTP owner переживаетprofile eviction/rebuild (directbuild callers могутпередатьgate); oldNewSMTP standalone семантикасохранена. Probe10s/3user/min/10project/min, binding checks before/after successfulnetwork. No new schema/deps/ENV/workers/cache.

Main formatter/source review. Source/default-off/isolation/copy/prerequisite/routes и sharedgate behavior test. Actual projectSMTPsettingsHTTP в accountfixture проверяет права/Origin, secrets/rotation/preservation/noop/version/allowlist/TLS/429/missingrow-no-seed; controlled noSTARTTLS409 до AUTH, registry pool и SQL row lock доступны во время network. Свои SMTP/audit/Redis keys восстановлены.

Luna task check/task check:api/targeted race/full Linux ARM64 TestPrepareCommandSQL PASS; project_SMTP_settings_HTTP без skip. Manifest15+JSON hashes совпали до/после прогона и с main; disposable containers/network/certificates/test binary удалены. Snapshot `/private/tmp/auth-project-smtp-settings-v1.kleg66me`, manifest/metadata sameprefix, logs `/private/tmp/auth-project-smtp-settings-v1-*.log`. Пользователь разрешил коммит после PASS; факт проверять Git.

## Следующий шаг

Project Google/Telegram settings, retention и MFA policy. FullMP5 two-project/phase-ready/operations/MP6R/MP7/MP8 отдельно. UIтолькопослепредупрежденияиотдельногосогласования. RealSMTPdelivery/externalmatrix/GC/RPSне считатьзакрытыми.

## Процесс

- Researcher01a1797b-d48d-7d71-9e48-2d92dc22d9f2 Luna medium read-only/reuse. Все executablechecks толькоотдельныйчат Luna01a16eab-c777-78a0-a815-47b45ff0860d hostlocal/exactsnapshot; default6377/authstale. Mainне дублирует/неждётполныйпрогон. [Процесс](development-workflow.md).
- SQL ownLinuxARM64 postgres18.6 readonly/src; sockettrust/TCP127SCRAMwrongpwdeny/TLSSAN127, Redis8.2 sharednetworkDB15. SCRAM_HOST/TLS_CA/ROOT/src/Redis127mandatory. Cleanuponlyownfixtures, realENV/secrets/DB/stagingсохранять.
- PreviousMP5.1o policyPASS commit739b099; Последний Luna cursor19bf04ec-f4f6-4693-9c20-73f414b172e4:18. Securityранее0reachable/1requiredmoduleadvisoryвнеcallgraph, MP6Rотдельнобезнесогласованногообновленияdeps. FullMP5/MP7/MP8/UIgatesоткрыты.
