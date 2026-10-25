# Настройки проекта и фактическая готовность

MP5.1e, 25 октября 2026. Реализовано; локальные проверки Luna V1/V2 PASS.

- Trusted assessment из того же ProjectHTTP/source/owners, а не HTTP booleans или static ENV capabilities. Проверить потенциальные методы при выключенной SQL policy, не строить readiness только по active routes. Password capability оценивается без verification, дополнительная готовность verification/delivery проверяется отдельно при сохранении соответствующей политики.
- Administrative GET/PUT выполняет current operator/target authority до и после bounded assessment. Все assembly/credential probes вне registry lease/SQL locks policy mutation; затем прежний committed admission3s и транзакция. Фабрики/ключи/SMTP/provider validators переиспользуются, assessment не публикует routes и не создаёт новые process owners.
- Перепроверять current key/policy и версии использованных SMTP/provider rows; при записи pin metadata versions под locks, сохраняя SQL dependency/expectedVersion/receipt/audit/no-op/replay правила. Отключение методов не требует их исправной работы. Shared Redis/worker failure даёт недоступную capability, не разрешение обходить SQL authority.
- API получает actual availableMethods/token profiles и безопасные причины readiness без secrets. Observation point-in-time, не обещание внешней SMTP/provider доступности; historical operation settings не считаются current readiness. Ни positive authority cache, ни сборка на каждом обычном login request не добавляются.
- Tests: disabled→enable, noSMTP password, verification/provider missing, stale metadata, authority loss/no probe, replay, no nested UsePool/3s admission eaten. Main formatter/API generation; Luna task check/API/race/security и actualSQL.

## Контракт API

Существующий GET `/api/v1/platform/projects/{id}/auth/settings?expectedVersion=…&expectedGeneration=…` сохраняет policy/version и дополняет их фактическими `availableMethods`, `tokenProfiles` и optional `readiness: {policyVersion, observedAt, features:[{feature,ready,reason}]}`. `availableMethods` относится к общей policy: password/email OTP могут быть готовы для browser и/или native; подробные feature names различают эти профили. Это возможные настройки, а не список включённых текущей policy routes.

Password capability проверяется без требования verification. При сохранении optional/required verification нужен отдельный `verification` и delivery readiness; один готовый recovery/OTP factory не подменяет verification flow. Причины включают `deployment_disabled`, `missing_configuration`, `delivery_not_running`, `smtp_not_configured`, `invalid_smtp_configuration`, `provider_credentials_unavailable`, `component_unavailable`. Они не содержат секретов или сырых ошибок SQL.

`tokenProfiles` строится из реально собранного token factory и проверенного project deployment source, включая resources; очищенный внутренний service config не используется как источник metadata. GET/POST используют тот же source/owners, что project HTTP. При HTTP default-off прежний административный bridge остаётся с закрытыми capabilities и без readiness observation.

Успешный POST возвращает settings и observation до mutation (его `readiness.policyVersion` может отличаться от новой settings.version). Replay может вернуть историческую policy вместе с текущей preflight observation; они не считаются одним снимком. GET operation не строит новую readiness и не обещает текущее состояние. Дополнительное поле omitted у прежнего local/static response, request schema/права/статусы остаются прежними; Swagger обновлён.

## Порядок выполнения

`RuntimeAuthPolicy.ReadAuthPolicyView` получает current actor/ready target и policy snapshot существующим bounded directory протоколом; внутри catalog authority transaction читает только exact origin/key. Project read transaction и registry lease заканчиваются до вызова callback. Callback получает key/origin, а не actor impersonation или SQL pool. После него повторяются current actor/target authority и полный policy snapshot; изменение отбрасывает observation.

`ProjectHTTP.Assess` строит только непубликуемый inspection profile, выбирая потенциальные capabilities из доверенного source. При обычном `BuildProjectProfile` текущая SQL policy продолжает определять реальные routes. До/после inspection считываются версии трёх маленьких metadata rows; изменение во время проверки даёт конфликт. Final current key/policy guards сохраняются. Никакие session/token/mail operations не выполняются, новые process owners не создаются.

При POST inspection выполняется до `AdmitAuthPolicy`, чтобы не расходовать его3-секундное окно на crypto/config probes. Дальше прежняя transaction-owned admission/execution/receipt цепочка. Receipt replay проверяется раньше current policy/dependency guards и не теряет commit из-за недоступного метода. Новая запись сохраняет expected policy/project versions; использованные SMTP/provider versions проверяются под `FOR SHARE` до commit. Изменение credentials после observation —409 policy conflict, отсутствие row/verification/adapter —409 method not ready. При отключении метод не входит в selected dependency checks.

PolicyRuntime версии/verification facts не являются полями API запроса. Старые trusted static adapters не получают вымышленные version pins и сохраняют прежние tests/contracts. Существующие SQL stored-provider/presence predicates остаются дополнительной транзакционной гарантией. Перепроверка metadata не является повторной domain validation.

## Нагрузка и ограничения

Assessment выполняется только для административного чтения/изменения настроек, под существующими HTTP/project admission и deadlines. Он делает ограниченное число точечных catalog/SQL reads и factory checks; обычный login hot path не получает эти дополнительные запросы. Между SQL и probes нет nested UsePool/connection ожидания при одном runtime pool. Factory references inspection не публикуются/не кешируются как authority.

Readiness описывает локальную конфигурацию и живые shared owners на момент наблюдения. Она не является успешным внешним Google/Telegram login или SMTP send; Redis/worker/network могут отказать сразу после неё. Actual операции сохраняют fail-closed guards; policy enable не обещает вечной доступности и не отзывает автоматически старые sessions/JWT.

Unit/projection и actual SQL scenarios добавлены: выключенный SQL method при готовом deployment; native/exchange resources; noSMTP password, missing verification; no unauthorized probe; capability probe дольше3s до admission; replay после readiness loss; disabling broken method; stale provider version; revoked authority before disclosure. Main formatter/Swagger generation/diff, Luna task check/API/affected race/security и actual command/runtime/operator SQL PENDING. Полная two-project/MP5/MP7/MP8 и UI остаются отдельными gates.


Luna V1: API/race/security/lint/actualcommand+runtime+operatorSQL PASS (noSKIP), standcleanup иmanifest26подтверждены. Taskcheck упал тольконаустаревшемSwaggerresponsecount4. Обновленыcount5/ref/optionalassertion вконтрактномтесте; V2 taskcheck PENDING. Измененияproduction/schema/artifactsнепотребовались.


Итог V2: task check PASS, lint0. Manifest27 и generated Swagger JSON/YAML совпали после проверки и с main. V1 API/race/security/три actual SQL PASS остаются evidence незатронутых гарантий; V2 изменял только устаревшую schema assertion, добавив optional readiness check. Внешняя и полная cross-project/нагрузочная приёмка остаются открытыми.
