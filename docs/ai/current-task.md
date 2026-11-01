# Текущий шаг

Обновлено 1 ноября 2026. [Карта](index.md) · [Telegram MFA](../features/telegram-mfa.md#private-подготовка-канала--a63m6d2a-pass-luna) · [Implementation](../planning/implementation.md).

## Завершён A6.3m.6d.2a — Luna V4 PASS

Private Request/Receive/Confirm: исходная browser/password/требуемый factor proof, короткий SQL intent, trusted bot candidate, encrypted retry payload без reset guesses/TTL, current bot/settings version, same-source code confirmation/token rotation без login/MFA/proof elevation. Session ID FK+index для cleanup, token hash отдельным snapshot; внешняя rotation/logout/version делает intent stale. Source000001/table/metadata/checks/indexes/audit, bounded retention/deletion; shared password-factor guard перенесён без изменения условий, CSPRNG8-digit generator внедряется через token port.

Luna: V2 Go tests/architecture/affected race и все4 actual schema roots с race/count1 PASS без SKIP; V4 final lint0, formatting-only V2→V4, manifest29/29 и cleanup DB/role/schema/TLS/cache подтверждены. Снимок `/private/tmp/auth-telegram-channel-v4.re2xxzjs`, base004ca08; evidence turn `01a19722-ff16-72e2-b5be-e930066ea5de`, cursor `944a6e9d-49fe-49f7-8ff5-48acb6c615a1:71`. Full task check/SQL после style-only правок не повторялись, успешные части сохранены. [History/FAIL и исправления](../planning/history.md).

Main сверил29/29 до обновления только Markdown, executable checks не запускал; pinned formatter — подготовка изменения. Перед следующим снимком применять штатный formatter Taskfile: одного gofmt недостаточно для gofumpt/gci. Пользователь разрешил коммит после PASS. Новых dependencies/ENV/routes/workers/очередей нет; real DB/secrets не менялись.

## Далее — .6d.2b

Guarded Bot API settings/secret storage/rotation: отдельные project crypto purposes для bot token/webhook secret, verified bot ID, permission/fresh-proof/version/audit guards, masked reads. Config verification без сетевого вызова под SQL locks; atomic settings.version change инвалидирует pending proofs даже при прежнем bot ID. Сейчас telegram_bot_id default NULL и SQL authority fail-closed; private preparation не открывает публичный flow.

Затем .6d.3/.4: factor policy/lifecycle и method-aware login/delivery/protected routes/readiness/actual two-project fault/recovery acceptance. Schema нужна binary даже при disabled Telegram (retention); upgrade MP6 отдельно. Внешние Telegram/ingress/capacity/GC/UI — отдельные gates. UI не начинать без предупреждения и отдельного согласования.

Локальный исследователь Luna gpt-6-luna (Jason,01a196ae-b5d3-7313-acb1-b14dad3aa9b6) дал bounded source/cleanup map. Проверки — только чат «Проверки Auth — Luna»,01a16eab-c777-78a0-a815-47b45ff0860d, host local.
