# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Завершённый блок — MP2.7 project Auth policy

[Контракт](../features/platform-auth-settings.md). GET/POST project settings и GET own operation: current SettingsManage/fresh-auth, exact project/policy versions, committed admission до3s, atomic policy/receipt с platform actor без копии identity. Shared local SQL rules/DTO/error mapping; standalone last-admin/audit сохранены. Initial SQL/grants/runtime guards изменены, рабочие БД/ENV не менялись; существующим БД нужен controlled upgrade.

Luna V1–V5: task check/affected race/API/security/operator SQL+HTTPS/runtime assembly/local settings/provider/token/public-policy SQL PASS. Финальный V5 full TestPrepareCommandSQL PASS без SKIP, включая unknowncommit/concurrency/onboarding/managed; targeted lint PASS (0 issues). Manifest68 совпал до/после и перед коммитом. Snapshot `/private/tmp/auth-platform-policy-v5.lz1ax5z7`, base816458c, manifest `/private/tmp/auth-platform-policy-v5-manifest.sha256`, metadata/deleted `/private/tmp/auth-platform-policy-v5-snapshot.json`. [Evidence](../planning/history.md#результат-mp27-project-auth-policy--25-октября-2026). Owned fixtures удалены. Это локальная приёмка блока, не весь MP2.7/MP3.8/MP4/public-ready/fleet.

## Следующий шаг

MP3.8/MP4: project settings/dependencies, production loader, actual delivery/provider/token assembly и publish-ready связка. Production capabilities нынешнего bridge пусты: SQL registry не является полной Auth assembly. Можно читать/сохранять закрытую policy и dormant flags; включение неподготовленных методов/issuance отклоняется. Для project provider нет ENV fallback, выбранным email-функциям нужны actual delivery и stored SMTP. Existing sessions/JWT policy автоматически не отзывает. Outcome — historical receipt при current authority/original binding и online проектной БД.

Перед UI заранее предупредить пользователя, отдельно согласовать переход/стек/макеты/экраны. Frontend сейчас не начинать. Commit только по запросу; пользователь разрешил текущий при successful Luna checks — условие выполнено.

## Нельзя потерять

- Committed admission до3s — окончательная авторизация точной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Unknown commit не означает rollback; повтор immutable operation или GET своей операции.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup остаётся прежним.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения; здесь не добавлены. Рабочие БД/ENV/secrets/staging сохранять. Go1.27.3 согласован.
- До UI: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → отдельно согласованный UI. Capacity/GC/fleet только по измерениям. Owner-only deletion ownership/backup ещё согласовать; optional MFA/email/Telegram второй фактор — план, нынешние guards сохраняются.
- Все executable checks и isolated fixtures в чате «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd. Её worktree6377/auth — другой stale проект. Здесь не ждать и не дублировать успешные наборы; [процесс](development-workflow.md).
