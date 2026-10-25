# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Завершённый блок — MP4.1b project password/session

[Контракт](../features/project-password-runtime.md). Registry.UsePool удерживает логический entry lease/MaxAcquiring slot без physical connection во время hash. ProjectPassword.New/Login используют data key/scoped limiter MP4.1a, borrowed process hasher/Redis/reader и existing password/session/settings services на том же pool. Early policy и final SQL active/auth_version/verification/MFA guards сохранены; current key/profile до login и перед выдачей raw result. Session config validator централизован без изменения правил. Новых pools/workers/routes/ENV seed/capabilities нет.

Luna: task check/lint0, affected race и полный actual TestPrepareCommandSQL PASS без SKIP, включая восемь password/session cases и прежние loader/runtime/downstream/parent replay. Snapshot `/private/tmp/auth-project-password.xss82yb3`, base672162d, manifest9 `/private/tmp/auth-project-password-manifest.sha256`, metadata `/private/tmp/auth-project-password-snapshot.json` совпали до/после и перед коммитом. Own PostgreSQL/Redis удалены, DB15 пуста. [Evidence](../planning/history.md#результат-mp41b-project-password-session--25-октября-2026). Пользователь разрешил commit; полного MP4/HTTP/readiness/fleet sign-off это не даёт.

## Следующий шаг

Полная project MFA challenge/session assembly, затем выбранные SMTP/provider/token dependencies, bounded workers и отдельные readiness/MP5 host routing guards. Этот первый Login не реализует MFA challenge: enrolled/role-required MFA fail-closed. Current platform availableMethods остаются false; normal traffic/UI не опубликованы.

UsePool callback держит MaxAcquiring slot до выхода; нельзя вкладывать registry acquisitions или сохранять pool/services/async работу. Pool закрывает owner после drain. TTL/capacity — trusted constructor inputs, не новый UI settings API. Old object pinned epoch не переключает проект: stale catalog даёт отказ, пересборка остаётся manager. Capacity/GC/fleet — только по фактическим измерениям.

## Процесс и ограничения

- По последнему согласованию: основной исполнитель Sol medium; разведка незнакомого участка — локальному субагенту Luna medium в этом чате, краткая карта файлов/символов/связей. Main затем читает изменяемый код и критичные контракты, не повторяет общий обзор. Для мелких правок отдельный поиск не нужен. Отдельный чат Luna — только тестирование/проверки, разведку туда больше не отправлять.
- Verification — «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; worktree6377/auth stale. Main не ждёт/не дублирует successful наборы. [Процесс](development-workflow.md).
- Committed admin admission до3s — отдельный контракт. Final current check не обещает distributed мгновенную отмену in-flight commit; при stale result raw token не выдаётся, массовый revoke не добавлен.
- PostgreSQL + обязательный Redis без fallback. Новые зависимости только с разрешения; здесь нет новых. Реальные ENV/БД/secrets/staging сохранять. Go1.27.3 согласован. Owner без копии identity в проектах, standalone setup сохраняется.
- До UI: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → отдельно согласованный UI. Перед UI заранее предупредить и согласовать стек/макеты/экраны. Frontend сейчас не начинать. Commit только по запросу.
