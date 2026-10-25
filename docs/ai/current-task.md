# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging проверять по факту.

## Текущий блок — MP4.1c project MFA

[Контракт/решение до кода](../features/project-mfa-runtime.md). Добавлен optional MFA Login factory на project data key/scoped Redis/TOTP и existing repo. ProjectPassword.Login использует sessionservice.NewLogin: enrolled/required-role дают challenge без session. CompleteMFA делегирует TOTP/recovery-code Complete; Start/ConfirmMFAEnrollment — existing required enrollment. Current catalog/profile до/после, UsePool lease и request-local services, без новых pools/workers/HTTP/ENV seed/dependencies.

После подтверждения enrollment existing invalidateFactors повышает auth_version и отзывает прошлые sessions/challenges; нужен повторный пароль и новый challenge, не автоматическая сессия. Default MFA.Enabled=false сохраняет прежний fail-closed профиль. Recovery codes не зависят от RecoveryEnabled; этот флаг loss-all-factors recovery здесь отклоняется как неподготовленный. SMTP/loss-all-factors/management delivery не собираются.

Unit config/disabled guards и actual SQL+Redis MFA case добавлены. Luna V1 task check/lint0 и affected race PASS; обнаруженный typed-nil wiring исправлен. V2 full TestPrepareCommandSQL PASS без SKIP, включая disabled/enrolled/role-required guards и enabled project MFA drill; targeted lint app/auth+cmd PASS (0 issues). Cleanup55006 не повторился. Manifest7 совпал до/после и main с текущим source; snapshot `/private/tmp/auth-project-mfa-v2.__kgd_jl`, base186adf5, manifest `/private/tmp/auth-project-mfa-v2-manifest.sha256`, metadata `/private/tmp/auth-project-mfa-v2-snapshot.json`. Own PostgreSQL/Redis/TLS/binaries удалены, DB15 пуста. Пользователь запросил коммит проверенного блока; перед фиксацией main повторно сверил manifest7, дополнительных source изменений нет.

## Следующий шаг

После фиксации проверенного блока продолжить selected SMTP/provider/token assembly, bounded workers и отдельные readiness/MP5 host routing guards. Current platform availableMethods остаются false; этого internal MFA wiring недостаточно для public-ready/fleet/browser acceptance. UI не начинать.

## Процесс и ограничения

- Единый локальный исследователь: Helmholtz, модель gpt-6-luna, reasoning medium, ID `01a17292-5405-7341-bae9-f5884a755889`. Создан по просьбе пользователя25 октября; открыт для reuse в связанных задачах. Не закрывать после каждого ответа. Предыдущий Dewey закрыт. Bohr закрыт по запросу пользователя: ID01a16ea2-a061-76e0-95ec-7693ce24a73a найден по exact role-outcome заданию в истории родительского чата.

- Локальный субагент Dewey, модель Luna medium, выполнил только targeted read-only MFA/API/fixture/crypto/Redis карту; main по ней прочитал изменяемые конструкторы и критичные primary/session/enrollment контракты. Разведку в отдельный verification chat не отправлять; для мелких правок агент не нужен.
- Все tests/fixtures — «Проверки Auth — Luna»01a16eab-c777-78a0-a815-47b45ff0860d на exact snapshot/cwd; worktree6377/auth stale. Здесь не ждать/не дублировать successful наборы; [процесс](development-workflow.md).
- UsePool callback не сохраняет pool/service/async работу и не вкладывает registry acquisitions; MaxAcquiring slot до выхода. Hash не удерживает SQL connection. Current-key guard не обещает распределённую мгновенную отмену committed in-flight factor/session; при stale result secret/raw token не выдаётся.
- PostgreSQL + обязательный Redis без fallback. Новые зависимости только с разрешения; здесь нет новых. TOTP test API existing pquerna/otp v1.5.0 сверена Context7 и installed source. Реальные ENV/БД/secrets/staging сохранять, Go1.27.3 согласован.
- До UI: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → отдельно согласованный UI. Перед UI предупредить/согласовать стек/макеты/экраны. Capacity/GC/fleet только по измерениям. Коммит только по запросу.
