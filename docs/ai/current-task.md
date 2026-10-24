# Текущий шаг

Обновлено25 октября2026. [Карта](index.md) · [статусы](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui) · [gates](../operations/acceptance-summary.md#открытые-ограничения-приёмки). Git/staging и стенд проверять по факту.

## Завершённый блок — MP3.7a closed managed configuration

[Контракт](../features/project-managed-readiness.md). CLI -managed требует schema/secrets/password и несовместим с-onboarding. Все public Auth/registration/token flows выключены, нет обязательного local admin/SMTP. Typed managed SQL probe/activation сохраняют current preparation/binding/journal/fresh authentication/cleanup; setup admission/ready/binding не публикуются. Legacy first-admin профиль сохранён; новых schema/grants/ENV/dependencies нет.

Luna: task check/tests/lint/affected race/security и actual PostgreSQL18.6 TestPrepareCommandSQL PASS; все managed/legacy cases без SKIP/NOT RUN. Manifest10 изменённых source совпал; cleanup выполнен. Перед коммитом source совпал с `/private/tmp/auth-managed-readiness-manifest.sha256`, snapshot `/private/tmp/auth-managed-readiness.ow59nzkt`. [Evidence](../planning/history.md#результат-mp37a-managed-configuration--25-октября-2026). Это не весь MP3.7/MP4/public-ready/fleet.

## Следующий шаг

Выбранные методы/проектные settings и их реальные dependencies, production loader и корректная publish-ready связка по MP3.8/MP4. Один SQL probe не разрешает normal Auth traffic. Сначала уточнить минимальный конкретный следующий подэтап по существующим settings/bridge контрактам, не добавлять универсальный механизм или вручную выставлять ready. Владелец управляет через platform session, не обязательную копию identity. Для выбранных email-сценариев нужна готовая доставка; для проекта без email-функций SMTP не требовать.

Все tests/стенд — Luna01a16eab-c777-78a0-a815-47b45ff0860d. Здесь проектирование/код/formatter/snapshot; не ждать и не дублировать проверки. Коммит только по запросу. Перед UI заранее предупредить пользователя и отдельно согласовать переход, стек, макеты и экраны; UI сейчас не начинать.

## Нельзя потерять

- Commit admission до3s — окончательная авторизация конкретной команды: revoke/suspend запрещает новые admissions, уже принятая может завершиться. Обычный session revoke не меняется. Poll — resource invalidation, не кеш прав/разрешение stale mutation. Unknown commit не означает rollback; read/reconcile только своей операции при current read authority.
- Platform owner управляет проектами без копии identity/обязательного local super_admin/raw setup-token handoff; owner-managed readiness ещё не готова. [ADR005](../adr/005-independent-projects.md#3-одна-сессия-оператора-без-пользовательского-sso). Standalone setup сохраняется.
- UI только после отдельного согласования материалов/стека/макетов: MP1–MP6 → MP6R security/refactor → MP7 → MP8 → UI. Optional MFA и email/Telegram второй фактор пока план; current platform guards остаются. Owner-only deletion ownership/backup ещё согласовать.
- PostgreSQL + обязательный Redis, без SQL-only/fallback. Новые зависимости только с разрешения. Рабочие БД/ENV/secrets/staging сохранять; старым БД нужен controlled upgrade, init их не обновляет. Go1.27.3 согласован; image build ранее NOT RUN из-за Docker disk — доступность проверять заново, чужое не чистить.
- Source checksum не полный DDL scanner/доверие произвольному серверу. Restore/JWT gates — [приёмка](../operations/acceptance-summary.md). Capacity/GC только по измерениям; local SQL/race не fleet sign-off.
- Следовать [переносимому процессу](development-workflow.md): точечная навигация, независимая параллельная работа, длительные проверки в отдельный чат «Проверки Auth — Luna» (01a16eab-c777-78a0-a815-47b45ff0860d) на точном снимке. Здесь не ждать и не дублировать успешные несвязанные прогоны.
