# Текущий шаг

Обновлено 25 октября 2026. [Карта](index.md) · [план](../planning/implementation.md#текущий-выпуск-auth-роли-и-ui). Git/staging проверять по факту.

## Текущий блок — MP5.1b project HTTP routes

[Контракт](../features/project-http-routes.md). NewProjectHTTP программно соединяет existing exact TLS boundary, общий base middleware/admission и bounded resident dispatcher с selected-feature ProjectProfile. Явные browser/callback/native/service/session_no_refresh/JWKS bindings, без admin/setup/management fallback. Existing DTO/API сохранены, узкие public password/verification handlers без копии логики.

Кеш сборок не кеширует authority: warm request проверяет full SQL policy/current catalog, boundary key переиспользуется без второго originlookup. Stale profile404/remove/next-request rebuild, dependency503, bounded residents/builds/age и no wait queue. Close прекращает admission/drains, shared pools/clients остаются у прежних owners. SMTP-related routes проверяют живой delivery runner. Production router/ENV/phase-ready автоматически не включены; UI не начинается.

Main formatter exit0 (existing gofumpt deprecation warning), diff/source review завершён. Read-only Helmholtz нашёл только unbounded fixture cleanup contexts — исправлены deadlines; финальные interface/cache/transport и HTTP key/policy guard review без конкретных проблем. Tests не запускал. Luna V1: API/security/actual full SQL PASS, manifest23 совпал. Task check и router race FAIL: promoted public methods при nil/zero PasswordHandler вызывали panic во время регистрации маршрутов; lint QF1008 избыточный selector. Main исправил guard на наличие public handler и selector. V2 task check +router race PASS, manifest24 совпал с main; повтор SQL/API/security не нужен: их гарантии не менялись. Новый actual TLS child проверяет login/cookie/Origin/no-refresh SQL session/block/policy rebuild/suspend.

Snapshot `/private/tmp/auth-project-http-routes-v1.r_a3wvbg`, manifest `/private/tmp/auth-project-http-routes-v1.r_a3wvbg-manifest.sha256`, metadata `/private/tmp/auth-project-http-routes-v1.r_a3wvbg-snapshot.json`, base3a18a3c. Manifest исходников сверять до/после и с main. Успех старого MP5.1a не подтверждает этот diff.

## Следующий шаг

V2 PASS принят, пользователь разрешил коммит. Факт коммита проверять Git. Далее явная integration с основным server/deployment source/lifecycle и полная MP5 two-project cookies/CORS/CSRF/callback/redirect/token matrix. Account/session/MFA management mounting, settings capabilities/phase-ready, managed rotation/MFA recovery/fleet/MP6R/MP7/MP8 отдельно. UI только после предупреждения и отдельного согласования.

## Процесс и ограничения

- Researcher Helmholtz gpt-6-luna medium01a17292-5405-7341-bae9-f5884a755889, read-only, сохранять для reuse. Bohr закрыт.
- Все исполняемые проверки — отдельный Luna01a16eab-c777-78a0-a815-47b45ff0860d, host local, exact snapshot/cwd. Default6377/auth stale. Main не дублирует/не ждёт полный прогон. [Процесс](development-workflow.md).
- Actual SQL recipe: собственный Linux ARM64 postgres18.6 container, source readonly /src; admin socket trust, TCP127 SCRAM/wrong-password deny, TLS+SAN127, Redis8.2 shared networkDB15. SCRAM_HOST=127.0.0.1/TLS_CA/ROOT/src/Redis127 env обязательны. Не macHost/randomport/trustTCP.
- Source/loader обязан соблюдать deadlines; отсутствие внешних provider secrets не закрывает external acceptance. Context deadline Close не разрешает закрывать shared resource до окончания активной операции. Новых deps/schema/ENV/workers нет; реальные secrets/БД/staging сохранять.
- HEAD3a18a3c проверен/закоммичен. Вердикт текущих tests PASS, внешние provider/SMTP/two-project full matrix/fleet/GC/RPS/UI gates открыты.

Текущий V2 snapshot `/private/tmp/auth-project-http-routes-v2.aja58y44`, manifest `/private/tmp/auth-project-http-routes-v2.aja58y44-manifest.sha256`, metadata `/private/tmp/auth-project-http-routes-v2.aja58y44-snapshot.json`. Проверки привязаны к V2; V1 snapshot в предыдущем абзаце — сохранённое evidence. Cursor Luna V1:001f5739-f635-4e82-85da-0f9c06b859c7:80. Commit разрешён пользователем только после успешного повтора.
