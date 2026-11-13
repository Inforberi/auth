# Security review — 10 ноября2026

Target: `1c4fc8cb`, много пользователей и несколько независимых проектов, общий backend и отдельные project DBs. Read-only source audit с приоритетом trust boundaries; новая executable проверка зависимостей/static analysis поручена Luna. Реальные env/данные/сервисы не читались и не атакованы. Предыдущая localMP7 приёмка не повторялась.

## Результат source review

Подтверждённых эксплуатируемых дефектов в просмотренных путях не найдено. Это не доказательство абсолютной безопасности и не построчный аудит всего репозитория. Production-код не менялся: выдумывать исправления без конкретного дефекта нельзя.

| Область | Просмотренные владельцы | Вывод и граница |
| --- | --- | --- |
| SQL injections | account list/read, project list, provisioning database/owner/password/schema | Значения параметризованы; переменные SQL placeholder numbers формируются из lengths, не user fragments. DDL identifiers через pgx.Identifier.Sanitize; SCRAM verifier содержит фиксированный синтаксис/base64, не plaintext password. Static schema/grants snippets не берутся из HTTP |
| Командные injections/path input | production `internal/pkg/cmd` поиск os/exec/syscall.Exec, configuration file reads | Shell execution в production Go paths не найден; CA/config paths — operational configuration, не пользовательский endpoint. Backup/restore scripts и реальный host отдельно не подвергались полноценному security review |
| SSRF/внешние протоколы | integrations/oidc/http.go, telegram/bot/request.go, settings/smtp/service/smtp_seed.go, infra/mailer/context.go | OIDC exact HTTPS endpoints, redirect forbidden; Telegram fixed API hostname и bounded response; SMTP exact host:port allowlist и production TLS policy. DNS/egress остаются operational trust boundaries: в allowlist должны быть только контролируемые destinations |
| SMTP/HTML injection | infra/mailer/context.go и message.go, settings/domain/smtp.go, account email/invitation mail, password/templates | Subject CR/LF rejected; SMTP settings From/Host/Domain validated; reset использует html/template, ссылки/адреса в письмах html.EscapeString. Raw MIME helper сам не security boundary: validated settings и SMTP envelope checks обязательны |
| Reset/защитное восстановление | password/repository/postgres/reset_password.go, forgot_password.go, account/repository/postgres/protected_recovery.go | Single-use digest+expiry/auth_version/current status в transaction; protected recovery дополнительно связывает old verified email/hash/state. Public invalid-reset response общий. Полное timing side-channel measurement не выполнялось |
| Права/fresh proof | access/repository/postgres/management.go, admin/administrators/repository/postgres/authorize.go, account/status.go | SQL authority, locks, fresh password/MFA, current versions и revoke сохраняются. До SQL успешный session middleware не заменяет permission check |
| MFA recovery function | migrations/auth `auth.decide_mfa_recovery`, recovery grants | SECURITY DEFINER имеет фиксированный search_path, schema-qualified tables; PUBLIC execute отозван, recovery operator выделен. Правильность реальных production grants требует проверки deployment |
| Сессии/JWT/CSRF/project isolation | предыдущие middleware source review + local MP7 | Принятые локальные негативные сценарии переиспользуются; не заявляются заново исполненными. JWT local сохраняет окно отзыва доexpiry, strict — online authority |

## Остаточные release-риски

- Backend допускает plaintext за доверенным HTTPS ingress, а project/onboarding требуют реального backend TLS. Доступ к plaintext listener, доверенные proxy, DNS и firewall проверяются в реальном deployment. X-Forwarded-Proto не делает соединение шифрованным.
- SMTP host allowlist не является IP/egress firewall. Не добавлять домены, DNS которых контролируется недоверенным project admin, или произвольные внутренние targets. Защита от DNS/network compromise не доказывается этой проверкой.
- Нет результатов pentest/fuzz/динамических атак и MP8 exhaustion/load/GC в этом аудите; нет реальных provider/SMTP/browser/fleet acceptance. Новые UI HTML templates и upload ещё не реализованы и этим review не проверены.
- Безопасность зависит от сохранности master/signing keys, минимальных DB grants, TLS, secrets rotation и обновления зависимостей; корректные middleware не защищают от компрометации хоста/владельца инфраструктуры.

## Проверки

Luna получила immutable target1c4fc8cb: существующий Taskfile check:security (govulncheck v1.1.4), gosec через существующую lint-конфигурацию v2.14.0 при поддерживаемой команде. Ожидаемый receipt `/private/tmp/auth-security-20261110-summary.json`. До фактического результата НЕ PASS. Никаких повторных MP7/SQL/race без нового code delta. Main source review не является executable check.

Исполняемый gate заблокирован: Luna сообщила, что закреплённые scanner/linter не могут получить module metadata в offline окружении; установленный более старый lint не подменялся. Передача Luna задания с require_escalated network была отклонена automatic approval review: возможна отправка внешнему vulnerability/module service приватных module paths/metadata, отдельного согласия на такой payload нет. Действие не повторялось и не обходилось. Для продолжения требуется разрешение на public vulnerability/module endpoints с module paths/versions; исходники/секреты/реальные данные не передаются. До разрешения dependency/static scan — NOT RUN, production readiness не подтверждена.

## Продолжение — 12 ноября 2026

Пользователь поручил первый из трёх оставленных блоков и отдельно разрешил передачу названий/версий модулей официальным vulnerability/module endpoints, включая приватные пути при попадании в запрос. Передача исходников, секретов и рабочих данных не требуется и не разрешена. Исторический отказ выше сохраняется; наличие согласия само по себе ещё не является успешным выполнением проверки.

Luna получила актуальный snapshot `/private/tmp/auth-security-20261112-tuYNdL/snapshot.tar.gz`, SHA256 `1b81bcf394a0a5e2787368332a3748e86515854b3d6beef3818e0fee99c79b74`; `manifest.json` рядом. Base `1c4fc8cb`, текущий delta — sandbox и документация, без изменения production Go/dependencies. Проверки: `govulncheck@v1.1.4` с актуальной базой и только `gosec` через `golangci-lint/v2@v2.14.0` с существующими security-настройками. Go в проекте1.27.3; новые зависимости/обновления автоматически не разрешались.

Ранее принятые функциональные session/access/MFA/isolation/MP7 проверки не повторяются. Полные tests/lint/race/build/SQL/Redis/API/нагрузка и Docker в этот запуск не входят. Static package loading не считается исполнением функциональных тестов. Нужны реальные exit statuses, версии сканеров, база уязвимостей, scope/exclusions и findings с достижимостью. Ожидаемый receipt `/private/tmp/auth-security-20261112-summary.json`; до результата блок остаётся открытым. Main проверил команды/подготовил snapshot, сканеры самостоятельно не запускал.

### Фактический результат Luna

Receipt `/private/tmp/auth-security-20261112-summary.json`; Go1.27.3 darwin/arm64, govulncheck1.1.4, официальная база обновлена2026-11-11T02:51:11Z. Source/manifest после скана совпали, go.mod/go.sum и конфигурация линтера совпали с main.

- **gosec PASS:** golangci-lint2.14.0 `--enable-only=gosec --tests=false` по production patterns cmd/internal/pkg/docs/migrations,0 issues, exit0. Существующие security settings/exclusions сохранены; новых suppressions нет. Предупреждение gofumpt deprecation не является security finding.
- **govulncheck FAIL:** GO-2026-6859, стандартная библиотека net/http в Go1.27.3, symbol-level reachability,58 example traces. Сообщение сканера: HTTP/1 server crash due to MaxBytesReader header race; исправление — Go1.27.4. Прямой production `http.MaxBytesReader` подтверждён в `internal/transport/http/httpx/decode.go` и других HTTP owners. Это приоритетная достижимая находка, не подтверждённая динамическая эксплуатация. Default scanner exit3 (обёртка go run —1).
- **Module-only:** GO-2026-5932 в golang.org/x/crypto0.56.0 относится к openpgp. Production imports openpgp не найдены; package/symbol reachability нет. Текущая база также перечисляет фиксирующую pseudo-version, но это не основание вслепую менять используемый Argon2-модуль из-за неимпортируемого пакета. Находка сохраняется в отчёте, не скрывается ignore-правилом.

Для определения ID module-only finding Luna дополнительно выполнила диагностический `govulncheck -show verbose`, без повторения функциональных тестов. Логи — `govulncheck.log`, `govulncheck-verbose.log`, `gosec.log` в snapshot-каталоге. Анализ выполнен на darwin/arm64; отдельного Linux скана/эксплуатационной приёмки не было. Это не общий pentest.

### Исправление: согласованное обновление Go

Пользователь явно разрешил Go1.27.4. Изменены только закреплённые версии в `go.mod`, `deploy/docker/Dockerfile.dev`, `deploy/docker/Dockerfile.prod`; x/crypto/go.sum и HTTP body limits не менялись. Исправление ещё ожидает целевой проверки Luna: повторный vulnerability scan на1.27.4, существующие unit HTTP decode/server tests и одна Linux-сборка Auth для совместимости. Чистый gosec и локальные MP7/session/MFA/SQL/Redis/нагрузочные проверки повторять не требуется. До подтверждения исправления security gate открыт.

### Подтверждение исправления — принято 13 ноября 2026

Luna завершила affected checks snapshot SHA256 `60e126964edb76b2a27f6fdba3753018317452fa93e0758fb6dd7fd336db2c0f`. Receipt `/private/tmp/auth-security-go1274-summary.json`. Main сверил три изменённых исходных файла с manifest и фактические логи, не повторяя команды проверки.

| Проверка | Результат |
| --- | --- |
| govulncheck1.1.4, фактический Go1.27.4, база2026-11-11T02:51:11Z | Exit0:0 достижимых уязвимостей,0 в импортируемых пакетах; GO-2026-6859 больше не обнаруживается |
| Module-only GO-2026-5932 | Сохраняется как неприменимая к импортируемому приложением коду запись openpgp; не скрыта suppression и не требует неподтверждённого апдейта x/crypto для закрытия этой достижимой HTTP-проблемы |
| Целевые httpx/server HTTP tests | Оба пакета PASS, exit0 |
| Единственная Linux/arm64 Auth compile | PASS, exit0; binary metadata Go1.27.4/CGO0 |
| gosec | Переиспользован предыдущий PASS0issues: production Go source и config не менялись |
| Docker registry/tag/build | Не подтверждены: manifest-запрос не ответил за~2min, свой процесс остановлен; image pull/build/запуск не выполнялись |

**Первый блок старого плана закрыт в согласованном объёме scan/triage/fix.** Это не pentest и не закрытие эксплуатационной приёмки. Проверки других функций, SQL/Redis/API/MP7/race/нагрузки не повторялись. Go.sum неизменен, новых dependencies/suppressions нет, чужие/сохранённые контейнеры не менялись.

Следующий блок — backup/restore, upgrade, grants и TLS/ingress. В него переносится проверка доступности и сборки Docker base tag. Изменение исходной версии не обновляет уже работающий процесс/образ: для использования исправления нужна реальная пересборка наGo1.27.4; production deploy не выполнялся и отдельно не разрешён.
