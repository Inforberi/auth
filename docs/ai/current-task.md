# Текущий шаг

4 ноября 2026. Полный корректирующий [план слоёв](../planning/layer-boundaries-audit.md#приёмка-v2) выполнен и принят Luna V2. Snapshot `/private/tmp/auth-layer-boundaries-v2-7da4k02g`, receipt `/private/tmp/auth-layer-boundaries-v2-summary.json`: targeted/security tests, lint0, race и 11 actual SQL/HTTP roots PASS без SQL SKIP; Redis webhook PASS. Main сверил manifest drift0/extra0 и17 exit evidence0. После проверки изменена только документация результатов.

Deployment source — app/projects/deployment; factory — app/projects/profile (17 production/11 tests); runtime readiness/public tests — auth/project/profile; Swagger — transport/http/projects/tests. Host routing, admin MFA adapter, SQL versions, webhook/password HTTP и CLI получили владельцев. Чистые правила вынесены, security transactions/replay/audit сохранены. Подробности и решения по оставленным atomic operations — в плане, security source review — в operations/middleware-security-review.md.

Следующий шаг — оставшиеся MP7/MP8 release gates, сверить implementation/acceptance-summary перед выбором следующего блока. UI не начинать без предварительного согласования. TLS topology реального ingress, pentest/scan/load не доказаны этим affected-only прогоном. Commit разрешён пользователем для принятого блока.

Проверки только отдельный чат Luna 01a16eab-c777-78a0-a815-47b45ff0860d. Retained R5 `/private/tmp/auth-r5-retained-fixture.json`, SQL LinuxARM64/Unix socket; не менять retained роли/realENV/чужие Docker и не повторять hostTCP SCRAM несовместимость. При новом code delta нужен новый immutable snapshot; успешные незатронутые gates не повторять.
