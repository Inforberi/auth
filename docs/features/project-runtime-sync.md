# Периодическая сверка resident-пулов

MP4,24 октября2026. Отдельный чат Luna проверил task check/lint0, host race и actual command/assembly SQL; новый sync scenario PASS без SKIP. [Evidence](../planning/history.md#результат-mp4-resident-sync--24-октября-2026). Это проверка catalog metadata между экземплярами, не кеш authority и не новая гарантия времени отзыва пользовательских сессий.

## Механизм

Каждый включённый project runtime запускает один sync-worker на Registry. Он берёт только текущие resident/opening entries и сверяет их с общей platform DB. Уведомления не нужны: изменение, сделанное другой replica или прямым provisioning SQL, видно при следующем успешном цикле.

Нет обхода всех зарегистрированных проектов, отдельного worker на проект, нового broker/Redis stream/таблицы событий или watermark map. Reader работает существующим SELECT-only private catalog pool. Redis по-прежнему обязателен для остальных Auth-гарантий; этот механизм не включает SQL-only Auth fallback.

`PLATFORM_PROJECT_SYNC_INTERVAL` — default5s, допустимо1s..1m. `PLATFORM_PROJECT_SYNC_TIMEOUT` — default2s, допустимо(0,3s]. Один цикл не перекрывается со следующим. При пустом registry SQL-запросов нет. До128 snapshots на запрос, большие resident sets разбиваются на последовательные партии в одном общем timeout. При default MaxRuntimes8 — один запрос за цикл, около0.2 metadata QPS на активный экземпляр, без учёта cold-open/readiness. Это арифметика настройки, не measured capacity.

## Что сверяется

Для каждой записи — realm/project/reservation/target/OIDs/schema/version/generation, secrets-created flag, наличие credentials row, expected database name, initialized realm и enabled/ready состояние. Общий SQL predicate переиспользуется cold credential loader, чтобы правила не расходились. Проверка прав private reader материализуется один раз на batch; ciphertext/key material не выбираются и не расшифровываются.

Запросы ограничены входными UUID и существующими ключами каталога, не hot user data. Порядок и полнота результата проверяются. Несовпадение retiring только исходный entry. Если entry успели удалить и заново открыть с тем же key, ответ старой проверки его не затронет — сравнивается конкретный объект entry, не только ключ.

SQL/protocol/permission error, timeout или неполный batch result не продлевают reuse: весь исходный снимок цикла retiring. Следующая попытка открытия проходит обычный current cold loader; чужой/default DB и stale credential fallback отсутствуют. Успешная прежняя проверка не используется как разрешение продолжать reuse бесконечно при outage.

Active lease не закрывается. После возврата callback pool освобождается; idle pool закрывается сразу после retiring, closing pool сохраняется в connection budget. Opening устаревшего entry не публикуется. Локальный lifecycle Observe остаётся быстрым путём на том экземпляре, который принял изменение; sync восстанавливает состояние остальных.

Период и длительность запроса определяют задержку resource invalidation при доступном каталоге и работающем scheduler. Они **не** разрешают новые мутации в этом окне: current SQL admission/ordinary session authority и actual transaction profile остаются обязательными. После suspend cached Use сам по себе не является пользовательским правом входа. Политика already-committed admission до3s не меняется.

## Сборка и shutdown

Worker подключён [опциональной platform assembly](project-runtime-lifecycle.md) и отсутствует при PLATFORM_PROJECT_RUNTIME_ENABLED=false. Registry.Close отменяет текущую probe и ждёт worker до закрытия private catalog dependencies. Повторный запуск sync-worker/запуск после Close отклоняется. StateReader должен соблюдать context, действующий pgx reader имеет дополнительный SQL-call timeout.

Secret password rotation/смена master key не реализованы этим механизмом. Producer таких изменений обязан менять catalog version/generation и соблюдать отдельный rotation/restore protocol. Poll не сканирует фактическую DDL проектных БД и не проверяет заново ciphertext: physical/runtime authority checks остаются на своих границах.

## Проверки и границы

Целевые unit tests прошли в основном чате: empty/no SQL, mismatch/error/incomplete evidence, batches128+1/partial failure, active lease, stale response против reopened entry и worker cancellation/join. Подготовлен actual SQL test двух независимых registry в одном процессе: mixed valid/stale binding batch, изменение версии/suspend без Observe, сохранение active PID и закрытие idle PID, resume/new key, утрата reader grants и recovery. Это не два отдельных API deployment и не fleet/network partition приёмка.

Новый SQL test, финальный lint/race и command/assembly regression прошли отдельным чатом Luna на неизменяемом снимке. Следующие задачи: общий connection/resource/rate бюджет по instances/workers, полная Auth feature assembly/scheduler и оставшиеся HTTP/concurrency/restore gates. Capacity/длительные memory/GC измерения — MP8. Два registry в одном процессе не являются fleet deployment/partition приёмкой.
