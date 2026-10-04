#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$project_root"
for script in deploy/scripts/*.sh; do bash -n "$script"; done
project="auth-check-$(date +%s)-$$"
compose() { APP_ENV_FILE=.env.example docker compose --project-directory "$project_root" --env-file .env.example -p "$project" -f deploy/compose.base.yml -f deploy/compose.check.yml "$@"; }
# Cleanup targets only the unique project created by this script, never user data.
trap 'compose down --volumes --remove-orphans' EXIT
compose up -d --wait postgres redis mailpit
compose run --rm migrate up
if [[ "${AUTH_SMOKE_ONLY:-false}" != true ]]; then
  compose run --rm --no-deps migrate version
  compose run --rm --no-deps migrate down 1
  compose run --rm --no-deps migrate up
fi
# Provision a restricted test login separately from the migration owner.
compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB" -c "CREATE ROLE auth_runtime LOGIN PASSWORD '\''test-runtime-only'\'';"'
compose exec -T postgres sh -c 'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"' < deploy/runtime-grants.sql
compose exec -T postgres sh -c 'PGPASSWORD=test-runtime-only psql -h localhost -U auth_runtime "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM auth.users;"'
if [[ "${AUTH_SMOKE_ONLY:-false}" != true ]]; then
  if compose exec -T postgres sh -c 'PGPASSWORD=test-runtime-only psql -h localhost -U auth_runtime "$POSTGRES_DB" -v ON_ERROR_STOP=1 -c "CREATE TABLE auth.forbidden(id int);"'; then echo 'Runtime DDL incorrectly permitted' >&2; exit 1; fi
fi
compose up -d --no-deps api
wait_ready() {
  address=$(compose port api 8080)
  for attempt in $(seq 1 120); do
    if curl --silent --fail --max-time 3 "http://$address/health/ready"; then return; fi
    if [[ "$(compose ps --status exited --services api)" == api ]]; then compose logs --tail=10 api; exit 1; fi
    if [[ "$attempt" == 120 ]]; then compose logs api; exit 1; fi
    sleep 1
  done
}
wait_ready
test "$(curl --silent --output /dev/null --write-out '%{http_code}' "http://$address/swagger/index.html")" = 404
if [[ "${AUTH_TEST_APP_ENV:-test}" == dev ]]; then
  curl --silent --fail --max-time 10 -H 'Content-Type: application/json' -d '{"to":"canary@example.com","subject":"Auth smoke","body":"<p>SMTP works</p>"}' "http://$address/api/v1/dev/send-mail"
else
  test "$(curl --silent --output /dev/null --write-out '%{http_code}' -X POST "http://$address/api/v1/dev/send-mail")" = 404
fi
curl --silent --fail --max-time 3 "http://$address/health/live"
if [[ "${AUTH_SMOKE_ONLY:-false}" == true ]]; then echo 'Startup/SMTP smoke passed'; exit 0; fi
# A concrete DB canary proves that the archive, not an empty replacement, is restored.
compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB" -c "INSERT INTO auth.users(id) VALUES ('\''00000000-0000-0000-0000-000000000001'\'');"'
compose run --rm --no-deps backup create
archive=$(compose run --rm --no-deps --entrypoint bash backup -c 'find /backups -maxdepth 1 -name "backup_*.dump" -printf "%f\n" | sort | tail -n 1')
if compose run --rm --no-deps backup verify ../unsafe.dump; then echo 'Traversal accepted' >&2; exit 1; fi
compose run --rm --no-deps --entrypoint bash backup -c 'cp "/backups/$1" /backups/corrupt.dump; cp "/backups/$1.sha256" /backups/corrupt.dump.sha256; printf corrupted >> /backups/corrupt.dump; sed -i "s/$1/corrupt.dump/" /backups/corrupt.dump.sha256' -- "$archive"
if compose run --rm --no-deps backup verify corrupt.dump; then echo 'Corrupt archive accepted' >&2; exit 1; fi
compose run -d --no-deps --name "$project-lock-test" --entrypoint bash backup -c 'exec 9>/backups/.backup-restore.lock; flock -x 9; touch /backups/test-lock-held; sleep 10'
for attempt in $(seq 1 20); do
  if compose run --rm --no-deps --entrypoint bash backup -c 'test -f /backups/test-lock-held'; then break; fi
  sleep 0.2
done
if compose run --rm --no-deps backup verify "$archive"; then echo 'Concurrent operation lock bypassed' >&2; exit 1; fi
docker rm -f "$project-lock-test"
compose stop api
compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB" -c "DELETE FROM auth.users;"'
compose run --rm --no-deps backup restore "$archive"
compose exec -T postgres sh -c 'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"' < deploy/runtime-grants.sql
count=$(compose exec -T postgres sh -c 'psql -At -U "$POSTGRES_USER" "$POSTGRES_DB" -c "SELECT count(*) FROM auth.users;"')
test "$count" = 1
compose run --rm --no-deps migrate down 1
compose run --rm --no-deps migrate up
compose exec -T postgres sh -c 'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"' < deploy/runtime-grants.sql
compose up -d --no-deps api
wait_ready
# Readiness must reflect real Redis failure; liveness remains healthy.
compose stop redis
sleep 1
test "$(curl --silent --max-time 15 --output /dev/null --write-out '%{http_code}' "http://$address/health/ready")" = 503
test "$(curl --silent --max-time 3 --output /dev/null --write-out '%{http_code}' "http://$address/health/live")" = 200
echo 'Isolated migrations, readiness, archive restore and failure checks passed'
