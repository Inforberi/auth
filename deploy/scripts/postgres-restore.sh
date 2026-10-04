#!/usr/bin/env bash
set -Eeuo pipefail
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
env_file="${AUTH_ENV_FILE:-.env.prod}"
[[ "$env_file" == /* ]] || env_file="$project_root/$env_file"
[[ -f "$env_file" ]] || { echo 'Missing production env file' >&2; exit 1; }
# Read only nonsecret target identifiers. Never source/eval an env file.
read_key() { sed -n "s/^$1=//p" "$env_file" | tail -n 1 | tr -d '\r'; }
app_name="${APP_NAME:-$(read_key APP_NAME)}"
database="${POSTGRES_DB:-$(read_key POSTGRES_DB)}"
[[ "$app_name" =~ ^[a-z0-9][a-z0-9_-]*$ && "$database" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'Unsafe target identifiers' >&2; exit 1; }
[[ "${RESTORE_CONFIRM:-}" == "$app_name:$database" ]] || { echo "Confirmation must equal $app_name:$database" >&2; exit 1; }
[[ "${RESTORE_FILE:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.dump$ ]] || { echo 'Invalid archive filename' >&2; exit 1; }
compose() { docker compose --project-directory "$project_root" --env-file "$env_file" -p "$app_name" -f "$project_root/deploy/compose.base.yml" -f "$project_root/deploy/compose.prod.yml" "$@"; }
# Docker names provide a host-wide operation mutex, including on macOS.
# An interrupted operation leaves API stopped; a stale mutex requires inspection.
lock_container="$app_name-restore-operation"
docker create --name "$lock_container" --label auth.operation=restore postgres:18.6-bookworm true >/dev/null
trap 'docker rm "$lock_container" >/dev/null' EXIT
compose run --rm --no-deps backup verify "$RESTORE_FILE"
was_running=false
if compose ps --status running --services | grep -qx api; then was_running=true; fi
backup_running=false
if compose ps --status running --services | grep -qx backup; then backup_running=true; fi
# Update this list before introducing email/billing workers (release stage 14).
compose stop api migrate backup
compose run --rm --no-deps backup restore "$RESTORE_FILE"
# Reconcile published migration versions after restoring an older archive.
compose run --rm --no-deps migrate up
# pg_dump/pg_restore deliberately omit privileges; reapply the reviewed role grants.
compose exec -T postgres sh -c 'exec psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"' < "$project_root/deploy/runtime-grants.sql"
compose run --rm --no-deps backup healthcheck-unlocked-standalone
if [[ "$was_running" == true ]]; then compose up -d --no-deps api; fi
if [[ "$backup_running" == true ]]; then compose up -d --no-deps backup; fi
echo "Restore verified for $app_name:$database"
