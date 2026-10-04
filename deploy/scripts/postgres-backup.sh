#!/usr/bin/env bash

set -Eeuo pipefail

umask 077

readonly BACKUP_DIR="${BACKUP_DIR:-/backups}"
readonly BACKUP_INTERVAL="${BACKUP_INTERVAL:-24h}"
readonly BACKUP_RETENTION_COUNT="${BACKUP_RETENTION_COUNT:-7}"
readonly RESTORE_HEALTHCHECK_SQL="${RESTORE_HEALTHCHECK_SQL:-SELECT 1}"
readonly LOCK_FILE="${BACKUP_DIR}/.backup-restore.lock"

log() {
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

fail() {
    log "ERROR: $*" >&2
    exit 1
}

ensure_backup_dir() {
    [[ "$BACKUP_DIR" == "/backups" && ! -L "$BACKUP_DIR" ]] || fail "backup directory must be the dedicated /backups volume"
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    touch "$LOCK_FILE"
}

duration_seconds() {
    local value="$1"
    local number suffix multiplier

    [[ "$value" =~ ^([1-9][0-9]*)([smhd])$ ]] || fail "invalid BACKUP_INTERVAL: $value"

    number="${BASH_REMATCH[1]}"
    suffix="${BASH_REMATCH[2]}"

    case "$suffix" in
        s) multiplier=1 ;;
        m) multiplier=60 ;;
        h) multiplier=3600 ;;
        d) multiplier=86400 ;;
    esac

    printf '%s\n' "$((number * multiplier))"
}

validate_settings() {
    [[ "$BACKUP_RETENTION_COUNT" =~ ^[1-9][0-9]*$ ]] || fail "invalid BACKUP_RETENTION_COUNT: $BACKUP_RETENTION_COUNT"
    duration_seconds "$BACKUP_INTERVAL" >/dev/null
}

validate_archive_name() {
    local archive="$1"

    [[ "$archive" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.dump$ ]] || fail "invalid backup filename: $archive"
}

is_valid_pair() {
    local dump_path="$1"
    local checksum_path="${dump_path}.sha256"

    [[ -f "$dump_path" && -f "$checksum_path" && ! -L "$dump_path" && ! -L "$checksum_path" ]] || return 1
    (cd "$BACKUP_DIR" && sha256sum --check --status "$(basename "$checksum_path")")
}

verify_archive_unlocked() {
    local archive="$1"
    local dump_path checksum_path

    validate_archive_name "$archive"

    dump_path="${BACKUP_DIR}/${archive}"
    checksum_path="${dump_path}.sha256"

    [[ -f "$dump_path" && ! -L "$dump_path" ]] || fail "backup not found: $archive"
    [[ -f "$checksum_path" && ! -L "$checksum_path" ]] || fail "checksum not found: ${archive}.sha256"

    (cd "$BACKUP_DIR" && sha256sum --check --status "$(basename "$checksum_path")") || fail "SHA256 mismatch: $archive"
    pg_restore --list "$dump_path" >/dev/null || fail "pg_restore preflight failed: $archive"
}

cleanup_incomplete_unlocked() {
    local file dump_path checksum_path

    shopt -s nullglob

    for file in "$BACKUP_DIR"/*.part; do
        rm -f -- "$file"
        log "removed incomplete file: $(basename "$file")"
    done

    for dump_path in "$BACKUP_DIR"/*.dump; do
        checksum_path="${dump_path}.sha256"
        if [[ ! -f "$checksum_path" ]]; then
            rm -f -- "$dump_path"
            log "removed orphan archive: $(basename "$dump_path")"
        fi
    done

    for checksum_path in "$BACKUP_DIR"/*.dump.sha256; do
        dump_path="${checksum_path%.sha256}"
        if [[ ! -f "$dump_path" ]]; then
            rm -f -- "$checksum_path"
            log "removed orphan checksum: $(basename "$checksum_path")"
        fi
    done
}

apply_retention_unlocked() {
    local dump_path index
    local -a archives=()

    while IFS= read -r dump_path; do
        if is_valid_pair "$dump_path"; then
            archives+=("$dump_path")
        fi
    done < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.dump' -printf '%T@\t%p\n' | sort -rn | cut -f2-)

    for ((index = BACKUP_RETENTION_COUNT; index < ${#archives[@]}; index++)); do
        rm -f -- "${archives[$index]}" "${archives[$index]}.sha256"
        log "removed expired backup: $(basename "${archives[$index]}")"
    done
}

create_backup_unlocked() {
    local prefix="$1"
    local run_retention="$2"
    local timestamp archive dump_path checksum_path dump_part checksum_part checksum sequence=0 suffix

    [[ "$prefix" =~ ^[a-z][a-z0-9_-]*$ ]] || fail "invalid backup prefix: $prefix"
    [[ "$run_retention" == "true" || "$run_retention" == "false" ]] || fail "invalid retention flag: $run_retention"

    timestamp="$(date -u +%Y-%m-%d_%H-%M-%SZ)"
    archive="${prefix}_${timestamp}.dump"

    while [[ -e "${BACKUP_DIR}/${archive}" || -e "${BACKUP_DIR}/${archive}.sha256" || -e "${BACKUP_DIR}/${archive}.part" || -e "${BACKUP_DIR}/${archive}.sha256.part" ]]; do
        ((sequence += 1))
        printf -v suffix '_%02d' "$sequence"
        archive="${prefix}_${timestamp}${suffix}.dump"
    done

    dump_path="${BACKUP_DIR}/${archive}"
    checksum_path="${dump_path}.sha256"
    dump_part="${dump_path}.part"
    checksum_part="${checksum_path}.part"

    log "creating backup: $archive"

    if ! pg_dump --format=custom --no-privileges --file="$dump_part"; then
        rm -f -- "$dump_part" "$checksum_part"
        fail "pg_dump failed"
    fi

    checksum="$(sha256sum "$dump_part" | awk '{print $1}')"
    printf '%s  %s\n' "$checksum" "$archive" >"$checksum_part"

    [[ "$(sha256sum "$dump_part" | awk '{print $1}')" == "$checksum" ]] || fail "temporary backup checksum mismatch"
    pg_restore --list "$dump_part" >/dev/null || fail "temporary backup preflight failed"

    mv -- "$dump_part" "$dump_path"
    mv -- "$checksum_part" "$checksum_path"

    is_valid_pair "$dump_path" || fail "published backup verification failed"
    log "backup created: $archive"

    if [[ "$run_retention" == "true" ]]; then
        apply_retention_unlocked
    fi
}

latest_valid_mtime_unlocked() {
    local dump_path mtime latest=0

    shopt -s nullglob
    for dump_path in "$BACKUP_DIR"/*.dump; do
        if is_valid_pair "$dump_path"; then
            mtime="$(stat -c %Y "$dump_path")"
            if ((mtime > latest)); then
                latest="$mtime"
            fi
        fi
    done

    printf '%s\n' "$latest"
}

with_lock() {
    local callback="$1"
    shift

    (
        exec 9>"$LOCK_FILE"
        flock -n 9 || fail "backup/restore operation is already running"
        "$callback" "$@"
    )
}

scheduled_cycle_unlocked() {
    local interval_seconds latest now

    cleanup_incomplete_unlocked

    interval_seconds="$(duration_seconds "$BACKUP_INTERVAL")"
    latest="$(latest_valid_mtime_unlocked)"
    now="$(date +%s)"

    if ((latest == 0 || now - latest >= interval_seconds)); then
        create_backup_unlocked "backup" "true"
        return
    fi

    log "backup is fresh; skipping scheduled creation"
}

manual_cycle_unlocked() {
    cleanup_incomplete_unlocked
    create_backup_unlocked "backup" "true"
}

list_backups() {
    local archive created_at dump_path mtime size type

    printf '%-20s %-12s %-14s %-10s %s\n' 'CREATED (UTC)' 'TYPE' 'SIZE' 'SHA256' 'FILE'
    shopt -s nullglob

    while IFS=$'\t' read -r mtime dump_path; do
        if is_valid_pair "$dump_path"; then
            archive="$(basename "$dump_path")"
            created_at="$(date -u -d "@${mtime%%.*}" '+%Y-%m-%d %H:%M:%SZ')"
            size="$(stat -c %s "$dump_path")"

            case "$archive" in
                backup_*) type='backup' ;;
                pre_restore_*) type='pre_restore' ;;
                *) type='legacy' ;;
            esac

            printf '%-20s %-12s %-14s %-10s %s\n' "$created_at" "$type" "${size} bytes" 'ok' "$archive"
        fi
    done < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.dump' -printf '%T@\t%p\n' | sort -rn)
}

require_restore_lock() {
    [[ "${BACKUP_LOCK_HELD:-}" == "1" ]] || fail "restore lock is required for this command"
}

terminate_sessions_unlocked() {
    psql --dbname=postgres --set=ON_ERROR_STOP=1 --set=db="$POSTGRES_DB" <<'SQL'
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = :'db'
  AND pid <> pg_backend_pid();
SQL
}

check_drop_blockers_unlocked() {
    local prepared slots subscriptions

    read -r prepared slots < <(
        psql --dbname=postgres --tuples-only --no-align --field-separator=' ' --set=ON_ERROR_STOP=1 --set=db="$POSTGRES_DB" <<'SQL'
SELECT
    (SELECT count(*) FROM pg_prepared_xacts WHERE database = :'db'),
    (SELECT count(*) FROM pg_replication_slots WHERE database = :'db');
SQL
    )

    subscriptions="$(psql --dbname="$POSTGRES_DB" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command='SELECT count(*) FROM pg_subscription;')"

    if ((prepared > 0 || slots > 0 || subscriptions > 0)); then
        fail "DROP DATABASE blockers found: prepared_transactions=$prepared logical_replication_slots=$slots subscriptions=$subscriptions"
    fi
}

recreate_database_unlocked() {
    dropdb --force --if-exists --maintenance-db=postgres "$POSTGRES_DB"
    createdb --maintenance-db=postgres --owner="$POSTGRES_USER" "$POSTGRES_DB"
}

restore_archive_unlocked() {
    local archive="$1"

    validate_archive_name "$archive"

    pg_restore \
        --single-transaction \
        --exit-on-error \
        --no-owner \
        --no-privileges \
        --dbname="$POSTGRES_DB" \
        "${BACKUP_DIR}/${archive}"
}

healthcheck_unlocked() {
    psql \
        --dbname="$POSTGRES_DB" \
        --set=ON_ERROR_STOP=1 \
        --command="$RESTORE_HEALTHCHECK_SQL"
}

run_scheduler() {
    local interval_seconds latest now retry_seconds=300 sleep_seconds

    interval_seconds="$(duration_seconds "$BACKUP_INTERVAL")"

    while true; do
        if with_lock scheduled_cycle_unlocked; then
            latest="$(latest_valid_mtime_unlocked)"
            now="$(date +%s)"
            sleep_seconds="$((interval_seconds - (now - latest)))"
            if ((latest == 0 || sleep_seconds < 1)); then
                sleep_seconds=1
            fi
        else
            sleep_seconds="$retry_seconds"
        fi

        sleep "$sleep_seconds"
    done
}

restore_cycle_unlocked() {
    local archive="$1"
    [[ "$POSTGRES_DB" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && "$POSTGRES_DB" != postgres && "$POSTGRES_DB" != template0 && "$POSTGRES_DB" != template1 ]] || fail "unsafe database target"
    verify_archive_unlocked "$archive"
    check_drop_blockers_unlocked
    create_backup_unlocked pre_restore false
    recreate_database_unlocked
    restore_archive_unlocked "$archive"
    healthcheck_unlocked
}

main() {
    local command="${1:-schedule}"

    ensure_backup_dir
    validate_settings

    case "$command" in
        schedule)
            run_scheduler
            ;;
        create)
            with_lock manual_cycle_unlocked
            ;;
        list)
            list_backups
            ;;
        verify)
            with_lock verify_archive_unlocked "${2:-}"
            ;;
        restore)
            with_lock restore_cycle_unlocked "${2:-}"
            ;;
        verify-unlocked)
            require_restore_lock
            verify_archive_unlocked "${2:-}"
            ;;
        create-unlocked)
            require_restore_lock
            create_backup_unlocked "${2:-}" "${3:-}"
            ;;
        terminate-sessions-unlocked)
            require_restore_lock
            terminate_sessions_unlocked
            ;;
        check-drop-blockers-unlocked)
            require_restore_lock
            check_drop_blockers_unlocked
            ;;
        recreate-database-unlocked)
            require_restore_lock
            recreate_database_unlocked
            ;;
        restore-unlocked)
            require_restore_lock
            restore_archive_unlocked "${2:-}"
            ;;
        healthcheck-unlocked-standalone)
            with_lock healthcheck_unlocked
            ;;
        healthcheck-unlocked)
            require_restore_lock
            healthcheck_unlocked
            ;;
        retention-unlocked)
            require_restore_lock
            apply_retention_unlocked
            ;;
        *)
            fail "unknown command: $command"
            ;;
    esac
}

main "$@"
