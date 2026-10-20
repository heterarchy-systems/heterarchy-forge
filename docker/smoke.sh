#!/usr/bin/env bash
# Forge standalone backend compose smoke.
#
# Steps: build → up → /healthz → /readyz → capability → location.register
# (container path) → location.list → typed duplicate-root conflict → down.
#
# This driver covers the HTTP service surface. Native Linux confinement and
# admitted execution have separate build-stage gates in Dockerfile.
#
# Project isolation: every run gets a unique compose project name, so the
# cleanup `down -v` can only ever remove this run's own containers, networks
# and named volumes. A developer's volumes that live under the directory-
# derived default project (or any other project) are never touched.
set -euo pipefail

cd "$(dirname "$0")/.."

# Execution-evidence layers use --security=insecure; route the build through
# the builder whose daemon allows that entitlement (created via
# `docker buildx create --buildkitd-flags '--allow-insecure-entitlement
# security.insecure'`). Overridable for environments with another setup.
export BUILDX_BUILDER="${BUILDX_BUILDER:-forge-insecure}"

COMPOSE_PROJECT_NAME="forge-smoke-$(date +%Y%m%d%H%M%S)-$$"
export COMPOSE_PROJECT_NAME
SMOKE_VOLUME="${COMPOSE_PROJECT_NAME}_forge-state"

SECRETS_DIR="docker/smoke/secrets"
HEALTH_URL="http://127.0.0.1:8080/healthz"
READY_URL="http://127.0.0.1:8080/readyz"
CAPABILITY_URL="http://127.0.0.1:8080/api/v1/capability"

log() { printf '[forge-smoke] %s\n' "$*"; }

generate_secrets() {
    mkdir -p "$SECRETS_DIR"
    if [ ! -s "$SECRETS_DIR/api.secret" ] || [ ! -s "$SECRETS_DIR/session.secret" ]; then
        log "generating throwaway smoke bearer secrets"
        # Bounded head feed: an unbounded /dev/urandom pipe would SIGPIPE the
        # producer and, under pipefail, abort the script.
        LC_ALL=C head -c 256 /dev/urandom | LC_ALL=C tr -cd 'a-f0-9' | head -c 48 \
            > "$SECRETS_DIR/api.secret"
        printf '\n' >> "$SECRETS_DIR/api.secret"
        LC_ALL=C head -c 256 /dev/urandom | LC_ALL=C tr -cd 'a-f0-9' | head -c 48 \
            > "$SECRETS_DIR/session.secret"
        printf '\n' >> "$SECRETS_DIR/session.secret"
    fi
    if cmp -s "$SECRETS_DIR/api.secret" "$SECRETS_DIR/session.secret"; then
        log "api and session secrets must differ"
        exit 1
    fi
}

exec_in_forge() {
    docker compose exec -T forge "$@"
}

log "step 1/7: compose build"
docker compose build

generate_secrets

log "step 2/7: compose up"
docker compose up -d --wait

cleanup() {
    log "compose down -v for isolated project ${COMPOSE_PROJECT_NAME}"
    docker compose down -v --remove-orphans || true
    if docker volume inspect "$SMOKE_VOLUME" > /dev/null 2>&1; then
        log "cleanup leak: $SMOKE_VOLUME still exists"
        exit 1
    fi
    log "cleanup verified: smoke volume removed, other projects untouched"
}
trap cleanup EXIT

log "step 3/7: /healthz and /readyz"
HEALTH="$(exec_in_forge curl -fsS "$HEALTH_URL")"
[ "$HEALTH" = "ok" ] || { log "unexpected /healthz body: $HEALTH"; exit 1; }
READY="$(exec_in_forge curl -fsS "$READY_URL")"
printf '%s' "$READY" | grep -q '"ready":true' || {
    log "readiness did not report ready: $READY"
    exit 1
}

log "step 4/7: capability document"
CAPABILITY="$(exec_in_forge curl -fsS "$CAPABILITY_URL")"
printf '%s' "$CAPABILITY" | grep -q 'location.register' || {
    log "capability is missing location.register: $CAPABILITY"
    exit 1
}

log "step 5/7: location.register with the container path"
BEARER="$(cat "$SECRETS_DIR/api.secret")"
REQUEST_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr 'A-Z' 'a-z')"
REGISTER_BODY="$(printf '{"forge_api":1,"request_id":"%s","op":"location.register","payload":{"location_id":"7f3c1e64-0000-4000-8000-00000000d001","name":"smoke-demo","path":"/workspaces/demo","observed_at_ms":1}}' "$REQUEST_ID")"
REGISTERED="$(exec_in_forge curl -fsS -X POST http://127.0.0.1:8080/api/v1/commands/location.register \
    -H "Authorization: Bearer $BEARER" \
    -H 'Content-Type: application/json' \
    -d "$REGISTER_BODY")"
printf '%s' "$REGISTERED" | grep -q '"state":"enabled"' || {
    log "location.register failed: $REGISTERED"
    exit 1
}

log "step 6/7: read-only location.list shows the registration; duplicate root is a typed conflict"
LISTING="$(exec_in_forge curl -fsS -X POST http://127.0.0.1:8080/api/v1/commands/location.list \
    -H "Authorization: Bearer $BEARER" \
    -H 'Content-Type: application/json' \
    -d "{\"forge_api\":1,\"request_id\":\"$REQUEST_ID\",\"op\":\"location.list\",\"payload\":{}}")"
printf '%s' "$LISTING" | grep -q 'smoke-demo' || {
    log "location.list is missing the smoke registration: $LISTING"
    exit 1
}
DUPLICATE_BODY="$(printf '{"forge_api":1,"request_id":"%s","op":"location.register","payload":{"location_id":"7f3c1e64-0000-4000-8000-00000000d002","name":"smoke-demo-dupe","path":"/workspaces/demo","observed_at_ms":1}}' "$REQUEST_ID")"
DUPLICATE_STATUS="$(exec_in_forge curl -sS -o /dev/null -w '%{http_code}' \
    -X POST http://127.0.0.1:8080/api/v1/commands/location.register \
    -H "Authorization: Bearer $BEARER" \
    -H 'Content-Type: application/json' \
    -d "$DUPLICATE_BODY")"
DUPLICATE_REPLY="$(exec_in_forge curl -sS \
    -X POST http://127.0.0.1:8080/api/v1/commands/location.register \
    -H "Authorization: Bearer $BEARER" \
    -H 'Content-Type: application/json' \
    -d "$DUPLICATE_BODY")"
printf '%s' "$DUPLICATE_REPLY" | grep -q 'WORKSPACE_ROOT_CONFLICT' || {
    log "duplicate root did not produce the typed conflict: $DUPLICATE_REPLY"
    exit 1
}
[ "$DUPLICATE_STATUS" = "409" ] || {
    log "duplicate root status was $DUPLICATE_STATUS, expected 409"
    exit 1
}

log "step 7/7: stop"
log "SMOKE PASS: build/up/healthz/readyz/capability/register/list/typed-conflict/isolated-down (project ${COMPOSE_PROJECT_NAME})"
