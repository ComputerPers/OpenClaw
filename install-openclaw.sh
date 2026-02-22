#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="220226-1342" #ddMMYY-HHmm

SCRIPT_NAME="$(basename "$0")"
TARGET_DIR="${OPENCLAW_ENV_DIR:-$HOME/OpenClawEnvironment}"
ENV_FILE="$TARGET_DIR/.env"
COMPOSE_FILE="$TARGET_DIR/docker-compose.yml"
CADDY_DIR="$TARGET_DIR/caddy"
CADDY_FILE="$CADDY_DIR/Caddyfile"

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME install      # create/update files, run OpenClaw + Caddy, onboard OpenRouter, set model, prompt Telegram setup
  $SCRIPT_NAME telegram     # connect Telegram bot using TELEGRAM_BOT_TOKEN from .env
  $SCRIPT_NAME status       # show docker compose status

Optional:
  OPENCLAW_ENV_DIR=/custom/path $SCRIPT_NAME install
EOF
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: required command is missing: $cmd" >&2
    exit 1
  fi
}

require_docker_compose() {
  if ! docker compose version >/dev/null 2>&1; then
    echo "Error: docker compose v2 is required." >&2
    exit 1
  fi
}

print_banner() {
  echo "OpenClaw Docker installer v${INSTALLER_VERSION}"
  echo "Environment dir: ${TARGET_DIR}"
  echo
}

ensure_dirs() {
  mkdir -p "$TARGET_DIR" "$TARGET_DIR/config" "$TARGET_DIR/workspace" "$CADDY_DIR"
}

write_compose() {
  cat >"$COMPOSE_FILE" <<'EOF'
services:
  openclaw-gateway:
    image: ${OPENCLAW_IMAGE:-ghcr.io/openclaw/openclaw:latest}
    container_name: openclaw-gateway
    environment:
      HOME: /home/node
      TERM: xterm-256color
      OPENCLAW_GATEWAY_TOKEN: ${OPENCLAW_GATEWAY_TOKEN}
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
    volumes:
      - ${OPENCLAW_CONFIG_DIR:-./config}:/home/node/.openclaw
      - ${OPENCLAW_WORKSPACE_DIR:-./workspace}:/home/node/.openclaw/workspace
    init: true
    restart: unless-stopped
    command:
      [
        "node",
        "dist/index.js",
        "gateway",
        "--allow-unconfigured",
        "--bind",
        "${OPENCLAW_GATEWAY_BIND:-lan}",
        "--port",
        "18789"
      ]

  openclaw-cli:
    image: ${OPENCLAW_IMAGE:-ghcr.io/openclaw/openclaw:latest}
    container_name: openclaw-cli
    environment:
      HOME: /home/node
      TERM: xterm-256color
      OPENCLAW_GATEWAY_TOKEN: ${OPENCLAW_GATEWAY_TOKEN}
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
      BROWSER: echo
    volumes:
      - ${OPENCLAW_CONFIG_DIR:-./config}:/home/node/.openclaw
      - ${OPENCLAW_WORKSPACE_DIR:-./workspace}:/home/node/.openclaw/workspace
    stdin_open: true
    tty: true
    init: true
    entrypoint: ["node", "dist/index.js"]

  caddy:
    image: ${CADDY_IMAGE:-caddy:2-alpine}
    container_name: openclaw-caddy
    depends_on:
      - openclaw-gateway
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
    ports:
      - "${OPENCLAW_GATEWAY_PORT:-18789}:18789"
    restart: unless-stopped
EOF
}

write_env_template_if_missing() {
  if [[ -f "$ENV_FILE" ]]; then
    return
  fi

  cat >"$ENV_FILE" <<'EOF'
# OpenClaw Docker environment
# Fill required values before first install run.

OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw:latest
# Caddy image registry fallback:
# - default: caddy:2-alpine (Docker Hub)
# - alternative: ghcr.io/caddyserver/caddy:2-alpine (GHCR)
CADDY_IMAGE=caddy:2-alpine
OPENCLAW_GATEWAY_BIND=lan
OPENCLAW_GATEWAY_PORT=18789

# Relative to this .env file location
OPENCLAW_CONFIG_DIR=./config
OPENCLAW_WORKSPACE_DIR=./workspace

# Required: OpenRouter API key (sk-or-...)
OPENROUTER_API_KEY=

# Optional: leave empty to auto-generate on install
OPENCLAW_GATEWAY_TOKEN=

# Required: LAN reverse-proxy auth credentials
CADDY_USER=admin
CADDY_PASSWORD=

# Default model for this installer
OPENCLAW_MODEL=openrouter/google/gemini-3-flash-preview

# Optional Telegram bot token for installer telegram command
TELEGRAM_BOT_TOKEN=
EOF
  chmod 600 "$ENV_FILE"
  echo "Created $ENV_FILE"
  echo "A .env template was created. Installer will prompt for required values."
}

load_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: .env not found at $ENV_FILE" >&2
    exit 1
  fi

  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
}

upsert_env() {
  local key="$1"
  local value="$2"
  local tmp_file
  tmp_file="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { done = 0 }
    $0 ~ "^" key "=" {
      print key "=" value
      done = 1
      next
    }
    { print }
    END {
      if (!done) {
        print key "=" value
      }
    }
  ' "$ENV_FILE" >"$tmp_file"
  mv "$tmp_file" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

generate_gateway_token_if_empty() {
  if [[ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]]; then
    return
  fi
  local token
  token="$(openssl rand -hex 32)"
  upsert_env "OPENCLAW_GATEWAY_TOKEN" "$token"
  OPENCLAW_GATEWAY_TOKEN="$token"
  export OPENCLAW_GATEWAY_TOKEN
  echo "Generated OPENCLAW_GATEWAY_TOKEN and saved to .env"
}

require_env_values() {
  local missing=0

  if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "Error: OPENROUTER_API_KEY is empty in $ENV_FILE" >&2
    missing=1
  fi
  if [[ -z "${CADDY_USER:-}" ]]; then
    echo "Error: CADDY_USER is empty in $ENV_FILE" >&2
    missing=1
  fi
  if [[ -z "${CADDY_PASSWORD:-}" ]]; then
    echo "Error: CADDY_PASSWORD is empty in $ENV_FILE" >&2
    missing=1
  fi
  if [[ -z "${OPENCLAW_MODEL:-}" ]]; then
    echo "Error: OPENCLAW_MODEL is empty in $ENV_FILE" >&2
    missing=1
  fi

  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
}

prompt_var_if_empty() {
  local var_name="$1"
  local prompt_text="$2"
  local secret="${3:-0}"
  local current_value="${!var_name:-}"
  local input_value=""

  if [[ -n "$current_value" ]]; then
    return
  fi

  local input_fd=0
  if [[ -r /dev/tty ]]; then
    input_fd=9
    exec 9</dev/tty
  elif [[ ! -t 0 ]]; then
    return
  fi

  while [[ -z "$input_value" ]]; do
    if [[ "$secret" == "1" ]]; then
      if [[ "$input_fd" -eq 9 ]]; then
        read -r -u 9 -s -p "$prompt_text: " input_value
      else
        read -r -s -p "$prompt_text: " input_value
      fi
      echo
    else
      if [[ "$input_fd" -eq 9 ]]; then
        read -r -u 9 -p "$prompt_text: " input_value
      else
        read -r -p "$prompt_text: " input_value
      fi
    fi

    if [[ -z "$input_value" ]]; then
      echo "Value cannot be empty."
    fi
  done

  if [[ "$input_fd" -eq 9 ]]; then
    exec 9<&-
  fi

  upsert_env "$var_name" "$input_value"
  export "$var_name=$input_value"
}

prompt_required_env_values() {
  prompt_var_if_empty "OPENROUTER_API_KEY" "Enter OPENROUTER_API_KEY (sk-or-...)" 1
  prompt_var_if_empty "CADDY_USER" "Enter CADDY username"
  prompt_var_if_empty "CADDY_PASSWORD" "Enter CADDY password" 1
}

prompt_openrouter_model() {
  local default_model="openrouter/google/gemini-3-flash-preview"
  local input_fd=0
  local selected_model=""

  if [[ -z "${OPENCLAW_MODEL:-}" ]]; then
    selected_model="$default_model"
  else
    OPENCLAW_MODEL="$OPENCLAW_MODEL"
    return
  fi

  if [[ -r /dev/tty ]]; then
    input_fd=9
    exec 9</dev/tty
  elif [[ ! -t 0 ]]; then
    OPENCLAW_MODEL="$selected_model"
    upsert_env "OPENCLAW_MODEL" "$OPENCLAW_MODEL"
    export OPENCLAW_MODEL
    return
  fi

  echo
  if [[ "$input_fd" -eq 9 ]]; then
    read -r -u 9 -p "OpenRouter model [${selected_model}]: " OPENCLAW_MODEL
  else
    read -r -p "OpenRouter model [${selected_model}]: " OPENCLAW_MODEL
  fi
  if [[ -z "${OPENCLAW_MODEL:-}" ]]; then
    OPENCLAW_MODEL="$selected_model"
  fi
  upsert_env "OPENCLAW_MODEL" "$OPENCLAW_MODEL"
  export OPENCLAW_MODEL

  if [[ "$input_fd" -eq 9 ]]; then
    exec 9<&-
  fi
}

prompt_telegram_token() {
  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    return
  fi

  local input_fd=0
  if [[ -r /dev/tty ]]; then
    input_fd=9
    exec 9</dev/tty
  elif [[ ! -t 0 ]]; then
    return
  fi

  echo
  echo "Telegram setup (optional): press Enter to skip."
  if [[ "$input_fd" -eq 9 ]]; then
    read -r -u 9 -s -p "Enter TELEGRAM_BOT_TOKEN: " TELEGRAM_BOT_TOKEN
  else
    read -r -s -p "Enter TELEGRAM_BOT_TOKEN: " TELEGRAM_BOT_TOKEN
  fi
  echo
  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    upsert_env "TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN"
    export TELEGRAM_BOT_TOKEN
  else
    echo "Telegram token is empty, skipping Telegram setup."
  fi

  if [[ "$input_fd" -eq 9 ]]; then
    exec 9<&-
  fi
}

docker_pull_try() {
  local image="$1"
  local attempts="${2:-3}"
  local sleep_s="${3:-2}"

  local i=1
  while [[ "$i" -le "$attempts" ]]; do
    if docker pull "$image" >/dev/null; then
      return 0
    fi
    echo "Warning: failed to pull $image (attempt $i/$attempts)" >&2
    sleep "$sleep_s"
    i=$((i + 1))
  done
  return 1
}

resolve_caddy_image() {
  local candidate_images=()
  local img=""

  # Prefer user-specified image if present.
  if [[ -n "${CADDY_IMAGE:-}" ]]; then
    candidate_images+=("$CADDY_IMAGE")
  fi

  # Known public mirrors.
  candidate_images+=(
    "caddy:2-alpine"
    "docker.io/library/caddy:2-alpine"
    "ghcr.io/caddyserver/caddy:2-alpine"
  )

  for img in "${candidate_images[@]}"; do
    # If already present locally, use it.
    if docker image inspect "$img" >/dev/null 2>&1; then
      CADDY_IMAGE="$img"
      upsert_env "CADDY_IMAGE" "$CADDY_IMAGE"
      export CADDY_IMAGE
      return 0
    fi

    if docker_pull_try "$img" 2 2; then
      CADDY_IMAGE="$img"
      upsert_env "CADDY_IMAGE" "$CADDY_IMAGE"
      export CADDY_IMAGE
      return 0
    fi
  done

  echo "Error: could not pull any Caddy image." >&2
  echo "Tried:" >&2
  printf '  - %s\n' "${candidate_images[@]}" >&2
  echo "Hint: set CADDY_IMAGE in $ENV_FILE to a reachable registry and re-run." >&2
  return 1
}

generate_caddyfile() {
  local hash_output
  local password_hash
  local caddy_img=""

  resolve_caddy_image
  caddy_img="${CADDY_IMAGE}"

  hash_output="$(docker run --rm "$caddy_img" caddy hash-password --plaintext "${CADDY_PASSWORD}")"
  password_hash="$(printf '%s\n' "$hash_output" | awk 'END { print $NF }')"

  if [[ -z "$password_hash" ]]; then
    echo "Error: failed to generate Caddy password hash" >&2
    exit 1
  fi

  cat >"$CADDY_FILE" <<EOF
:18789 {
  basic_auth {
    ${CADDY_USER} ${password_hash}
  }
  reverse_proxy openclaw-gateway:18789 {
    header_up X-Forwarded-User {http.auth.user.id}
  }
}
EOF
}

compose_cmd() {
  docker compose --project-directory "$TARGET_DIR" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

try_configure_telegram_channel() {
  local token="$1"
  local output=""
  local rc=0
  local ch=""
  local -a candidates=("telegram" "tg" "telegram-bot" "telegram_bot" "telegramBot")

  # Prefer config-based setup (more stable than `channels add` across versions/builds).
  set +e
  output="$(compose_cmd run --rm openclaw-cli config set channels.telegram.enabled true 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    set +e
    output="$(compose_cmd run --rm openclaw-cli config set channels.telegram.botToken "$token" 2>&1)"
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
      echo "Telegram channel configured via config."
      return 0
    fi
  fi

  for ch in "${candidates[@]}"; do
    set +e
    output="$(compose_cmd run --rm openclaw-cli channels add --channel "$ch" --token "$token" 2>&1)"
    rc=$?
    set -e

    if [[ "$rc" -eq 0 ]]; then
      echo "Telegram channel configured (channel=$ch)."
      return 0
    fi

    if printf '%s\n' "$output" | grep -qiE 'unknown channel|unsupported channel'; then
      continue
    fi

    echo "Warning: failed to configure Telegram channel (channel=$ch). Output:" >&2
    printf '%s\n' "$output" >&2
    return 1
  done

  echo "Warning: Telegram channel is not available in this OpenClaw build; skipping Telegram setup." >&2
  echo "Hint: run 'openclaw channels list' to see supported channels (inside the container: 'docker compose ... run --rm openclaw-cli channels list')." >&2
  return 2
}

configure_trusted_proxy_auth() {
  # Use trusted-proxy auth so the browser never needs to know the gateway token.
  # Caddy authenticates users via Basic Auth and passes identity in X-Forwarded-User.
  # Gateway trusts requests from the Docker network (172.16.0.0/12 covers all default
  # Docker subnets) and grants access based on the header value.
  #
  # Uses a Node.js one-liner to patch openclaw.json atomically because
  # `openclaw config set` does not support array values (trustedProxies).
  local docker_subnet="172.16.0.0/12"
  echo "Configuring gateway trusted-proxy auth..."
  compose_cmd run --rm --entrypoint node openclaw-cli \
    -e "var fs=require('fs'),p='/home/node/.openclaw/openclaw.json',c=JSON.parse(fs.readFileSync(p,'utf8'));c.gateway=c.gateway||{};c.gateway.auth={mode:'trusted-proxy',trustedProxy:{userHeader:'x-forwarded-user'}};c.gateway.trustedProxies=['${docker_subnet}'];fs.writeFileSync(p,JSON.stringify(c,null,2));console.log('Gateway trusted-proxy auth configured.');" \
    || {
      echo "Warning: failed to configure trusted-proxy auth via node; falling back to config set." >&2
      compose_cmd run --rm openclaw-cli config set gateway.auth.mode trusted-proxy || true
      compose_cmd run --rm openclaw-cli config set gateway.auth.trustedProxy.userHeader x-forwarded-user || true
    }
}

dump_compose_diagnostics() {
  echo >&2
  echo "---- docker compose ps ----" >&2
  compose_cmd ps >&2 || true
  echo >&2
  echo "---- openclaw-gateway logs (tail 200) ----" >&2
  compose_cmd logs --tail 200 openclaw-gateway >&2 || true
  echo >&2
  echo "---- caddy logs (tail 120) ----" >&2
  compose_cmd logs --tail 120 caddy >&2 || true
  echo >&2
}

ensure_services_running() {
  local required_services="openclaw-gateway caddy"
  local missing=0
  local service

  for service in $required_services; do
    if ! compose_cmd ps --status running --services | awk -v s="$service" '$0 == s { found=1 } END { exit found ? 0 : 1 }'; then
      echo "Error: service is not running: $service" >&2
      missing=1
    fi
  done

  if [[ "$missing" -ne 0 ]]; then
    return 1
  fi
}

run_health_checks() {
  local port="${OPENCLAW_GATEWAY_PORT:-18789}"
  local max_attempts=20
  local sleep_s=2
  local attempt=1

  # Step 1: verify both containers are in running state.
  ensure_services_running

  # Step 2: wait for the Caddy HTTP endpoint to respond.
  # We do NOT probe the gateway WebSocket directly: the gateway requires device pairing for
  # new CLI connections, so a raw WS connect from openclaw-cli would be rejected with
  # 1008 "pairing required" even when everything is perfectly healthy. Caddy up + gateway
  # container running is a sufficient indicator of a successful install.
  echo "Waiting for Caddy endpoint http://127.0.0.1:${port}/ ..."
  while [[ "$attempt" -le "$max_attempts" ]]; do
    if curl -fsS -u "${CADDY_USER}:${CADDY_PASSWORD}" "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
      echo "Caddy endpoint is up."
      return 0
    fi
    if [[ "$attempt" -eq "$max_attempts" ]]; then
      echo "Error: Caddy endpoint check failed on http://127.0.0.1:${port}/ after ${max_attempts} attempts." >&2
      dump_compose_diagnostics
      return 1
    fi
    echo "Warning: Caddy not ready yet (attempt ${attempt}/${max_attempts}); retrying..." >&2
    sleep "$sleep_s"
    attempt=$((attempt + 1))
  done
}

collect_host_ipv4() {
  if ! command -v ifconfig >/dev/null 2>&1; then
    return
  fi

  ifconfig | awk '
    /inet / {
      ip = $2
      if (ip !~ /^127\./) {
        print ip
      }
    }
  ' | awk '!seen[$0]++'
}

run_install() {
  ensure_dirs
  write_compose
  write_env_template_if_missing
  load_env
  generate_gateway_token_if_empty
  prompt_required_env_values
  prompt_openrouter_model
  require_env_values
  prompt_telegram_token
  generate_caddyfile

  echo "Pulling images..."
  compose_cmd pull

  echo "Restarting OpenClaw services..."
  compose_cmd down --remove-orphans || true
  compose_cmd up -d openclaw-gateway caddy

  echo "Configuring OpenRouter model: $OPENCLAW_MODEL"
  compose_cmd run --rm openclaw-cli models set "$OPENCLAW_MODEL"

  # Set gateway.mode=local so the gateway doesn't block on startup (without this it refuses
  # to start and crash-loops). --allow-unconfigured in the compose command covers the first
  # boot before this config is written; subsequent restarts use the config value.
  echo "Setting gateway mode and bind..."
  compose_cmd run --rm openclaw-cli config set gateway.mode local || true
  # Force gateway.bind=lan so the gateway listens on the container's LAN interface (0.0.0.0 /
  # eth0), not just loopback. Without this the CLI container can't reach the gateway by Docker
  # service name, causing health checks to fail with WS 1006.
  compose_cmd run --rm openclaw-cli config set gateway.bind lan || true
  configure_trusted_proxy_auth

  echo "Verifying OpenRouter auth (small live probe)..."
  compose_cmd run --rm openclaw-cli models status --probe --probe-provider openrouter --probe-max-tokens 8 >/dev/null

  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    echo "Configuring Telegram channel..."
    try_configure_telegram_channel "$TELEGRAM_BOT_TOKEN" || true
  fi

  echo "Restarting gateway to apply final config..."
  compose_cmd restart openclaw-gateway
  # Give the gateway a moment to fully come up before probing.
  sleep 3

  echo "Running post-install checks..."
  if ! run_health_checks; then
    echo "Warning: post-install checks failed. OpenClaw may still be running; see diagnostics above." >&2
  fi

  echo
  echo "================================================================"
  echo " OpenClaw is up."
  echo "================================================================"
  echo
  echo "Access URLs (IPv4):"
  echo "  http://localhost:${OPENCLAW_GATEWAY_PORT:-18789}/"
  while IFS= read -r ipv4; do
    [[ -z "$ipv4" ]] && continue
    echo "  http://${ipv4}:${OPENCLAW_GATEWAY_PORT:-18789}/"
  done < <(collect_host_ipv4)
  echo
  echo "Login (Basic Auth):"
  echo "  Username: ${CADDY_USER}"
  echo "  Password: value from ${ENV_FILE} -> CADDY_PASSWORD"
  echo
  echo "The gateway token is injected automatically by the proxy — no manual setup needed."
  echo "================================================================"
}

run_telegram() {
  ensure_dirs
  write_compose
  write_env_template_if_missing
  load_env

  if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    echo "Error: TELEGRAM_BOT_TOKEN is empty in $ENV_FILE" >&2
    exit 1
  fi

  echo "Adding Telegram channel..."
  if ! try_configure_telegram_channel "$TELEGRAM_BOT_TOKEN"; then
    echo "Error: could not configure Telegram channel in this OpenClaw build." >&2
    exit 1
  fi
}

run_status() {
  ensure_dirs
  write_compose
  write_env_template_if_missing
  compose_cmd ps
}

main() {
  local action="${1:-install}"

  print_banner

  require_cmd docker
  require_cmd openssl
  require_cmd curl
  require_docker_compose

  case "$action" in
    install)
      run_install
      ;;
    telegram)
      run_telegram
      ;;
    status)
      run_status
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "Unknown action: $action" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
