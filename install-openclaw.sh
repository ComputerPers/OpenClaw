#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="220226-1725" #ddMMYY-HHmm

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
  $SCRIPT_NAME approve      # approve a pending device (run after opening the dashboard in browser)
  $SCRIPT_NAME pairing approve telegram <CODE>  # approve Telegram pairing (8-char code from bot message)
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
  mkdir -p "$TARGET_DIR" "$TARGET_DIR/config" "$TARGET_DIR/workspace" "$CADDY_DIR" "$TARGET_DIR/python-packages" "$TARGET_DIR/scripts"
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
      - ${OPENCLAW_PYTHON_DIR:-./python-packages}:/usr/local/lib/python-packages
      - ${OPENCLAW_SCRIPTS_DIR:-./scripts}:/home/node/.openclaw/scripts
    init: true
    restart: unless-stopped
    entrypoint: ["/home/node/.openclaw/scripts/entrypoint.sh"]
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
      - ${OPENCLAW_PYTHON_DIR:-./python-packages}:/usr/local/lib/python-packages
      - ${OPENCLAW_SCRIPTS_DIR:-./scripts}:/home/node/.openclaw/scripts
    stdin_open: true
    tty: true
    init: true
    entrypoint: ["/home/node/.openclaw/scripts/entrypoint.sh", "node", "dist/index.js"]

  caddy:
    image: ${CADDY_IMAGE:-caddy:2-alpine}
    container_name: openclaw-caddy
    depends_on:
      - openclaw-gateway
    volumes:
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro
    ports:
      - "0.0.0.0:${OPENCLAW_GATEWAY_PORT:-18789}:18789"
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
OPENCLAW_PYTHON_DIR=./python-packages
OPENCLAW_SCRIPTS_DIR=./scripts

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
    header_up Authorization "Bearer ${OPENCLAW_GATEWAY_TOKEN}"
  }
}
EOF
}

write_entrypoint_script() {
  local entrypoint_file="$TARGET_DIR/scripts/entrypoint.sh"

  cat >"$entrypoint_file" <<'ENTRYPOINT_EOF'
#!/bin/sh
set -e

# Python packages directory
PYTHON_PACKAGES_DIR="/usr/local/lib/python-packages"
REQUIREMENTS_FILE="/home/node/.openclaw/requirements.txt"

# Check if requirements.txt exists and install packages
if [ -f "$REQUIREMENTS_FILE" ]; then
    echo "Found requirements.txt, installing Python packages..."

    # Ensure pip is available
    if ! command -v pip3 >/dev/null 2>&1; then
        echo "Installing pip..."
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache py3-pip python3-dev build-base || true
        elif command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y python3-pip python3-dev build-essential || true
        fi
    fi

    # Install packages to persistent directory
    export PYTHONPATH="${PYTHON_PACKAGES_DIR}:${PYTHONPATH}"
    pip3 install --break-system-packages --target="$PYTHON_PACKAGES_DIR" -r "$REQUIREMENTS_FILE" 2>&1 | grep -v "WARNING: Running pip as the 'root' user" || true
    echo "Python packages installed successfully."
else
    echo "No requirements.txt found, skipping Python package installation."
fi

# Set PYTHONPATH for the main process
export PYTHONPATH="${PYTHON_PACKAGES_DIR}:${PYTHONPATH}"

# Execute the main command
exec "$@"
ENTRYPOINT_EOF

  chmod +x "$entrypoint_file"
  echo "Created entrypoint script at $entrypoint_file"
}

write_requirements_template() {
  local requirements_file="$TARGET_DIR/config/requirements.txt"

  if [[ -f "$requirements_file" ]]; then
    echo "requirements.txt already exists, skipping template creation."
    return
  fi

  cat >"$requirements_file" <<'REQUIREMENTS_EOF'
# Python packages for OpenClaw
# Add your required packages here, one per line
# Example:
# python-docx
# python-pptx
# pandas
# requests

python-docx
python-pptx
REQUIREMENTS_EOF

  echo "Created requirements.txt template at $requirements_file"
  echo "You can edit this file to add more Python packages."
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

configure_gateway_auth() {
  local config_file="$TARGET_DIR/config/openclaw.json"
  local docker_subnet="172.16.0.0/12"

  if [[ ! -f "$config_file" ]]; then
    echo "Warning: openclaw.json not found at $config_file; skipping auth config." >&2
    return 1
  fi

  echo "Configuring gateway auth for Docker reverse-proxy deployment..."

  # trusted-proxy mode: Caddy authenticates users (Basic Auth) and injects
  # X-Forwarded-User. The gateway trusts Caddy by IP and uses the header as
  # user identity — no gateway token needed in the browser.
  #
  # Note on bug #17761: trusted-proxy early-returns for non-proxy IPs without
  # fallback to token auth. To work around this, internal CLI commands route
  # through Caddy (see gateway_exec_cli) so they also get X-Forwarded-User.
  if python3 -c '
import json, sys
path, subnet = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        c = json.load(f)
    gw = c.setdefault("gateway", {})

    gw["auth"] = {
        "mode": "trusted-proxy",
        "trustedProxy": {"userHeader": "x-forwarded-user"}
    }
    gw["trustedProxies"] = [subnet]

    gw.setdefault("controlUi", {})["allowInsecureAuth"] = True

    with open(path, "w") as f:
        json.dump(c, f, indent=2)
    print("Gateway auth configured (trusted-proxy + allowInsecureAuth).")
except Exception as e:
    print("Error:", e, file=sys.stderr)
    sys.exit(1)
' "$config_file" "$docker_subnet"; then
    return 0
  fi

  echo "Warning: Python3 config patch failed; using config set fallback." >&2
  compose_cmd run --rm openclaw-cli config set gateway.auth.mode trusted-proxy || true
  compose_cmd run --rm openclaw-cli config set gateway.auth.trustedProxy.userHeader x-forwarded-user || true
  compose_cmd run --rm openclaw-cli config set gateway.controlUi.allowInsecureAuth true || true
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

check_gateway_direct() {
  echo "Probing gateway directly inside Docker network..."
  local i
  for i in 1 2 3; do
    if docker exec openclaw-caddy wget -qO /dev/null --timeout=5 \
        "http://openclaw-gateway:18789/" 2>/dev/null; then
      echo "Gateway HTTP endpoint is responsive."
      return 0
    fi
    sleep 2
  done
  echo "Error: gateway is not responding inside Docker network (openclaw-gateway:18789)." >&2
  return 1
}

check_gateway_api() {
  local port="$1"
  echo "Probing gateway API health endpoints..."
  local -a api_endpoints=("/api/health" "/health" "/api/status")
  local ep http_code body
  for ep in "${api_endpoints[@]}"; do
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' \
        -u "${CADDY_USER}:${CADDY_PASSWORD}" \
        "http://127.0.0.1:${port}${ep}" 2>/dev/null)" || true
    if [[ "$http_code" == "200" ]]; then
      echo "Gateway API endpoint ${ep} returned 200."
      return 0
    fi
  done
  echo "Info: no known health endpoint found (tried: ${api_endpoints[*]}); skipping API probe."
  return 0
}

check_gateway_auth() {
  local port="$1"
  echo "Verifying gateway accepts authenticated requests through Caddy..."
  local http_code body
  http_code="$(curl -sS -o /dev/null -w '%{http_code}' \
      -u "${CADDY_USER}:${CADDY_PASSWORD}" \
      "http://127.0.0.1:${port}/api/health" 2>/dev/null)" || true
  if [[ "$http_code" == "401" || "$http_code" == "403" ]]; then
    echo "Error: gateway returned ${http_code} through Caddy — token injection may be broken." >&2
    echo "Hint: verify that the Caddyfile contains 'header_up Authorization \"Bearer ...\"'." >&2
    return 1
  fi

  # Probe the gateway directly with Bearer token (bypass Caddy) to isolate the issue.
  local direct_code
  direct_code="$(docker exec openclaw-caddy wget -qS -O /dev/null \
      --header='Authorization: Bearer '"${OPENCLAW_GATEWAY_TOKEN}" \
      "http://openclaw-gateway:18789/api/health" 2>&1 \
      | awk '/HTTP\//{print $2}' | tail -1)" || true
  if [[ "$direct_code" == "401" || "$direct_code" == "403" ]]; then
    echo "Error: gateway rejected Bearer token directly (HTTP ${direct_code}) — token mismatch." >&2
    echo "Hint: OPENCLAW_GATEWAY_TOKEN in .env must match the token the gateway was started with." >&2
    return 1
  fi
  echo "Gateway auth check passed."
  return 0
}

check_crash_loop() {
  echo "Checking for crash loops..."
  local restart_count
  restart_count="$(docker inspect --format='{{.RestartCount}}' openclaw-gateway 2>/dev/null)" || restart_count="0"
  if [[ "${restart_count:-0}" -gt 0 ]]; then
    echo "Error: gateway container has restarted ${restart_count} time(s) — possible crash loop." >&2
    return 1
  fi
  echo "No crash loops detected (restart count: 0)."
  return 0
}

check_gateway_logs() {
  echo "Scanning gateway logs for fatal errors..."
  local gw_logs
  gw_logs="$(compose_cmd logs --tail 80 openclaw-gateway 2>&1)" || true
  local -a fatal_patterns=(
    "FATAL" "EADDRINUSE" "OOMKilled" "segfault" "panic:"
    "unhandledRejection" "Cannot find module" "ERR_SOCKET_BAD_PORT"
  )
  local pat
  for pat in "${fatal_patterns[@]}"; do
    if printf '%s\n' "$gw_logs" | grep -qi "$pat"; then
      echo "Error: gateway logs contain '${pat}' — the gateway may have crashed." >&2
      return 1
    fi
  done
  echo "No fatal errors found in gateway logs."
  return 0
}

check_gateway_config() {
  local config_file="$TARGET_DIR/config/openclaw.json"
  if [[ ! -f "$config_file" ]]; then
    echo "Warning: openclaw.json not found; skipping config validation." >&2
    return 0
  fi
  echo "Validating gateway config..."
  if ! python3 -c '
import json, sys
path = sys.argv[1]
errors = []
with open(path) as f:
    c = json.load(f)
gw = c.get("gateway", {})

auth = gw.get("auth", {})
mode = auth.get("mode", "")
if mode != "trusted-proxy":
    errors.append("gateway.auth.mode is \"" + mode + "\", expected \"trusted-proxy\"")
header = auth.get("trustedProxy", {}).get("userHeader", "")
if not header:
    errors.append("gateway.auth.trustedProxy.userHeader is not set")
proxies = gw.get("trustedProxies", [])
if not proxies:
    errors.append("gateway.trustedProxies list is empty")

ui = gw.get("controlUi", {})
if not ui.get("allowInsecureAuth"):
    errors.append("gateway.controlUi.allowInsecureAuth is not true")

if errors:
    for e in errors:
        print("Error: " + e, file=sys.stderr)
    sys.exit(1)

print("Gateway config OK: auth=trusted-proxy, header=" + header
      + ", proxies=" + str(proxies) + ", allowInsecureAuth=true")
' "$config_file" 2>&1; then
    echo "Error: gateway config validation failed." >&2
    return 1
  fi
  return 0
}

gateway_exec_cli() {
  # Run an openclaw CLI command THROUGH CADDY so the request gets
  # X-Forwarded-User from Basic Auth — required for trusted-proxy auth.
  #
  # Bug #17761: trusted-proxy mode blocks direct connections (loopback) that
  # don't go through the proxy. Routing CLI through Caddy works around this.
  #
  # We URL-encode the password to handle special characters in the WS URL.
  # Clean HOME avoids stale device tokens from the shared config volume.
  local encoded_pass
  encoded_pass="$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=""))' "${CADDY_PASSWORD}")"

  docker exec -u node openclaw-gateway \
    env HOME=/tmp/openclaw-cli-approve \
    node dist/index.js "$@" \
    --url "ws://${CADDY_USER}:${encoded_pass}@caddy:18789" \
    --token "${OPENCLAW_GATEWAY_TOKEN}"
}

auto_approve_devices() {
  # Docker NAT makes browser connections appear non-local (172.18.x.x instead
  # of 127.0.0.1), so the gateway's auto-approval never fires and the browser
  # gets "pairing required" (1008). This loop runs inside the gateway container
  # via loopback and auto-approves pending device requests as they appear.
  local duration_s="${1:-120}"
  local interval_s=3
  local elapsed=0

  echo "Starting device auto-approval (${duration_s}s window)..."
  echo "Open the dashboard in your browser — the device will be approved automatically."

  while [[ "$elapsed" -lt "$duration_s" ]]; do
    if gateway_exec_cli devices approve --latest >/dev/null 2>&1; then
      echo "Device approved successfully."
      return 0
    fi
    sleep "$interval_s"
    elapsed=$((elapsed + interval_s))
  done

  echo "Warning: no pending device requests appeared within ${duration_s}s." >&2
  echo "Hint: open the dashboard, then run: $SCRIPT_NAME approve" >&2
  return 1
}

run_approve() {
  load_env
  echo "Approving the latest pending device..."
  if gateway_exec_cli devices approve --latest 2>&1; then
    echo "Device approved. Refresh the dashboard."
  else
    echo "Listing pending devices..."
    gateway_exec_cli devices list 2>&1 || true
    echo
    echo "No pending devices found. Open the dashboard first, then re-run: $SCRIPT_NAME approve"
  fi
}

run_pairing_approve_telegram() {
  local code="${1:-}"
  if [[ -z "$code" ]]; then
    echo "Usage: $SCRIPT_NAME pairing approve telegram <CODE>" >&2
    echo "Get the 8-character code from the Telegram message from your bot." >&2
    echo "Codes expire after 1 hour." >&2
    exit 1
  fi
  load_env
  echo "Approving Telegram pairing code: $code"
  compose_cmd run --rm openclaw-cli pairing approve telegram "$code" 2>&1
}

run_health_checks() {
  local port="${OPENCLAW_GATEWAY_PORT:-18789}"
  local max_attempts=20
  local sleep_s=2
  local attempt=1
  local failed=0

  # Step 1: verify both containers are in running state.
  ensure_services_running

  # Step 2: wait for the Caddy HTTP endpoint to respond.
  echo "Waiting for Caddy endpoint http://127.0.0.1:${port}/ ..."
  while [[ "$attempt" -le "$max_attempts" ]]; do
    if curl -fsS -u "${CADDY_USER}:${CADDY_PASSWORD}" "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
      echo "Caddy endpoint is up."
      break
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

  # Step 3: verify the gateway responds directly inside Docker network (not just Caddy).
  if ! check_gateway_direct; then
    dump_compose_diagnostics
    return 1
  fi

  # Step 4: try known API/health endpoints.
  check_gateway_api "$port"

  # Step 5: verify gateway accepts authenticated requests (Bearer token through Caddy).
  if ! check_gateway_auth "$port"; then
    dump_compose_diagnostics
    failed=1
  fi

  # Step 6: detect crash loops.
  if ! check_crash_loop; then
    dump_compose_diagnostics
    return 1
  fi

  # Step 7: scan gateway logs for fatal/crash indicators.
  if ! check_gateway_logs; then
    dump_compose_diagnostics
    return 1
  fi

  # Step 8: validate gateway config (trusted-proxy auth + allowInsecureAuth).
  if ! check_gateway_config; then
    dump_compose_diagnostics
    failed=1
  fi

  if [[ "$failed" -ne 0 ]]; then
    return 1
  fi

  echo "All health checks passed."
  return 0
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

check_lan_access() {
  local port="$1"
  local localhost_ok=0
  local lan_ok=0
  local lan_ip=""

  if curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 \
      -u "${CADDY_USER}:${CADDY_PASSWORD}" \
      "http://127.0.0.1:${port}/" 2>/dev/null | grep -q 200; then
    localhost_ok=1
  fi

  lan_ip="$(collect_host_ipv4 | head -1)"
  if [[ -n "$lan_ip" ]]; then
    if curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 \
        -u "${CADDY_USER}:${CADDY_PASSWORD}" \
        "http://${lan_ip}:${port}/" 2>/dev/null | grep -q 200; then
      lan_ok=1
    fi
  fi

  if [[ "$localhost_ok" -eq 1 && "$lan_ok" -eq 0 && -n "$lan_ip" ]]; then
    echo >&2
    echo "================================================================" >&2
    echo " LAN access not available (Docker Desktop Mac)" >&2
    echo "================================================================" >&2
    echo " Dashboard works on localhost but not on http://${lan_ip}:${port}/" >&2
    echo " Docker Desktop binds published ports to localhost only by default." >&2
    echo >&2
    echo " To enable LAN access:" >&2
    echo "   1. Docker Desktop → Settings (gear icon)" >&2
    echo "   2. Resources → Network" >&2
    echo "   3. Port binding behavior → set to 'Bind to all interfaces'" >&2
    echo "      (or disable 'Only bind to localhost when exposing ports')" >&2
    echo "   4. Apply & Restart" >&2
    echo "   5. Re-run: $SCRIPT_NAME install" >&2
    echo "================================================================" >&2
    return 1
  fi
  return 0
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
  write_entrypoint_script
  write_requirements_template
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

  echo "Verifying OpenRouter auth (small live probe)..."
  compose_cmd run --rm openclaw-cli models status --probe --probe-provider openrouter --probe-max-tokens 8 >/dev/null

  if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]]; then
    echo "Configuring Telegram channel..."
    try_configure_telegram_channel "$TELEGRAM_BOT_TOKEN" || true
  fi

  # Must run AFTER all openclaw-cli config set commands — the CLI may overwrite the JSON
  # and drop fields it doesn't know about.
  configure_gateway_auth

  echo "Restarting gateway to apply final config..."
  compose_cmd restart openclaw-gateway
  # Give the gateway a moment to fully come up before probing.
  sleep 3

  echo "Running post-install checks..."
  if ! run_health_checks; then
    echo "Warning: post-install checks failed. OpenClaw may still be running; see diagnostics above." >&2
  fi

  local port="${OPENCLAW_GATEWAY_PORT:-18789}"
  echo
  echo "================================================================"
  echo " OpenClaw is up.  Open the dashboard to complete setup."
  echo "================================================================"
  echo
  echo "Access URLs (IPv4):"
  echo "  http://localhost:${port}/"
  while IFS= read -r ipv4; do
    [[ -z "$ipv4" ]] && continue
    echo "  http://${ipv4}:${port}/"
  done < <(collect_host_ipv4)
  echo
  echo "Login (Basic Auth):"
  echo "  Username: ${CADDY_USER}"
  echo "  Password: value from ${ENV_FILE} -> CADDY_PASSWORD"
  echo
  check_lan_access "$port" || true
  echo "================================================================"
  echo

  # Auto-approve the browser device. Docker NAT prevents auto-approval, so we
  # run a loopback-based approval loop while the user opens the dashboard.
  auto_approve_devices 120 || true

  echo
  echo "================================================================"
  echo "If you see 'pairing required' later, run:"
  echo "  $SCRIPT_NAME approve"
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
    approve)
      run_approve
      ;;
    pairing)
      if [[ "${2:-}" == "approve" && "${3:-}" == "telegram" ]]; then
        run_pairing_approve_telegram "${4:-}"
      else
        echo "Usage: $SCRIPT_NAME pairing approve telegram <CODE>" >&2
        exit 1
      fi
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
