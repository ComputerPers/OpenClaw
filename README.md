# OpenClaw Docker Installer (macOS/Linux)

Скрипт поднимает OpenClaw в Docker с доступом к админке из локальной сети через Caddy + Basic Auth.

## Быстрый старт (одна команда)

```bash
curl -fsSL https://raw.githubusercontent.com/ComputerPers/OpenClaw/master/install-openclaw.sh -o install-openclaw.sh && chmod +x install-openclaw.sh && ./install-openclaw.sh install
```

## Что сделает инсталлятор

- создаст рабочую среду в `~/OpenClawEnvironment` (или в `OPENCLAW_ENV_DIR`, если задан);
- создаст структуру каталогов: `config`, `workspace`, `caddy`, `python-packages`, `scripts`;
- скачает из GitHub или создаст локально:
  - `Dockerfile.openclaw-python` — кастомный образ с Python и pip3
  - `entrypoint.sh` — скрипт автоустановки Python пакетов при старте
  - `requirements.txt` — список Python пакетов (`python-docx`, `python-pptx`)
- соберет кастомный Docker образ `openclaw-python:local` с предустановленным Python (один раз, 2-3 минуты);
- сгенерирует `docker-compose.yml` c сервисами `openclaw-gateway`, `openclaw-cli`, `caddy`;
- создаст `.env`-шаблон (права `600`) для ключей и параметров;
- сгенерирует `OPENCLAW_GATEWAY_TOKEN`, если он не задан;
- создаст `caddy/Caddyfile` с bcrypt-хешем пароля для Basic Auth;
- подтянет Docker-образы и запустит контейнеры;
- установит модель через OpenRouter (по умолчанию `openrouter/google/gemini-3-flash-preview`) и проверит ключ OpenRouter коротким live-probe;
- автоматически установит Python пакеты из `requirements.txt` в постоянный volume;
- выведет локальный и LAN URL для доступа к админке.

## Важно при первом запуске

Если `.env` только что создан, заполните как минимум:

- `OPENROUTER_API_KEY`
- `CADDY_PASSWORD`

Инсталлятор также умеет сам запросить эти значения интерактивно при первом запуске.
Инсталлятор запрашивает только недостающие значения из `.env`.
Если модель не задана, он попросит её ввести; по умолчанию используется `openrouter/google/gemini-3-flash-preview`.
Telegram-токен скрипт запрашивает напрямую (скрытый ввод); можно просто нажать Enter, чтобы пропустить этот шаг.

Примечание: по умолчанию используется `CADDY_IMAGE=caddy:2-alpine`, но инсталлятор умеет автоматически переключиться на `ghcr.io/caddyserver/caddy:2-alpine`, если Docker Hub недоступен (и наоборот).

После этого снова запустите:

```bash
./install-openclaw.sh install
```

## Дополнительные команды

Проверить статус:

```bash
./install-openclaw.sh status
```

Подключить Telegram (если задан `TELEGRAM_BOT_TOKEN` в `.env`):

```bash
./install-openclaw.sh telegram
```

### Одобрить pairing Telegram (код из сообщения бота)

Когда бот присылает 8-символьный код (например, `WZXXHBZ1`) для pairing, выполните:

```bash
./install-openclaw.sh pairing approve telegram WZXXHBZ1
```

Замените `WZXXHBZ1` на ваш код. Коды действительны 1 час.

## Как начать работать после установки

- **Через Web UI:** откройте `http://localhost:18789` (или `http://<IP_вашего_Mac>:18789` из LAN), пройдите Basic Auth, затем в Dashboard подключитесь к Gateway.
- **Через Telegram:** если токен задан, просто напишите вашему боту в Telegram и начните диалог с OpenClaw.
- **Если Telegram не подключен:** добавьте токен в `~/OpenClawEnvironment/.env` (`TELEGRAM_BOT_TOKEN=...`) и выполните `./install-openclaw.sh telegram`.
- **При повторном запуске:** инсталлятор перезаписывает конфиги, перезапускает контейнеры и выполняет post-install проверку доступности сервисов.

## Python пакеты

Инсталлятор автоматически настраивает поддержку Python с установкой пакетов:

- **Автоматическая установка:** при первом запуске собирается кастомный образ `openclaw-python:local` с Python и pip3
- **Persistent storage:** установленные пакеты сохраняются в `~/OpenClawEnvironment/python-packages/`
- **Управление пакетами:** редактируйте `~/OpenClawEnvironment/config/requirements.txt` и перезапустите контейнеры

### Добавление Python пакетов

1. Отредактируйте `~/OpenClawEnvironment/config/requirements.txt`:
   ```txt
   python-docx
   python-pptx
   pandas
   requests
   ```

2. Перезапустите контейнеры:
   ```bash
   cd ~/OpenClawEnvironment
   docker compose restart
   ```

Пакеты установятся автоматически при старте и не пропадут при перезапуске.
