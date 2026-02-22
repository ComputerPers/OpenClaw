# OpenClaw Docker Installer (macOS/Linux)

Скрипт поднимает OpenClaw в Docker с доступом к админке из локальной сети через Caddy + Basic Auth.

## Быстрый старт (одна команда)

```bash
curl -fsSL https://raw.githubusercontent.com/ComputerPers/OpenClaw/master/install-openclaw.sh -o install-openclaw.sh && chmod +x install-openclaw.sh && ./install-openclaw.sh install
```

## Что сделает инсталлятор

- создаст рабочую среду в `~/OpenClawEnvironment` (или в `OPENCLAW_ENV_DIR`, если задан);
- создаст структуру каталогов: `config`, `workspace`, `caddy`;
- сгенерирует `docker-compose.yml` c сервисами `openclaw-gateway`, `openclaw-cli`, `caddy`;
- создаст `.env`-шаблон (права `600`) для ключей и параметров;
- сгенерирует `OPENCLAW_GATEWAY_TOKEN`, если он не задан;
- создаст `caddy/Caddyfile` с bcrypt-хешем пароля для Basic Auth;
- подтянет Docker-образы и запустит контейнеры;
- выполнит onboarding для OpenRouter и установит модель:
  - `openrouter/google/gemini-3-flash-preview`;
- выведет локальный и LAN URL для доступа к админке.

## Важно при первом запуске

Если `.env` только что создан, заполните как минимум:

- `OPENROUTER_API_KEY`
- `CADDY_PASSWORD`

Инсталлятор также умеет сам запросить эти значения интерактивно при первом запуске.
При установке он опционально предлагает выбрать модель OpenRouter; по умолчанию используется `openrouter/google/gemini-3-flash-preview`.

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
