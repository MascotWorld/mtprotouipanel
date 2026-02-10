# MTProto Proxy Admin Panel (Docker Compose)

Веб-панель для админ-управления `mtproxy/mtproxy`:
- создание/редактирование/удаление клиентов;
- `secret` режимы: `secure`, `fake_tls`, `plain`, `custom`;
- сроки действия с пресетами (7 дней, 1/3/6 месяцев, 1 год) и кастомной датой;
- авто-удаление просроченных клиентов;
- готовая ссылка подключения `https://t.me/proxy?server=...&port=...&secret=...` для каждого клиента;
- автоматическая синхронизация `SECRET` и пересоздание контейнера прокси.

## 1. Настройка

Склонировать репозиторий (папка `mtprotouipanel` создастся автоматически):

```bash
git clone git@github.com:MascotWorld/mtprotouipanel.git
cd mtprotouipanel
```

Измените в `docker-compose.yml` логин/пароль админки:

```yaml
services:
  panel:
    environment:
      ADMIN_LOGIN: "admin"
      ADMIN_PASSWORD: "change-me-now"
      SESSION_SECRET: "change-this-session-secret"
```

Порты панели и прокси задаются через переменные в `.env`:

```bash
cp .env.example .env
```

Минимально:

```env
PANEL_PORT=8080
PROXY_PORT=3443
PROXY_HTTP_PORT=8888
PROXY_PUBLIC_HOST=
PROXY_PUBLIC_PORT=3443
MTP_WORKERS=2
MTP_TAG=
DEFAULT_FAKE_TLS_HOST=google.com
MAX_PROXY_SECRETS=16
PUBLIC_IP_REFRESH_SECONDS=900
```

`PROXY_PUBLIC_HOST` и `PROXY_PUBLIC_PORT` используются для генерации ссылки в панели.
Если `PROXY_PUBLIC_HOST` пустой, панель автоматически определяет внешний IP через публичные сервисы
(`ipify`/`ifconfig.me`/`icanhazip`) и периодически обновляет его.

## 2. Запуск

```bash
docker compose up -d --build
```

Открыть панель:
- `http://localhost:<PANEL_PORT>`
- по умолчанию `http://localhost:8080`

## 3. Как это работает

- Панель хранит клиентов в `panel_data` (volume).
- Панель генерирует файл `proxy/mtproxy.env` с актуальным `SECRET` (список 32-hex secret через запятую, до `MAX_PROXY_SECRETS`).
- После изменений клиентов панель выполняет:

```bash
docker compose -p mtprotouipanel -f /opt/stack/docker-compose.yml up -d --force-recreate mtproxy
```

- Просроченные клиенты автоматически удаляются каждые `CLEANUP_INTERVAL_SECONDS` (по умолчанию 60 сек).

## 4. Важно по безопасности

Панель монтирует Docker socket (`/var/run/docker.sock`) для управления контейнером прокси. Это дает расширенные права контейнеру панели. Используйте только в доверенной среде.

## 5. Формат секретов

- `plain`: случайный 16-байтный hex (`32` символа)
- `secure`: `ee` + случайный hex
- `fake_tls`: `dd` + случайный hex + hex(SNI host)
- `custom`: вручную `32 hex` или `ee/dd + 32 hex`

`MTP_TAG` для `mtproxy/mtproxy` опционален.

## 6. Сброс данных клиентов

Удалите volume панели:

```bash
docker compose down
docker volume rm mtprotouipanel_panel_data
```
