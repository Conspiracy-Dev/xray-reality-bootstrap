# Xray Reality Bootstrap

Развёртывание Xray на собственном Linux VPS через Docker Compose. Один контейнер принимает VLESS TCP/Vision на 443/tcp и VLESS gRPC на 34241/tcp. Для каждого транспорта генерируются отдельные UUID, short ID и пара ключей REALITY. Docker загружает официальный образ XTLS по digest из `deploy/docker/compose.yaml`. В образ ничего встраивать не требуется.

## 1. Подготовьте VPS

Нужны Linux VPS с публичным IPv4, SSH и sudo, Python 3.10+, обычный Docker Engine с плагином Compose и доступ к GHCR. Откройте входящие 443/tcp и 34241/tcp в панели провайдера и firewall VPS. Создайте DNS-запись A своего VPN-домена на IPv4 сервера. Для REALITY выберите отдельный HTTPS-домен, доступный с VPS по TCP 443, с действительным сертификатом, TLS 1.3 и HTTP/2.

Получите код с помощью своего GitHub-аккаунта. Можно клонировать репозиторий на своей машине и передать на VPS через SSH только содержимое коммита. В примере ниже замените значение SSH-адреса. Каталог назначения должен быть новым.

```sh
git clone https://github.com/Conspiracy-Dev/xray-reality-bootstrap.git
cd xray-reality-bootstrap
read -r -p 'Пользователь и адрес VPS (user@host): ' VPS_USER_HOST
git archive HEAD | ssh "$VPS_USER_HOST" 'mkdir -m 700 ~/xray-bootstrap && tar -xf - -C ~/xray-bootstrap'
ssh "$VPS_USER_HOST"
```

Для Terminal на Mac с оболочкой zsh в предыдущем блоке сначала запустите `bash`. Далее команды выполняются **на VPS** в Bash под пользователем с доступом к Docker.

```sh
cd ~/xray-bootstrap
read -r -p 'Ваш VPN-домен: ' VPN_DOMAIN
read -r -p 'HTTPS-домен для REALITY: ' REALITY_TARGET
getent ahostsv4 "$VPN_DOMAIN"
openssl s_client -connect "${REALITY_TARGET}:443" -servername "$REALITY_TARGET" \
  -tls1_3 -alpn h2 -verify_hostname "$REALITY_TARGET" -verify_return_error </dev/null
ss -lnt '( sport = :443 or sport = :34241 )'
```

Сверьте IPv4 с панелью провайдера. В выводе TLS ожидаются успешная проверка сертификата и `ALPN protocol: h2`. Оба входных порта должны быть свободны.

## 2. Создайте доступы своего сервера

```sh
STATE="$HOME/.local/share/xray-reality/$VPN_DOMAIN"
python3 tools/init_node.py --endpoint "$VPN_DOMAIN" --target "$REALITY_TARGET" --state "$STATE"
```

Инициализация создаёт новый закрытый каталог. Существующий каталог защищён от повторной инициализации. Сохраните зашифрованную резервную копию `node.json` и `node-secrets.json` в своём хранилище. Для восстановления профилей с прежними ключами используйте `python3 tools/render_config.py render --manifest "$STATE/node.json" --secrets "$STATE/node-secrets.json" --output "$STATE/runtime"`.

## 3. Проверьте конфигурацию и запустите Xray

Для одного экземпляра на VPS используем каталоги /etc/xray-bootstrap и /var/log/xray-bootstrap. Следующий блок предназначен для первого запуска на чистом сервере. Файл с конфигурацией читает контейнерный UID 65532.

```sh
(
  set -eu
  sudo mkdir -m 0700 /etc/xray-bootstrap
  sudo install -m 0400 -o 65532 -g 65532 "$STATE/runtime/xray-server.json" /etc/xray-bootstrap/server.json
  sudo install -d -m 0750 -o 65532 -g 65532 /var/log/xray-bootstrap
  umask 077
  printf '%s\n' 'VPN_CONFIG_FILE=/etc/xray-bootstrap/server.json' 'VPN_LOG_DIR=/var/log/xray-bootstrap' > "$STATE/compose.env"
  dc() { docker compose -p xray-bootstrap --env-file "$STATE/compose.env" -f deploy/docker/compose.yaml "$@"; }
  dc config --quiet
  dc run --rm --no-deps --pull never xray run -test -config /run/conspiracy-ray/server.json
  dc up -d --pull never
  dc ps
)
```

В тесте ожидается `Configuration OK.`, в списке контейнеров — работающий сервис `xray`. Для последующих операций из каталога проекта используйте `docker compose -p xray-bootstrap --env-file "$STATE/compose.env" -f deploy/docker/compose.yaml ps`. Для остановки замените `ps` на `stop`.

**Для уже работающего узла.** В этой версии изменились пути внутри контейнера. При обновлении пересоздайте серверный JSON из сохранённых `node.json` и `node-secrets.json` по команде из шага 2, повторите установку файла в `/etc/xray-bootstrap/server.json` и проверку `xray run -test` из шага 3, затем выполните `dc up -d --pull never` с новым Compose. Существующие клиентские профили продолжат работать с прежними ключами.

## 4. Подключите клиент

Передавайте клиенту по SSH или AirDrop только файл нужного профиля из `$STATE/runtime`. Профиль даёт доступ к этому узлу. `node-secrets.json` и серверные JSON содержат приватные ключи и остаются у администратора.

| Клиент | Файлы и импорт |
|---|---|
| Podkop | `sing-box-tcp.json` или `sing-box-grpc.json` как outbound. Списки маршрутизации задаются на роутере. |
| RabbitHole на iOS | `rabbithole-tcp.yaml` или `rabbithole-grpc.yaml`. Импортируйте через Configs → + → YAML. Правило MATCH направляет трафик профиля в выбранный транспорт. |
| Husi на Android | Импортируйте `vless-tcp.uri` или `vless-grpc.uri` из буфера. Совместимость gRPC зависит от клиента и сети, проверьте её на своём устройстве. |

Откройте https://api.ipify.org через каждый профиль и сравните результат с IPv4 выхода своего VPS. В Podkop для проверки адреса направьте тестовый домен через VPN. При раздельной маршрутизации отдельно проверьте прямой маршрут.

## Проверка изменений

```sh
python3 -m unittest discover -s tests -q
python3 tests/smoke_compose.py
```

Smoke-тест использует одноразовые ключи, проверяет `xray run -test`, запуск контейнера, оба порта на loopback, монтирование и отсутствие тестовых секретов в метаданных Docker. При обновлении digest образа повторите также проверку обоих клиентов.
