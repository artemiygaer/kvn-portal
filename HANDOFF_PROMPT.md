# Промт для передачи KVN VPN v3 новому ИИ-агенту

Ты продолжаешь разработку проекта KVN VPN v3. Работай автономно до проверенного
результата, но не расширяй задачу за пределы запроса пользователя. Отвечай
по-русски, коротко и по делу. Комментарии, документацию и сообщения интерфейса
пиши на русском.

## Начало работы на Windows

Не используй жёстко заданный путь или букву диска. Корень проекта — каталог,
в котором одновременно находятся `AGENTS.md`, `docker-compose.yml`, `setup.sh`,
`portal/` и `tools/`.

1. Определи корень из текущего workspace и перейди в него.
2. Если корень нельзя определить однозначно, только тогда попроси пользователя
   указать каталог проекта.
3. Полностью прочитай `AGENTS.md`. Затем открой относящиеся к задаче разделы
   `README.md`, `deploy/DEPLOY.md`, `PROJECT_AUDIT.md`, `MTPROTO.md`,
   `CONTAINER_SECURITY.md` и `PORTAL_UPDATE_NOTES.md`.
4. Выполни `git status --short`, `git remote -v` и `git log -3 --oneline`.
   Существующие изменения принадлежат пользователю: не удаляй и не откатывай их.
5. На Windows используй PowerShell. Для shell-скриптов используй Git Bash,
   для Linux/root-проверок — WSL, для контейнеров — Docker Desktop.
6. Не полагайся на наличие команды `python3` в Windows. Найди доступный Python
   через `Get-Command python` или `py -3`; включи UTF-8:

```powershell
$env:PYTHONIOENCODING = 'utf-8'
$ProjectRoot = (Resolve-Path .).Path
$PythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
$PythonArgs = @()
if ($PythonCommand) {
    $Python = $PythonCommand.Source
} else {
    $Python = (Get-Command py.exe -ErrorAction Stop).Source
    $PythonArgs = @('-3')
}
```

WSL-путь всегда вычисляй из текущего Windows-пути:

```powershell
$PortableRoot = $ProjectRoot.Replace('\', '/')
$WslRoot = (wsl.exe wslpath -a -u $PortableRoot).Trim()
wsl.exe -u root bash -lc "cd '$WslRoot' && python3 -m unittest discover -s tests -v"
```

Не запускай интерактивные команды в видимом отдельном окне. Не проси повторного
разрешения на обычные проверки, сборку и изменения внутри проекта.

## Архитектура и назначение

KVN VPN v3 — мультипротокольный VPN-стек для Debian 12/13.

- Compose: nginx SNI-router, portal, portal-gateway, Xray, Hysteria2, Telemt,
  mtg FakeTLS и ocserv.
- Host-службы Debian: `kvn-amneziawg.service`, `kvn-wireguard.service`,
  `kvn-portal-agent.service`.
- `users.json` — единственный source of truth.
- Web-портал работает непривилегированным контейнером без Docker socket.
- Привилегированные операции разрешены только через versioned allowlisted RPC
  host-agent по Unix socket.
- Setup, update, portal apply и reconcile используют единый effective service
  plan. Отключённый сервис не должен самопроизвольно запускаться.
- Peer-only изменения AWG/WG применяются через `syncconf`; structural delta —
  через controlled restart.
- Full release позволяет слабому Debian-серверу применить обновление через
  `--no-build --pull never`.

Поддерживаемые `systems`: `tls`, `reality-xhttp`, `reality-tcp`, `hysteria`,
`telemt`, `mtg`, `amneziawg`, `wireguard`, `ocserv`.

## Неприкосновенные границы

- Сначала изучай код вокруг задачи, затем меняй его минимально необходимым
  способом.
- Не редактируй вручную generated/runtime-файлы, перечисленные в `AGENTS.md`.
- Не включай в git, deploy, логи и ответы: production `users.json`, `clients/`,
  приватные ключи, сертификаты, `.env`, БД/WAL/SHM, sockets, agent secret,
  GitHub token, backup и содержимое пользовательских конфигураций.
- Не монтируй Docker socket в портал.
- Не передавай root/GitHub/Telegram credentials через браузер, argv, git,
  документацию или чат.
- `/backup` содержит runtime-секреты и Docker images.
- Предпочитай hot update/reload. Restart выполняй только при технической
  необходимости.
- Не удаляй пользовательский runtime. Разрешено удалять только проверенные кеши,
  временные тестовые каталоги и сборочные артефакты.
- Не используй `git reset --hard`, принудительное переписывание чужих изменений
  или перемещение опубликованного release tag.

## Реализованный функционал

- Portal разделён на совместимые Flask Blueprints и page-specific JS.
- Есть light profile, lazy inline-логи сервисов, история нагрузки и безопасная
  активность пользователей.
- Кнопка «Экспорт» создаёт allowlisted ZIP в памяти и `send.txt` для ручной
  отправки через Telegram. Прямого Telegram API и bot token нет.
- Domain/public-IP policy применяется ко всем клиентским endpoint.
- `public-ip` меняет endpoint, но не SNI, Reality `serverName` и certificate
  identity. HTTPS subscription по IP требует direct route и точный IP SAN.
- Legacy `/<token>`, отдельные HAPP/Karing endpoints и Karing Clash-профиль
  standard WireGuard сохранены.
- Standard WireGuard работает на `wg0:51821`; AmneziaWG — только на
  `awg0:51820`. Эти профили нельзя подменять друг другом.
- GitHub-источник обновлений зафиксирован как `artemiygaer/kvn-portal`.
  Поток обновления: check → download/verify → ready → отдельный start с
  повторной root-аутентификацией.
- Ручная загрузка и GitHub Release используют один archive validator и updater.
- Deploy строится только из `tools/canonical-files.txt`.

## Статус на момент передачи

Проверенный baseline от 26.07.2026:

- 339 тестов проекта прошли локально, 18 Debian/Linux-only проверок пропущены;
- 94 portal tests прошли в Docker test image;
- deploy runtime E2E прошёл;
- Bash syntax, Compose config, compileall, docs checker и source safety прошли;
- browser matrix 1440/390 px, светлая/тёмная темы: без горизонтального
  переполнения, обрезанных кнопок и ошибок консоли;
- full release: `linux/amd64`, семь runtime images, build ID
  `20260726-release3`;
- публичный Release `v3.0.3` опубликован из commit `9ae03b1`;
- `v3.0.2` помечен как неподходящий для full update на Docker/containerd:
  verifier мог ложно отклонить корректный `kvn-portal:local` до изменения source.

Workflow `.github/workflows/release.yml` запускается только вручную, создаёт
проверяемый draft и публикует его после проверки всех четырёх assets.

Этот файл мог быть изменён после последней сборки. Поэтому не публикуй лежащие
рядом архивы, пока не проверишь, что их embedded source совпадает с текущим
canonical deploy через `tools/publication_manifest.py`. При несовпадении собери
новые артефакты с новым build ID и новым version tag.

## Release и публикация

Публичный набор Release должен содержать только:

- `kvn-vpn-release-linux-amd64.tar.gz`;
- `kvn-vpn-deploy.tar.gz`;
- `publication-manifest.json`;
- `SHA256SUMS`.

Публичный репозиторий работает без token:

```bash
sudo python3 tools/kvnctl.py updates configure \
  --enable true --channel stable --asset-preference release --clear-token
sudo python3 tools/kvnctl.py updates status
```

Если репозиторий снова станет private, token создаётся только на Debian-сервере:

```bash
sudo python3 tools/kvnctl.py updates configure \
  --enable true --channel stable --asset-preference release --set-token
sudo python3 tools/kvnctl.py updates status
```

Token вводится через `getpass`, хранится в `/etc/kvn-portal/github.token` с
root-only правами и не выводится.

Перед созданием нового Release:

1. Проверь чистоту source через `tools/source_safety.py`.
2. Убедись, что commit отправлен в `main`.
3. Не перемещай tag уже опубликованного immutable Release.
4. Собери full release и отдельный deploy из одного source state/build ID.
5. Проверь совпадение source и точный состав assets.
6. Создай draft, загрузи все четыре файла, сверь их и только затем публикуй.
7. После публикации проверь latest Release API и portal `release.check`.

## Обновление Debian-сервера

Команды ниже выполняются из фактического корня установленного проекта, каким бы
он ни был:

```bash
sudo ./tools/project-backup.sh
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
sudo python3 tools/kvnctl.py amneziawg verify
sudo python3 tools/kvnctl.py wireguard verify
sudo docker compose -f docker-compose.yml ps
```

Для старого updater:

```bash
sudo ./update.sh --bootstrap-only ./kvn-vpn-deploy.tar.gz
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

Не распаковывай шаблонный `deploy/users.json` поверх production.

## Полный gate на Windows

Используй найденные пути к Python и Git Bash, не копируй чужие абсолютные пути:

```powershell
$env:PYTHONIOENCODING = 'utf-8'
$PythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
$PythonArgs = @()
if ($PythonCommand) {
    $Python = $PythonCommand.Source
} else {
    $Python = (Get-Command py.exe -ErrorAction Stop).Source
    $PythonArgs = @('-3')
}
& $Python @PythonArgs -m py_compile tools\kvnctl.py
& $Python @PythonArgs -m compileall -q portal tools
& $Python @PythonArgs tools\docs_check.py
& $Python @PythonArgs tools\source_safety.py --mode worktree
& $Python @PythonArgs -m unittest discover -s tests -v

$GitExe = (Get-Command git.exe -ErrorAction Stop).Source
$GitRoot = Split-Path (Split-Path $GitExe -Parent) -Parent
$Bash = Join-Path $GitRoot 'bin\bash.exe'
if (-not (Test-Path -LiteralPath $Bash)) {
    throw 'Git Bash не найден'
}
& $Bash -n setup.sh update.sh tools/*.sh amneziawg/*.sh wireguard/*.sh ocserv/*.sh portal/*.sh

docker compose -f docker-compose.yml config --quiet
docker build --target test -t kvn-portal:test portal
& $Python @PythonArgs tools\kvnctl.py render
& $Python @PythonArgs tests\deploy_runtime_e2e.py
```

Linux/root suite:

```powershell
$ProjectRoot = (Resolve-Path .).Path
$PortableRoot = $ProjectRoot.Replace('\', '/')
$WslRoot = (wsl.exe wslpath -a -u $PortableRoot).Trim()
wsl.exe -u root bash -lc "cd '$WslRoot' && PYTHONIOENCODING=utf-8 python3 -m unittest discover -s tests -v"
```

Сборка выполняется только после проверок и только когда действительно нужны
новые артефакты:

```powershell
& $Bash -c 'bash tools/build-deploy.sh'
$env:KVN_BUILD_ID = 'YYYYMMDD-releaseN'
& $Bash -c 'bash tools/build-release.sh'
```

Не записывай промежуточные SHA в документацию. Финальные SHA сообщай только
после последней сборки и повторной проверки manifest.

## Ограничения локальной проверки

На Windows нельзя считать проверенными Debian systemd units, Unix socket
ownership, host/cloud firewall, Certbot HTTP-01/IP profile и доступность у
конкретного мобильного оператора. Проверяй их на Debian-сервере. Успешная
server-side SNI-диагностика не гарантирует доступность у другого оператора РФ.

## Формат завершения следующей задачи

В ответе кратко укажи:

- что изменено;
- какие проверки фактически выполнены и их результат;
- какие проверки возможны только на Debian;
- какие файлы/commit/tag/Release созданы;
- точную следующую команду пользователя только при реальной внешней блокировке.

Не объявляй работу завершённой, если обязательные проверки не пройдены или
Release/серверное применение только предполагаются.
