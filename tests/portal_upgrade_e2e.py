#!/usr/bin/env python3
"""Реальное обновление опубликованного v4.0.1 через HTTPS-портал в отдельном Docker daemon."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
BASELINE_SHA = "a26816589796c3a32e4a9d6777b9993ae3c5ddc745c9d4eea8b5609665b7073b"
BASELINE_URL = "https://github.com/artemiygaer/kvn-portal/releases/download/v4.0.1/kvn-vpn-release-linux-amd64.tar.gz"
NAME = "kvn-portal-upgrade-e2e"
LOGIN_PASSWORD = "UpgradePortal-Test-2026"
ROOT_PASSWORD = "UpgradeRoot-Test-2026"

# Systemd отсутствует в Docker Desktop. Shim только управляет agent PID и
# transient updater; все проверки архива, HTTP/RPC, Docker load и Compose реальные.
SYSTEMCTL = r'''#!/usr/bin/python3
import os, signal, subprocess, sys, time
from pathlib import Path
args=sys.argv[1:]
command=args[0] if args else ''
agent='kvn-portal-agent.service' in args
pidfile=Path('/test/agent.pid')
if command=='list-unit-files': sys.exit(0 if agent else 1)
if command=='is-active':
    try: os.kill(int(pidfile.read_text()),0); sys.exit(0 if agent else 3)
    except (OSError,ValueError): sys.exit(3)
if command in ('restart','start') and agent:
    if pidfile.exists():
        try: os.kill(int(pidfile.read_text()),signal.SIGTERM); time.sleep(.3)
        except (OSError,ValueError): pass
    Path('/run/kvn-portal').mkdir(exist_ok=True)
    os.chown('/run/kvn-portal',0,12345); os.chmod('/run/kvn-portal',0o750)
    log=open('/test/agent.log','ab')
    process=subprocess.Popen(['/usr/bin/python3','/project/portal/agent.py','--project-root','/project',
        '--socket','/run/kvn-portal/control.sock','--secret-file','/etc/kvn-portal/agent.secret',
        '--socket-group','kvn-portal','--metrics-db','/var/lib/kvn-portal/metrics.db'],
        stdout=log,stderr=log,start_new_session=True)
    pidfile.write_text(str(process.pid)); sys.exit(0)
if command in ('enable','disable','daemon-reload','show','status'): sys.exit(0)
sys.exit(1)
'''
SYSTEMD_RUN = r'''#!/usr/bin/python3
import subprocess,sys
from pathlib import Path
args=sys.argv[1:]
unit=next((a.split('=',1)[1] for a in args if a.startswith('--unit=')),'update')
start=args.index('/bin/bash')
log=open('/test/update.log','ab')
subprocess.Popen(['/bin/bash','-c','"$@"; result=$?; printf "\nUPDATE_EXIT=%s\n" "$result"',
    '--',*args[start:]],stdout=log,stderr=log,start_new_session=True)
print('Running as unit: '+unit)
'''


def run(args, *, input=None, check=True, timeout=600):
    result = subprocess.run(args, input=input, text=True, encoding="utf-8", errors="replace",
                            capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[:4]}: {result.stdout[-6000:]}\n{result.stderr[-6000:]}")
    return result.stdout


def extract(archive, target):
    with tarfile.open(archive, "r:gz") as handle:
        handle.extractall(target, filter="data")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", type=Path, default=ROOT / "kvn-vpn-release-linux-amd64.tar.gz")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="kvn-portal-upgrade-"))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0)); port = listener.getsockname()[1]
    volumes = [NAME + suffix for suffix in ("-socket", "-secret", "-metrics")]
    project = work / "project"
    baseline = args.baseline or work / "baseline.tar.gz"
    if not args.baseline:
        run(["curl", "-fL", "--retry", "3", BASELINE_URL, "-o", str(baseline)])
    if hashlib.sha256(baseline.read_bytes()).hexdigest() != BASELINE_SHA:
        raise RuntimeError("SHA-256 опубликованной v4.0.1 не совпадает")
    seed = work / "seed"; seed.mkdir()
    extract(baseline, seed); extract(seed / "kvn-vpn-deploy.tar.gz", work)
    (work / "deploy").rename(project)
    fixture = work / "fixture.py"
    fixture.write_text('''import json,sys
sys.path.insert(0,'/project')
from tools.kvnctl import STATE_STORE,render_all
from portal.app.security import hash_password
state=json.loads(open('/project/users.json').read())
state['server']='1.1.1.1'
state['ocserv']={'enabled':True,'sni_enabled':True,'sni':'oc.example.test'}
state['services']={name:{'enabled':False} for name in ['xray','hysteria','telemt','mtg','amneziawg','wireguard']}
state['services'].update({name:{'enabled':True} for name in ['nginx','portal','agent','ocserv']})
state['portal']={'enabled':True,'name':'Upgrade E2E','domain':'1.1.1.1','port':8443,'path':'/gaer',
    'login':'admin','password_hash':hash_password('UpgradePortal-Test-2026'),
    'proxy_secret':'b'*64,'hysteria_secret':'c'*64,'allow_self_signed_ip':True,
    'performance':{'profile':'light'}}
state['subscription']={'enabled':False,'port':2096}
state['letsencrypt']={'enabled':False,'domain':'','domains':[]}
state['users']=[{'name':'UpgradeUser','enabled':True,'systems':['reality-tcp','telemt','hysteria'],
    'uuid':'f6ba8fc1-a21d-459f-ae10-a9db64535e14'}]
STATE_STORE.save(state)
open('/project/.env','w').write('KVN_PORTAL_GID=12345\\nKVN_PORTAL_PORT=8443\\nCOMPOSE_PROFILES=portal,portal-custom\\n')
''', encoding="utf-8")
    (work / "systemctl").write_text(SYSTEMCTL, encoding="utf-8")
    (work / "systemd-run").write_text(SYSTEMD_RUN, encoding="utf-8")
    network = NAME + "-network"
    dind, agent = NAME + "-docker", NAME + "-agent"
    def agent_run(*command, input=None):
        return run(["docker", "exec", "-i", agent, *command], input=input)
    def request(method, path, *, data=None, cookie="", upload=None):
        connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=600,
                                                context=ssl._create_unverified_context())
        headers = {"Host":"1.1.1.1", "User-Agent":"KVN-Portal-Upgrade-E2E"}
        if cookie: headers["Cookie"] = cookie
        body = urlencode(data).encode() if data else None
        if data: headers["Content-Type"] = "application/x-www-form-urlencoded"
        if upload:
            headers.update({"Content-Type":"application/octet-stream", "Content-Length":str(upload.stat().st_size),
                            "X-KVN-Archive-Name":"kvn-vpn-release-linux-amd64.tar.gz",
                            "X-CSRF-Token":data["csrf_token"], "Accept":"application/json"})
            with upload.open("rb") as handle: connection.request(method,path,body=handle,headers=headers)
        else: connection.request(method,path,body=body,headers=headers)
        response = connection.getresponse(); content=response.read().decode(errors="replace")
        result=(response.status,dict(response.getheaders()),content); connection.close(); return result
    def wait_portal(version):
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            try:
                status,_,text=request("GET","/gaer/login")
                if status==200 and agent_run("docker","exec","kvn-portal","printenv","KVN_VERSION").strip()==version:
                    return text
            except (OSError,http.client.HTTPException): pass
            time.sleep(1)
        raise RuntimeError("Не появился портал версии "+version)
    def csrf(text): return re.search(r'name="csrf_token" value="([^"]+)"',text).group(1)
    def login(version):
        page=wait_portal(version)
        status,headers,_=request("POST","/gaer/login",data={"csrf_token":csrf(page),"login":"admin","password":LOGIN_PASSWORD})
        if status!=302: raise RuntimeError("Вход в портал не удался")
        return headers["Set-Cookie"].split(";",1)[0]
    def toggle(cookie,action,service="ocserv"):
        status,_,text=request("GET","/gaer/services",cookie=cookie)
        if status!=200: raise RuntimeError("Список сервисов недоступен")
        data={"csrf_token":csrf(text),"action":action}
        if action=='disable':
            data['confirmation_token']=re.search(r'action="/gaer/services/'+re.escape(service)+r'/action".*?value="disable".*?name="confirmation_token" value="([^"]+)"',text,re.S).group(1)
        status,_,text=request("POST",f"/gaer/services/{service}/action",cookie=cookie,data=data)
        if status!=200 or 'Операция выполнена.' not in text:
            main = re.search(r'<main[^>]*>(.*?)</main>',text,re.S)
            detail = re.sub('<[^>]+>',' ',main.group(1) if main else text[:2500])
            raise RuntimeError(f"Переключение {service} HTTP {status}: "+detail.strip()[:2500])
    try:
        print("[INFO] Поднимаю опубликованный baseline v4.0.1 в изолированном Docker daemon",flush=True)
        run(["docker","build","-f",str(ROOT/'tests/portal-upgrade-agent.Dockerfile'),"-t",NAME+"-host",str(ROOT)])
        run(["docker","network","create",network])
        for volume in volumes: run(["docker","volume","create",volume])
        run(["docker","run","-d","--privileged","--name",dind,"--network",network,
             "-e","DOCKER_TLS_CERTDIR=","-p",f"127.0.0.1:{port}:8443",
             "-v",f"{project}:/project","-v",volumes[0]+":/run/kvn-portal",
             "-v",volumes[1]+":/etc/kvn-portal","docker:29-dind"])
        run(["docker","run","-d","--name",agent,"--network",network,
             "-e",f"DOCKER_HOST=tcp://{dind}:2375","-e","COMPOSE_PROJECT_NAME=kvn-upgrade",
             "-v",f"{project}:/project","-v",f"{seed}:/seed:ro","-v",f"{work}:/test",
             "-v",volumes[0]+":/run/kvn-portal","-v",volumes[1]+":/etc/kvn-portal",
             "-v",volumes[2]+":/var/lib/kvn-portal",NAME+"-host","sleep","infinity"])
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            try: agent_run("docker","info"); break
            except RuntimeError: time.sleep(1)
        else: raise RuntimeError("Изолированный Docker daemon не запустился")
        agent_run("bash","-ceu","cp /test/systemctl /usr/local/bin/systemctl; cp /test/systemd-run /usr/local/bin/systemd-run; chmod 755 /usr/local/bin/systemctl /usr/local/bin/systemd-run; groupadd -g 12345 kvn-portal; python3 /test/fixture.py; python3 tools/kvnctl.py render --certs")
        agent_run("chpasswd",input="root:"+ROOT_PASSWORD+"\n")
        agent_run("bash","-ceu","mkdir -p site-certs; openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=1.1.1.1 -addext subjectAltName=IP:1.1.1.1 -keyout site-certs/server.key -out site-certs/server.crt >/dev/null 2>&1; python3 tools/kvnctl.py render; bash portal/install-host-agent.sh")
        agent_run("docker","image","load","-i","/seed/kvn-vpn-images-linux-amd64.tar")
        agent_run("docker","compose","--profile","portal","--profile","portal-custom","up","-d","--no-build","--pull","never","nginx","portal","portal-gateway","ocserv")
        cookie=login("v4.0.1")
        # В опубликованном v4.0.1 route передаёт request_id, который его registry
        # ещё не допускает. Подготовка persistent-состояния выполняется через
        # старый allowlisted RPC без этого поля; portal update остаётся реальным.
        agent_run("python3","-c","from portal.agent_client import AgentClient; from pathlib import Path; c=AgentClient(Path('/run/kvn-portal/control.sock'),Path('/etc/kvn-portal/agent.secret').read_text().strip()); r=c.call('service.action',{'service':'ocserv','action':'disable'}); assert r['ok']")
        agent_run("python3","-c","import json; from tools.kvnctl import STATE_STORE; state=STATE_STORE.load(); state['sni_routes']['reality-tcp']['aliases'].append('.'.join(['a'*63,'b'*63,'c'*63,'d'*61])); STATE_STORE.save(state)")
        before=json.loads(agent_run("python3","-c","import json; print(json.dumps(json.load(open('users.json'))))"))
        certificate=agent_run("sha256sum","site-certs/server.crt").split()[0]
        print("[OK] Опубликованный v4.0.1 запущен; persistent ocserv=false задан старым allowlisted RPC",flush=True)
        status,_,page=request("GET","/gaer/settings?group=update",cookie=cookie)
        status,_,text=request("POST","/gaer/settings/update/prepare",cookie=cookie,
                              data={"csrf_token":csrf(page)},upload=args.release)
        if status!=201: raise RuntimeError("Старый портал отклонил архив: "+text)
        prepared=json.loads(text)
        print("[OK] v4.0.1 загрузил и проверил full release; ready",flush=True)
        status,_,page=request("GET","/gaer/settings?group=update",cookie=cookie)
        token=re.search(r'name="prepared_id" value="([^"]+)"',page).group(1)
        status,_,text=request("POST","/gaer/settings/update/start",cookie=cookie,
                              data={"csrf_token":csrf(page),"prepared_id":token,"root_password":ROOT_PASSWORD,"mode":"full"})
        if status not in (200,302): raise RuntimeError("Запуск обновления отклонён: "+text)
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            log=(work/'update.log').read_text(errors='replace') if (work/'update.log').exists() else ''
            if 'UPDATE_EXIT=' in log:
                if 'UPDATE_EXIT=0' not in log: raise RuntimeError(log[-10000:])
                break
            time.sleep(1)
        else: raise RuntimeError("Updater не завершился: "+log[-10000:])
        cookie=login("v4.1.0")
        print("[OK] Updater завершился; портал v4.1.0 доступен",flush=True)
        after=json.loads(agent_run("python3","-c","import json; print(json.dumps(json.load(open('users.json'))))"))
        for key in ('users','portal'):
            if after[key]!=before[key]: raise RuntimeError("Обновление изменило state: "+key)
        if agent_run("sha256sum","site-certs/server.crt").split()[0]!=certificate: raise RuntimeError("Изменился сертификат")
        if after['services']['ocserv']['enabled'] is not False: raise RuntimeError("ocserv включился после update")
        running=agent_run("docker","compose","ps","--status","running","--services")
        if 'ocserv' in running: raise RuntimeError("Отключённый ocserv запущен")
        agent_run("docker","compose","exec","-T","nginx","nginx","-t")
        print("[OK] nginx -t: SNI длиной 253 байта; state/certs и отключённый ocserv сохранены",flush=True)
        toggle(cookie,"enable")
        if json.loads(agent_run("python3","-c","import json; print(json.dumps(json.load(open('users.json'))))"))['services']['ocserv']['enabled'] is not True:
            raise RuntimeError("Включение ocserv не сохранено")
        toggle(cookie,"disable")
        for service in ("telemt","hysteria","xray"):
            toggle(cookie,"enable",service)
        time.sleep(5)
        running=set(agent_run("docker","compose","ps","--status","running","--services").splitlines())
        if not {"telemt","hysteria","xray"}.issubset(running):
            raise RuntimeError("Новые runtime-конфиги не запустились: "+agent_run("docker","compose","logs","--tail=30","telemt","hysteria","xray"))
        print("[OK] Новые Telemt/Hysteria/Xray запущены с generated-конфигами",flush=True)
        for service in ("telemt","hysteria","xray"):
            toggle(cookie,"disable",service)
        print("[OK] PORTAL_UPGRADE_E2E: v4.0.1 → v4.1.0, реальные HTTPS upload/ready/start/Compose, сохранение state/certs, ocserv disable/enable",flush=True)
    finally:
        if args.keep:
            print(f"[INFO] Стенд сохранён: {work}, https://127.0.0.1:{port}/gaer/")
        else:
            # Только наш mkdtemp: убрать root-владельца у тестового runtime до
            # удаления стенда обычным пользователем WSL.
            if work.resolve().parent != Path(tempfile.gettempdir()).resolve() or not work.name.startswith('kvn-portal-upgrade-'):
                raise RuntimeError('Небезопасный путь очистки E2E')
            run(['docker','exec',agent,'chown','-R',f'{os.getuid()}:{os.getgid()}','/test'],check=False)
            run(["docker","rm","-f",agent,dind],check=False)
            for volume in volumes: run(["docker","volume","rm",volume],check=False)
            run(["docker","network","rm",network],check=False)
            shutil.rmtree(work)


if __name__=='__main__': main()
