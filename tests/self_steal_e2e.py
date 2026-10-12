#!/usr/bin/env python3
"""Проверяет браузерный HTTPS и настоящий Reality TCP/xHTTP в Docker/WSL."""

import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "self-steal.example.test"
PREFIX = "kvn-self-steal-e2e"
XRAY = "ghcr.io/xtls/xray-core:26.3.27"

def run(*args, cwd=ROOT, input=None, timeout=120):
    result = subprocess.run(args, cwd=cwd, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        # Команды с ключами не выводятся. Диагностика CLI не содержит users.json.
        raise RuntimeError(f"{args[0]}: {result.stderr[-2500:]}")
    return result.stdout

def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0))
        return listener.getsockname()[1]

def main():
    work=Path(tempfile.mkdtemp(prefix="kvn-self-steal-"))
    network=PREFIX+"-network"
    containers=[PREFIX+"-nginx", PREFIX+"-xray", PREFIX+"-client"]
    try:
        archive=work/"source.tar.gz"
        run("bash","tools/build-deploy.sh",str(archive))
        with tarfile.open(archive) as handle: handle.extractall(work,filter="data")
        project=work/"deploy"
        keys=run("docker","run","--rm",XRAY,"x25519")
        private=re.search(r"PrivateKey:\s*(\S+)",keys).group(1)
        public=re.search(r"(?:Password(?: \(PublicKey\))?|PublicKey):\s*(\S+)",keys).group(1)
        fixture='''import json,sys
from tools import kvnctl
state=kvnctl.load_state()
state['server']='self-steal.example.test'
state['site']={'title':'Self-steal HTTPS proof'}
state['ocserv']={'enabled':True,'sni_enabled':True,'sni':state['server']}
state['portal']={'enabled':False}
state['subscription']={'enabled':True,'port':2096}
state['users']=[{'name':'Fixture','uuid':'00000000-0000-4000-8000-000000000001',
    'enabled':True,'systems':[sys.argv[1],'ocserv'],'ocserv_password':'Fixture-password-2026'}]
for section in ('reality','reality_tcp'):
    state[section]={'privateKey':sys.argv[2],'shortIds':['0011223344556677'],'short_id':'0011223344556677','public_key':sys.argv[3]}
state['sni_routes'][sys.argv[1]]={'default':state['server'],'aliases':[state['server']],
    'dest':'xray:2054' if sys.argv[1]=='reality-tcp' else 'xray:2053', 'reality_mode':'self-steal'}
kvnctl.save_state(state)
'''
        run("docker","network","create",network)
        for system in ("reality-tcp","reality-xhttp"):
            for name in containers: subprocess.run(["docker","rm","-f",name],capture_output=True)
            # Не используем секреты в argv: параметры fixture передаются stdin.
            script=fixture.replace("sys.argv[1]","params[0]").replace("sys.argv[2]","params[1]").replace("sys.argv[3]","params[2]")
            run("python3","-c","import json,sys; params=json.loads(sys.stdin.read());\n"+script,
                cwd=project,input=json.dumps([system,private,public]))
            run("python3","tools/kvnctl.py","render","--certs",cwd=project)
            state=json.loads((project/"users.json").read_text())
            original=json.loads((project/"xray/config.json").read_text())
            selected=next(i for i in original['inbounds'] if i['port']==(2054 if system=='reality-tcp' else 2053))
            assert selected['streamSettings']['realitySettings']['target']=='nginx:8443'
            assert selected['streamSettings']['realitySettings']['privateKey']==private
            client_name="xray-reality-tcp.json" if system=="reality-tcp" else "xray-reality.json"
            client=json.loads((project/"clients/Fixture"/client_name).read_text())
            # Экспорт содержит vnext/streamSettings для приложения, не standalone config.
            client={'outbounds':[{'protocol':'vless','settings':{'vnext':client['vnext']},
                                  'streamSettings':client['streamSettings']}]}
            client['log']={'loglevel':'debug'}
            client['inbounds']=[{'listen':'0.0.0.0','port':10808,'protocol':'socks',
                                'settings':{'auth':'noauth','udp':False}}]
            # Отдельный test overlay, generated config не изменяется.
            client_path=work/'client-test.json'
            client_path.write_text(json.dumps(client))
            https_port,socks_port=port(),port()
            run("docker","run","-d","--name",containers[1],"--network",network,"--network-alias","xray",
                "-v",f"{project/'xray/config.json'}:/etc/xray/config.json:ro",
                "-v",f"{project/'certs'}:/etc/xray/certs:ro",XRAY,"run","-c","/etc/xray/config.json")
            run("docker","run","-d","--name",containers[0],"--network",network,"--network-alias","nginx",
                "--network-alias",DOMAIN,"-p",f"127.0.0.1:{https_port}:443",
                "-v",f"{project/'nginx/nginx.conf'}:/etc/nginx/nginx.conf:ro",
                "-v",f"{project/'site-certs'}:/etc/nginx/certs:ro",
                "-v",f"{project/'nginx/site'}:/var/www/site:ro",
                "-v",f"{project/'nginx/web'}:/var/www/sub:ro","nginx:1.31.6-alpine")
            run("docker","exec",containers[0],"nginx","-t")
            time.sleep(1)
            try:
                page=run("curl","-fsS","--max-time","15","--cacert",str(project/'site-certs/server.crt'),
                    "--resolve",f"{DOMAIN}:{https_port}:127.0.0.1",f"https://{DOMAIN}:{https_port}/")
            except RuntimeError:
                for name in containers[:2]:
                    diagnostic=subprocess.run(['docker','logs','--tail=20',name],capture_output=True,text=True)
                    print(diagnostic.stdout[-2000:]+diagnostic.stderr[-2000:])
                raise
            assert 'Self-steal HTTPS proof' in page and 'Please enter your username' not in page
            run("docker","run","-d","--name",containers[2],"--network",network,
                "-p",f"127.0.0.1:{socks_port}:10808","-v",f"{client_path}:/client.json:ro",XRAY,"run","-c","/client.json")
            time.sleep(1)
            try:
                code=run("curl","-fsS","--socks5-hostname",f"127.0.0.1:{socks_port}","--max-time","30",
                    "https://github.com/artemiygaer/kvn-portal","-o","/dev/null","-w","%{http_code}")
            except RuntimeError:
                for name in containers[1:]:
                    diagnostic=subprocess.run(['docker','logs','--tail=15',name],capture_output=True,text=True)
                    print(diagnostic.stdout[-2000:]+diagnostic.stderr[-2000:])
                raise
            assert code=='200', code
            assert 'https://self-steal.example.test:2448/' in (project/'clients/Fixture/openconnect.txt').read_text()
            print(f"[OK] {system}: nginx -t, TLS-сайт без ключа, authenticated Reality SOCKS → HTTPS 200, ocserv export 2448",flush=True)
            # Следующий режим начинается с чистого source template, без предыдущего SNI.
            if system=='reality-tcp':
                shutil.copyfile(ROOT/'packaging/deploy-template/users.json',project/'users.json')
        print('[OK] SELF_STEAL_E2E',flush=True)
    finally:
        for name in containers: subprocess.run(["docker","rm","-f",name],capture_output=True)
        subprocess.run(["docker","network","rm",network],capture_output=True)
        if work.resolve().parent!=Path(tempfile.gettempdir()).resolve() or not work.name.startswith('kvn-self-steal-'):
            raise RuntimeError('Небезопасный путь очистки')
        shutil.rmtree(work)

if __name__=='__main__': main()
