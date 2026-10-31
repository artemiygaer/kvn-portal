#!/usr/bin/env python3
"""Проверяет браузерный HTTPS и настоящий Reality TCP/xHTTP в Docker/WSL."""

import json
import os
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
XRAY = "ghcr.io/xtls/xray-core:26.10.29"

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
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit(
            "Self-steal E2E требует Linux/root для production ownership UID 65532. "
            "Запустите sudo python3 tests/self_steal_e2e.py; "
            "на Windows используйте WSL: wsl.exe -d Ubuntu -u root -- bash."
        )
    work=Path(tempfile.mkdtemp(prefix="kvn-self-steal-"))
    network=PREFIX+"-network"
    containers=[PREFIX+"-nginx", PREFIX+"-xray", PREFIX+"-client", PREFIX+"-cover"]
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
            https_port,socks_port,xray_port=port(),port(),port()
            run("docker","run","-d","--name",containers[1],"--network",network,"--network-alias","xray",
                "-p",f"127.0.0.1:{xray_port}:{2054 if system == 'reality-tcp' else 2053}",
                "-v",f"{project/'xray/config.json'}:/etc/xray/config.json:ro",
                "-v",f"{project/'certs'}:/etc/xray/certs:ro",XRAY,"run","-c","/etc/xray/config.json")
            run("docker","run","-d","--name",containers[0],"--network",network,"--network-alias","nginx",
                "--network-alias",DOMAIN,"-p",f"127.0.0.1:{https_port}:443",
                "-v",f"{project/'nginx/nginx.conf'}:/etc/nginx/nginx.conf:ro",
                "-v",f"{project/'site-certs'}:/etc/nginx/certs:ro",
                "-v",f"{project/'nginx/site'}:/var/www/site:ro",
                "-v",f"{project/'nginx/web'}:/var/www/sub:ro","nginx:1.31.8-alpine")
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
            started_before=run('docker','inspect','--format','{{.State.StartedAt}}',containers[1]).strip()
            hot_script = '''import copy,json,subprocess,sys
from tools import kvnctl
params=json.load(sys.stdin)
before=kvnctl.load_state()
after=copy.deepcopy(before)
after['users'][0]['uuid']='00000000-0000-4000-8000-000000000002'
plan=kvnctl.render_all(after)
change=plan.services.get('xray')
assert change is not None, 'users-only не изменил конфигурацию Xray'
only=kvnctl.ChangeSet(changed_paths=('xray/config.json',), services={'xray':change}, xray_before_evidence=plan.xray_before_evidence, xray_after_evidence=plan.xray_after_evidence)
original=subprocess.run
def isolated(argv,*args,**kwargs):
    argv=list(argv)
    if argv[:3]==['docker','exec','xray']:
        argv[2]=params['container']
    elif argv[:5]==['docker','exec','--user','0','xray']:
        argv[4]=params['container']
    elif argv[:2]==['docker','cp']:
        argv=[params['container']+a[4:] if isinstance(a,str) and a.startswith('xray:') else a for a in argv]
    return original(argv,*args,**kwargs)
subprocess.run=isolated
result=kvnctl.restart_services(only,before_state=before,after_state=after)
assert result['hot_updated']==['xray'] and not result['restarted'], 'HandlerService не применил пользователя'
kvnctl.save_state(after)
'''
            try:
                print(run('python3','-c',hot_script,cwd=project,input=json.dumps({'container':containers[1]})), flush=True)
            except RuntimeError:
                diagnostic=subprocess.run(['docker','logs','--tail=20',containers[1]],capture_output=True,text=True)
                print('[ДИАГНОСТИКА] Xray: '+(diagnostic.stdout+diagnostic.stderr)[-2000:],flush=True)
                raise
            assert run('docker','inspect','--format','{{.State.StartedAt}}',containers[1]).strip()==started_before
            client['outbounds'][0]['settings']['vnext'][0]['users'][0]['id']='00000000-0000-4000-8000-000000000002'
            client_path.write_text(json.dumps(client))
            run('docker','restart',containers[2])
            time.sleep(1)
            try:
                code=run('curl','-fsS','--socks5-hostname',f'127.0.0.1:{socks_port}','--max-time','30',
                         'https://github.com/artemiygaer/kvn-portal','-o','/dev/null','-w','%{http_code}')
            except RuntimeError:
                for name in containers[1:3]:
                    diagnostic=subprocess.run(['docker','logs','--tail=20',name],capture_output=True,text=True)
                    print('[ДИАГНОСТИКА] Xray: '+(diagnostic.stdout+diagnostic.stderr)[-2000:],flush=True)
                raise
            assert code=='200', 'Новый пользователь не подключился после hot-update'
            print(f'[OK] {system}: реальный HandlerService обновил пользователя без restart Xray',flush=True)
            if system in ('reality-tcp', 'reality-xhttp'):
                cover = work / 'cover.conf'
                cover.write_text('events {}\nhttp { server { listen 443 ssl; ssl_certificate /certs/server.crt; ssl_certificate_key /certs/server.key; location / { return 200 "external-cover-proof"; } } }\n')
                run('docker', 'run', '-d', '--name', containers[3], '--network', network,
                    '--network-alias', 'cover.example.test', '-v', f'{cover}:/etc/nginx/nginx.conf:ro',
                    '-v', f"{project/'site-certs'}:/certs:ro", 'nginx:1.31.8-alpine')
                script = '''import copy,json,subprocess,sys
from tools import kvnctl
params=json.load(sys.stdin)
before=kvnctl.load_state()
after=copy.deepcopy(before)
route=after['sni_routes'][params['system']]
route['default']=params['sni']; route['aliases']=[params['sni']]; route['reality_mode']=params['mode']
plan=kvnctl.render_all(after)
change=plan.services.get('xray')
assert change is not None, 'смена режима не изменила конфигурацию Xray'
only=kvnctl.ChangeSet(changed_paths=('xray/config.json',), services={'xray':change}, xray_before_evidence=plan.xray_before_evidence, xray_after_evidence=plan.xray_after_evidence)
def restart(services):
    assert services == ['xray']
    return subprocess.run(['docker','restart',params['container']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
kvnctl._restart_docker_services=restart
result=kvnctl.restart_services(only,before_state=before,after_state=after)
assert result['restarted']==['xray'] and not result['hot_updated'], 'не подтверждён структурный restart'
kvnctl.save_state(after)
same=kvnctl.render_all(copy.deepcopy(after))
assert 'xray' not in same.services, 'повтор изменения не является no-op'
'''
                for mode, sni, marker in (('external','cover.example.test','external-cover-proof'),
                                          ('self-steal',DOMAIN,'Self-steal HTTPS proof'),
                                          ('external','cover.example.test','external-cover-proof')):
                    run('python3','-c',script,cwd=project,input=json.dumps({'mode':mode,'sni':sni,'container':containers[1],'system':system}))
                    page=run('curl','-fkSs','--noproxy','*','--max-time','15','--resolve',f'{sni}:{xray_port}:127.0.0.1',f'https://{sni}:{xray_port}/')
                    assert marker in page, f'Неверный работающий cover после {mode}'
                    changed=json.loads((project/'xray/config.json').read_text())
                    entry=next(i for i in changed['inbounds'] if i['port']==(2054 if system=='reality-tcp' else 2053))
                    assert entry['streamSettings']['realitySettings']['privateKey']==private
                    assert any(item['id']=='00000000-0000-4000-8000-000000000002' for item in entry['settings']['clients'])
                print(f'[OK] {system}: external → self-steal → external, live cover, restart и no-op',flush=True)
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
