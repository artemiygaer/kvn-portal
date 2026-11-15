"""Узкий Unix RPC смены состояния уже проверенных пакетов."""

import argparse
from dataclasses import asdict
import json
import re
import socket
import sqlite3
import struct

from v5.core.contracts import CORE_API_VERSION, validate_module_id
from v5.core.audit import outcome
from v5.core.network.plan import NetworkConflict
from v5.core.packages.manifest import SHA256, PackageError, json_object, reject
from v5.core.packages.status import PACKAGE_STATE
from v5.core.tls.transaction import GatewayApplyError
from v5.core.users.controller import UserApplyError
from v5.core.users.rpc import UsersApplication
from v5.core.users.store import UserStore
from v5.core.observability import control as observation_control
from v5.modules.host_tunnel.platform import capability
from v5.modules.host_tunnel.state import TUNNELS
from v5.modules.hysteria.config import Settings as HysteriaSettings, identity as hysteria_identity
from v5.modules.mtproto_common.profiles import Exposure as MTExposure, Secret as MTSecret
from v5.modules.mtg.settings import Settings as MTGSettings
from v5.modules.telemt.settings import Settings as TelemtSettings
from v5.modules.xray.config import Settings as XraySettings
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles, Reality

from .assembly import build_lifecycle
from .controller import LifecycleError

_PEER = struct.Struct('3i')
_LIMIT = 1024
_METHODS = {
    'lifecycle.enable': frozenset({'module'}),
    'lifecycle.disable': frozenset({'module'}),
    'lifecycle.upgrade': frozenset({'module', 'ticket'}),
    'lifecycle.diagnostics': frozenset({'module'}),
    'lifecycle.plan': frozenset({'module'}),
    'lifecycle.initialize': frozenset({'module', 'egress'}),
    'lifecycle.tunnel_settings': frozenset({'module'}),
    'lifecycle.change_tunnel': frozenset({'module', 'egress', 'revision'}),
    'lifecycle.initialize_xray': frozenset({'module', 'kind', 'exposure', 'sni', 'reality', 'external_host', 'path'}),
    'lifecycle.add_xray': frozenset({'module', 'kind', 'exposure', 'sni', 'reality', 'external_host', 'path'}),
    'lifecycle.xray_profiles': frozenset({'module'}),
    'lifecycle.replace_xray': frozenset({'module', 'kind', 'exposure', 'sni', 'reality', 'external_host', 'path', 'revision'}),
    'lifecycle.remove_xray': frozenset({'module', 'kind', 'revision'}),
    'lifecycle.initialize_hysteria': frozenset({'module', 'identity', 'port', 'salamander'}),
    'lifecycle.change_hysteria': frozenset({'module', 'identity', 'port', 'salamander', 'revision'}),
    'lifecycle.initialize_mtproto': frozenset({'module', 'sni', 'mode', 'exposure'}),
    'lifecycle.mtproto_exposure': frozenset({'module'}),
    'lifecycle.change_mtproto': frozenset({'module', 'sni', 'mode', 'exposure', 'revision'}),
}


class Application:
    def __init__(self, web_uid, factory=build_lifecycle, users_factory=None):
        self.web_uid, self.factory = web_uid, factory
        self.users_factory = users_factory or self._users

    def _users(self):
        def runtime():
            database = PACKAGE_STATE / "registry.sqlite3"
            return self.factory() if database.exists() or database.is_symlink() else None
        return UsersApplication(UserStore(PACKAGE_STATE.parent / "users"), runtime)

    def dispatch(self, request):
        if (request.keys() != {'version', 'method', 'params'} or type(request['version']) is not int
                or request['version'] != CORE_API_VERSION):
            reject('invalid_request')
        method, params = request['method'], request['params']
        if method == 'lifecycle.history.status' and params == {}:
            return observation_control.status()
        if method == 'lifecycle.history.configure' and isinstance(params, dict) and params.keys() == {'enabled'}:
            return observation_control.configure(params['enabled'])
        if method == 'lifecycle.settings_snapshot':
            allowed = frozenset(('xray', 'wireguard', 'amneziawg', 'hysteria', 'telemt', 'mtg'))
            if (not isinstance(params, dict) or params.keys() != {'modules'}
                    or not isinstance(params['modules'], list) or len(params['modules']) > len(allowed)
                    or any(not isinstance(item, str) or item not in allowed for item in params['modules'])
                    or len(set(params['modules'])) != len(params['modules'])):
                reject('invalid_request')
            lifecycle = self.factory()
            values, errors = {}, []
            for module in params['modules']:
                try:
                    adapter = lifecycle.adapters[module]
                    values[module] = (adapter.profile_list() if module == 'xray' else
                                      adapter.egress_view() if module in ('wireguard', 'amneziawg') else
                                      adapter.settings_view() if module == 'hysteria' else
                                      adapter.exposure_view())
                except (PackageError, LifecycleError, OSError, ValueError):
                    errors.append(module)
            return {'settings': values, 'errors': errors}
        if isinstance(method, str) and method.startswith('users.'):
            try:
                return self.users_factory().dispatch(method, params)
            except PackageError:
                raise
            except ValueError:
                reject('invalid_user_request')
        if (not isinstance(method, str) or method not in _METHODS or not isinstance(params, dict)
                or params.keys() != _METHODS[method]):
            reject('invalid_request')
        try:
            module = validate_module_id(params['module'])
        except ValueError:
            reject('invalid_request')
        if method == 'lifecycle.diagnostics':
            if module not in TUNNELS:
                reject('invalid_request')
            return {'module': module, 'host': asdict(capability(TUNNELS[module]))}
        if method == 'lifecycle.tunnel_settings':
            if module not in TUNNELS:
                reject('invalid_request')
            return {'module': module, 'settings': self.factory().adapters[module].egress_view()}
        if method == 'lifecycle.change_tunnel':
            if module not in TUNNELS:
                reject('invalid_request')
            self.factory().adapters[module].change_egress(params['egress'], params['revision'])
            return {'module': module, 'configured': True}
        if method == 'lifecycle.initialize':
            egress = params['egress']
            if module not in TUNNELS:
                reject('invalid_request')
            if egress is not None and (not isinstance(egress, str)
                                       or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', egress)
                                       or egress in {'lo', 'wg0', 'awg0'}):
                reject('tunnel_egress_invalid')
            adapter = self.factory().adapters[module]
            state = adapter.runtime.initial_state(egress=egress)
            adapter.configure(state, initial=True)
            return {'module': module, 'configured': True, 'internet_requested': egress is not None}
        if method in ('lifecycle.initialize_hysteria', 'lifecycle.change_hysteria'):
            if (module != 'hysteria' or not isinstance(params['identity'], str)
                    or type(params['port']) is not int or type(params['salamander']) is not bool):
                reject('invalid_request')
            try:
                from secrets import token_urlsafe
                identity = hysteria_identity(params['identity'])
            except ValueError:
                reject('hysteria_settings_invalid')
            lifecycle = self.factory()
            validate = lambda network: lifecycle.preview_configuration_locked(module, network)
            if method == 'lifecycle.change_hysteria':
                lifecycle.adapters[module].change_settings(identity, params['port'], params['salamander'],
                                                           params['revision'], validate=validate)
            else:
                try:
                    settings = HysteriaSettings(identity, port=params['port'],
                                                salamander=token_urlsafe(32) if params['salamander'] else None)
                except ValueError:
                    reject('hysteria_settings_invalid')
                lifecycle.adapters[module].configure(settings, initial=True, validate=validate)
            return {'module': module, 'configured': True}
        if method == 'lifecycle.mtproto_exposure':
            if module not in ('telemt', 'mtg'):
                reject('invalid_request')
            return {'module': module, 'exposure': self.factory().adapters[module].exposure_view()}
        if method in ('lifecycle.initialize_mtproto', 'lifecycle.change_mtproto'):
            if (module not in ('telemt', 'mtg') or not isinstance(params['sni'], str)
                    or params['mode'] not in ('external', 'own')
                    or params['exposure'] not in ('shared', 'direct', 'both')):
                reject('invalid_request')
            try:
                exposure = MTExposure(params['sni'], own_site=params['mode'] == 'own',
                                      shared=params['exposure'] != 'direct',
                                      direct_ip='0.0.0.0' if params['exposure'] != 'shared' else None)
            except ValueError:
                reject('mtproto_settings_invalid')
            lifecycle = self.factory()
            validate = lambda network: lifecycle.preview_configuration_locked(module, network)
            if method == 'lifecycle.change_mtproto':
                lifecycle.adapters[module].change_exposure(exposure, params['revision'], validate=validate)
            else:
                settings = TelemtSettings(exposure, ()) if module == 'telemt' else MTGSettings(exposure, MTSecret.create())
                lifecycle.adapters[module].configure(settings, initial=True, validate=validate)
            return {'module': module, 'configured': True}
        if method == 'lifecycle.xray_profiles':
            if module != 'xray':
                reject('invalid_request')
            return {'module': module, 'profiles': self.factory().adapters[module].profile_list()}
        if method == 'lifecycle.remove_xray':
            if module != 'xray':
                reject('invalid_request')
            try:
                kind = Kind(params['kind'])
            except (ValueError, TypeError):
                reject('xray_settings_invalid')
            lifecycle = self.factory()
            lifecycle.adapters[module].change_profile(kind, params['revision'], None,
                validate=lambda network: lifecycle.preview_configuration_locked(module, network))
            return {'module': module, 'configured': True}
        if method in ('lifecycle.initialize_xray', 'lifecycle.add_xray', 'lifecycle.replace_xray'):
            if module != 'xray':
                reject('invalid_request')
            try:
                kind = Kind(params['kind'])
                exposure = Exposure(params['exposure'])
                reality = Reality(params['reality']) if params['reality'] is not None else None
                profile = Profile(kind, exposure, params['sni'], reality, params['external_host'], params['path'])
                settings = XraySettings(Profiles((profile,)))
            except (TypeError, ValueError):
                reject('xray_settings_invalid')
            lifecycle = self.factory()
            validate = lambda network: lifecycle.preview_configuration_locked(module, network)
            if method == 'lifecycle.initialize_xray':
                lifecycle.adapters[module].configure(settings, initial=True, validate=validate)
            elif method == 'lifecycle.add_xray':
                lifecycle.adapters[module].add_profile(profile, validate=validate)
            else:
                lifecycle.adapters[module].change_profile(kind, params['revision'], profile, validate=validate)
            return {'module': module, 'configured': True}
        ticket = params.get('ticket')
        if method == 'lifecycle.upgrade' and (not isinstance(ticket, str) or not SHA256.fullmatch(ticket)):
            reject('unknown_prepared_package')
        lifecycle = self.factory()
        if method == 'lifecycle.plan':
            plan = lifecycle.preview_enable(module)
            return {'module': module,
                    'sni': [row.route.sni for row in plan.routes if row.owner == module],
                    'ports': [asdict(row.publication.public) for row in plan.publications if module in row.owners]}
        if method == 'lifecycle.upgrade':
            plan = lifecycle.upgrade(module, ticket)
        else:
            plan = lifecycle.change(module, method == 'lifecycle.enable')
        return {'module': module, 'enabled': module in plan.active}

    def handle(self, connection):
        connection.settimeout(8)
        request = None
        try:
            _, uid, _ = _PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size))
            if uid != self.web_uid:
                reject('forbidden')
            with connection.makefile('rb') as stream:
                line = stream.readline(_LIMIT + 1)
                if len(line) > _LIMIT or not line.endswith(b'\n') or stream.read(1):
                    reject('invalid_request')
                request = json_object(line)
                result = self.dispatch(request)
            response = {'ok': True, 'result': result}
        except (PackageError, LifecycleError, NetworkConflict, GatewayApplyError, UserApplyError) as exc:
            code = getattr(exc, 'code', str(exc))
            response = {'ok': False, 'error': code if re.fullmatch('[a-z0-9_]{1,64}', code) else 'lifecycle_unavailable'}
        except (OSError, ValueError, sqlite3.Error, RecursionError):
            response = {'ok': False, 'error': 'lifecycle_unavailable'}
        if request is not None:
            outcome(request, response)
        try:
            connection.sendall(json.dumps(response, separators=(',', ':')).encode() + b'\n')
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--web-uid', type=int, required=True)
    args = parser.parse_args()
    with socket.socket(fileno=0) as connection:
        Application(args.web_uid).handle(connection)


if __name__ == '__main__':
    main()
