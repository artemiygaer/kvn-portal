"""Применять пользовательское право и восстановленные параметры WG/AWG."""

from dataclasses import replace

from v5.modules.amneziawg.profile import Profile, V31

from .credentials import allocate, peer, public_key

_V31_FIELDS = {"content_padding_addition": "content_padding", "rekey_after_time": "rekey_after",
               "rekey_timeout": "rekey_timeout", "reject_after_time": "reject_after",
               "keepalive_timeout": "keepalive_timeout", "max_handshake_attempts": "max_handshakes"}


def set_user(state, credential, enabled):
    if type(enabled) is not bool:
        raise ValueError("Некорректное состояние доступа к туннелю")
    if credential is None:
        if not enabled:
            return state
        raise ValueError("Ключи клиента туннеля ещё не подготовлены")
    current = peer(credential)
    before = tuple(item for item in state.settings.peers if item.public_key == current.public_key)
    if before and before != (current,):
        raise ValueError("Импортированный peer конфликтует с настройками назначения")
    if bool(before) == enabled:
        return state
    others = tuple(item for item in state.settings.peers if item.public_key != current.public_key)
    return replace(state, settings=replace(state.settings, peers=(*others, current) if enabled else others))


def project_user(state, user_id, enabled, *, material, credentials):
    module = state.spec.module
    if enabled:
        credential = credentials.ensure(user_id, module, lambda occupied: allocate(state.settings, occupied))
    else:
        credential = material.credential(user_id, module)
    return set_user(state, credential, enabled)


def restore_profile(seed) -> Profile:
    mode = seed.get("mode", "legacy")
    obfs, v3 = seed.get("obfuscation", {}), seed.get("v3", {})
    modern = None
    if mode == "3.1":
        modern = V31(v3["header_protection_key"], **{dest: v3[name] for name, dest in _V31_FIELDS.items() if name in v3},
                     random_trailers=v3.get("random_trailers", False), disable_cookies=v3.get("disable_cookies", False))
    default = Profile.modern(v3["header_protection_key"]) if modern else Profile()
    tagged = tuple(obfs.get(f"I{i}", "") for i in range(1, 6))
    while tagged and not tagged[-1]:
        tagged = tagged[:-1]
    return Profile(mode=mode, junk_count=obfs.get("Jc", default.junk_count), junk_min=obfs.get("Jmin", default.junk_min),
                   junk_max=obfs.get("Jmax", default.junk_max),
                   padding=tuple(obfs.get(f"S{i}", value) for i, value in enumerate(default.padding, 1)),
                   headers=tuple(str(obfs.get(f"H{i}", value)) for i, value in enumerate(default.headers, 1)),
                   tagged=tagged, v31=modern)


def restore_seed(state, seed):
    if public_key(seed["private_key"]) != seed["public_key"]:
        raise ValueError("Ключи сервера туннеля не соответствуют друг другу")
    settings = replace(state.settings, private_key=seed["private_key"],
                       address=seed.get("address", state.settings.address), mtu=seed.get("mtu", state.settings.mtu))
    profile = restore_profile(seed) if state.spec.module == "amneziawg" else None
    return replace(state, settings=settings, profile=profile)


def server_seed(state):
    """Только для шифрованного переноса; интерфейс выхода и peers не экспортируются."""
    settings, profile = state.settings, state.profile
    value = {"private_key": settings.private_key, "public_key": public_key(settings.private_key),
             "address": settings.address, "mtu": settings.mtu}
    if profile is not None:
        obfuscation = {"Jc": profile.junk_count, "Jmin": profile.junk_min, "Jmax": profile.junk_max}
        for prefix, items in (("S", profile.padding), ("H", profile.headers), ("I", profile.tagged)):
            obfuscation.update({f"{prefix}{index}": item for index, item in enumerate(items, 1) if item != ""})
        value.update(mode=profile.mode, obfuscation=obfuscation)
        if profile.v31 is not None:
            modern = profile.v31
            value["v3"] = {name: getattr(modern, attr) for name, attr in _V31_FIELDS.items()}
            value["v3"].update(header_protection_key=modern.header_key, random_trailers=modern.random_trailers,
                               disable_cookies=modern.disable_cookies)
    return value


def client_file(state, credential, *, endpoint, active):
    if credential is None or not active:
        return b""
    current = peer(credential)
    return state.client(current, private_key=credential["private_key"], server_key=public_key(state.settings.private_key),
                        endpoint=endpoint, active=active)
