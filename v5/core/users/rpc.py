"""Закрытые операции единой VPN-карточки, вызываемые через Unix RPC."""

from contextlib import contextmanager
from uuid import uuid4

from v5.core.contracts import MODULE_IDS, UserGrant
from v5.core.packages.manifest import reject

from .controller import UserController
from .model import GrantState, ModuleState, SubscriptionToken, User
from .store import MAX_USERS
from .subscription import CONFIG_MODULES, SubscriptionService

_METHODS = {
    "users.list": {"offset"}, "users.create": {"name"}, "users.detail": {"id"},
    "users.grant": {"id", "module", "enabled", "revision"},
    "users.retry": {"id", "module", "revision"}, "users.rotate": {"id", "revision"},
    "users.revoke": {"id", "revision"}, "users.profiles": {"id"}, "users.subscription": {"token"},
    "users.config": {"id", "module"},
}


class UsersApplication:
    def __init__(self, store, runtime):
        self.store, self.runtime = store, runtime

    @staticmethod
    @contextmanager
    def guard(lifecycle):
        if lifecycle is None:
            yield
            return
        with lifecycle.inventory.runtime_guard():
            lifecycle.inventory.require_network_idle()
            yield

    def dispatch(self, method, params):
        if method not in _METHODS or not isinstance(params, dict) or params.keys() != _METHODS[method]:
            reject("invalid_request")
        if method == "users.list":
            offset = params["offset"]
            if type(offset) is not int or not 0 <= offset <= MAX_USERS:
                reject("invalid_request")
            rows = self.store.list_users(offset=offset, limit=51)
            return {"users": list(rows[:50]), "more": len(rows) > 50}
        if method == "users.create":
            user = User(uuid4().hex, params["name"])
            self.store.create(user)
            return {"id": user.id}
        if method == "users.subscription":
            try:
                token = SubscriptionToken(params["token"])
            except ValueError:
                reject("user_not_found")
            if self.store.subscription_owner(token) is None:
                reject("user_not_found")
        else:
            user_id = User(params["id"], "valid").id
            if self.store.get(user_id) is None:
                reject("user_not_found")
        if method == "users.revoke":
            return {"revision": self.store.revoke_token(user_id, revision=params["revision"])}
        if method == "users.rotate":
            return {"token": self.store.rotate_token(user_id, revision=params["revision"]).value}
        lifecycle = self.runtime()
        modules = lifecycle.user_modules if lifecycle is not None else {}
        if method == "users.detail":
            return self.detail(user_id, lifecycle, modules)
        if method in {"users.grant", "users.retry"}:
            controller = UserController(self.store, modules)
            if method == "users.grant":
                grant = UserGrant(user_id, params["module"], params["enabled"])
                return {"revision": controller.change(grant, revision=params["revision"])}
            return {"revision": controller.reconcile(user_id, params["module"], revision=params["revision"])}
        subscriptions = SubscriptionService(self.store, modules, lambda: self.guard(lifecycle))
        if method == "users.profiles":
            profiles = subscriptions.profiles(user_id)
            if profiles is None:
                reject("user_export_unavailable")
            return {"profiles": list(profiles)}
        if method == "users.config":
            name = params["module"]
            if not isinstance(name, str) or name not in CONFIG_MODULES:
                reject("invalid_request")
            config = subscriptions.config(user_id, name)
            if config is None:
                reject("user_config_unavailable")
            return {"config": config.decode("ascii")}
        body = subscriptions.render(token)
        if body is None:
            reject("user_not_found")
        return {"body": body.decode("ascii")}

    def detail(self, user_id, lifecycle, modules):
        # Карточка не передаёт настройки модулей или материал ключей.
        user, revision, grants = self.store.get(user_id)
        assigned = {item.grant.module_id: item for item in grants}
        inventory = ({} if lifecycle is None else
                     {row["module"]: row for row in lifecycle.inventory.installed()})
        items = []
        for name in sorted(MODULE_IDS):
            stored = assigned.get(name)
            grant = stored or GrantState(UserGrant(user_id, name, False), False)
            row = inventory.get(name)
            if stored is None:
                status = "not_granted"
            elif row and row["enabled"] and name not in modules and grant.grant.enabled:
                status = "unsupported"
            else:
                try:
                    enabled = bool(row and row["enabled"])
                    state = (modules[name].state() if enabled and name in modules and grant.grant.enabled
                             and grant.applied and not grant.error else ModuleState(name, bool(row), enabled))
                    status = grant.status(user, state)
                except Exception:
                    status = "error"
            items.append({"module": name, "desired": grant.grant.enabled, "status": status})
        return {"id": user.id, "name": user.name, "enabled": user.enabled, "revision": revision, "grants": items}
