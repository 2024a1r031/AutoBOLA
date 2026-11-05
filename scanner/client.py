"""
Talks to the target API. Creates fresh test users (victim and attacker) and sends requests.
Every single test gets its own brand-new victim + attacker, so tests never disturb each other.
"""
from dataclasses import dataclass
import httpx
from .utils import fill, rand, dig


@dataclass
class User:
    username: str
    password: str
    token: str | None


class Target:
    def __init__(self, cfg, base_url):
        self.cfg = cfg
        self.base = base_url.rstrip("/")
        auth = cfg["auth"]
        self.header = auth.get("header", "Authorization")
        self.prefix = auth.get("prefix", "Bearer ")
        self.http = httpx.Client(timeout=10, follow_redirects=False)

    def call(self, method, path, token=None, body=None):
        headers = {}
        if token:
            headers[self.header] = self.prefix + token
        return self.http.request(method, self.base + path, headers=headers, json=body)

    def login(self, username, password):
        lg = self.cfg["auth"]["login"]
        r = self.call(lg.get("method", "POST"), lg["path"],
                      body=fill(lg["body"], username=username, password=password))
        try:
            data = r.json()
        except ValueError:
            return None
        return dig(data, lg["token_field"]) if isinstance(data, dict) else None

    def new_user(self, role):
        """Register + log in a brand new user, e.g. victim_a1b2c3d4."""
        name = f"{role}_{rand(8)}"
        password = "Pass#" + rand(8)
        reg = self.cfg["auth"]["register"]
        self.call(reg.get("method", "POST"), reg["path"],
                  body=fill(reg["body"], username=name, password=password))
        return User(name, password, self.login(name, password))

    def run_setup(self):
        """Optional one-time setup calls from the config (e.g. VAmPI's /createdb)."""
        for step in self.cfg.get("setup", []):
            try:
                self.call(step.get("method", "GET"), step["path"])
            except httpx.HTTPError:
                pass
