"""Role-based access control with hashed API keys and an audit trail."""
import hashlib
import hmac
import secrets

ROLES = {
    "admin": {"*"},
    "analyst": {"scan:run", "scan:read", "threats:read", "threats:write",
                "reports:read", "access:read"},
    "viewer": {"scan:read", "threats:read", "reports:read"},
}


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


class AccessControl:
    def __init__(self, store):
        self.store = store

    def bootstrap(self, admin_key=""):
        """Ensure an admin exists. Returns a newly generated key (or None)."""
        if self.store.execute("SELECT 1 FROM users WHERE role='admin' AND active=1"):
            return None
        generated = not admin_key
        key = admin_key or secrets.token_urlsafe(32)
        self.store.execute("INSERT OR REPLACE INTO users VALUES (?,?,?,1)",
                           ("admin", "admin", hash_key(key)))
        return key if generated else None

    def create_user(self, name, role):
        if role not in ROLES:
            raise ValueError(f"unknown role: {role}")
        if not name or len(name) > 64 or not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError("invalid user name")
        if self.store.execute("SELECT 1 FROM users WHERE name=?", (name,)):
            raise ValueError("user exists")
        key = secrets.token_urlsafe(32)
        self.store.execute("INSERT INTO users VALUES (?,?,?,1)", (name, role, hash_key(key)))
        return key

    def authenticate(self, key):
        if not key:
            return None
        h = hash_key(key)
        rows = self.store.execute("SELECT name, role, key_hash FROM users WHERE key_hash=? AND active=1", (h,))
        if rows and hmac.compare_digest(rows[0][2], h):
            return {"name": rows[0][0], "role": rows[0][1]}
        return None

    @staticmethod
    def allowed(role, perm):
        perms = ROLES.get(role, set())
        return "*" in perms or perm in perms

    def list_users(self):
        return [{"name": n, "role": r, "active": bool(a)} for n, r, a in
                self.store.execute("SELECT name, role, active FROM users ORDER BY name")]

    def set_role(self, name, role):
        if role not in ROLES:
            raise ValueError(f"unknown role: {role}")
        return bool(self._update("UPDATE users SET role=? WHERE name=?", (role, name), name))

    def revoke(self, name):
        return bool(self._update("UPDATE users SET active=0 WHERE name=?", (name,), name))

    def _update(self, sql, args, name):
        if not self.store.execute("SELECT 1 FROM users WHERE name=?", (name,)):
            return False
        self.store.execute(sql, args)
        return True

    def audit(self, user, action, resource="", allowed=True, ip=""):
        self.store.add("audit", {"user": user, "action": action, "resource": resource,
                                 "allowed": allowed, "ip": ip})
