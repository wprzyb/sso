from environs import Env

env = Env()
env.read_env()

SQLALCHEMY_TRACK_MODIFICATIONS = False

# This needs to be disabled when we use an additional proxy in front of our app
WTF_CSRF_SSL_STRICT = env.bool("WTF_CSRF_SSL_STRICT", default=False)

SECRET_KEY = env.str("SECRET_KEY", default="randomstring")

TESTING = env.bool("TESTING", default=False)

db_username = env.str("DATABASE_USERNAME", default="postgres")
db_password = env.str("DATABASE_PASSWORD", default="secret")
db_hostname = env.str("DATABASE_HOSTNAME", default="postgres")
db_name = env.str("DATABASE_NAME", default="postgres")
db_port = env.str("DATABASE_PORT", default="5432")
SQLALCHEMY_DATABASE_URI = env.str(
    "DATABASE_URI",
    default="postgresql+psycopg2://%s:%s@%s:%s/%s"
    % (db_username, db_password, db_hostname, db_port, db_name),
)

TEMPLATES_AUTO_RELOAD = env.bool("TEMPLATES_AUTO_RELOAD", default=False)

LDAP_STRIP_RE = env.str("LDAP_STRIP_RE", default=r'[()"\'&|<>=~!*]+')
LDAP_URL = env.str("LDAP_URL", default="ldaps://ldap.hackerspace.pl")
LDAP_DN_STRING = env.str(
    "LDAP_DN_STRING", default="uid=%s,ou=People,dc=hackerspace,dc=pl"
)
LDAP_PEOPLE_BASEDN = env.str(
    "LDAP_PEOPLE_BASEDN", default="ou=People,dc=hackerspace,dc=pl"
)
LDAP_UID_FILTER = env.str(
    "LDAP_UID_FILTER", default="(&(objectClass=hsMember)(uid=%s))"
)

LDAP_GROUPS_BASEDN = env.str(
    "LDAP_GROUPS_BASEDN", default="ou=Group,dc=hackerspace,dc=pl"
)
LDAP_GROUP_MEMBERSHIP_FILTER = env.str(
    "LDAP_GROUP_MEMBERSHIP_FILTER", default="(&(objectClass=*)(uniqueMember=%s))",
)

LDAP_BIND_DN = env.str(
    "LDAP_BIND_DN", default="cn=sso,ou=Services,dc=hackerspace,dc=pl"
)
LDAP_BIND_PASSWORD = env.str("LDAP_BIND_PASSWORD", default="insert password here")

PROXYFIX_ENABLE = env.bool("PROXYFIX_ENABLE", default=True)
PROXYFIX_NUM_PROXIES = env.int("PROXYFIX_NUM_PROXIES", default=1)

import pathlib
from authlib.jose import jwk

jwt_alg = env.str("JWT_ALG", default="HS256")

if jwt_alg == "HS256":
    jwt_privkey = env.str("JWT_SECRET_KEY", default=SECRET_KEY)
    JWT_PUBLIC_KEYS = []
else:
    jwt_privkey = jwk.dumps(env.path("JWT_PRIVATE_KEY").read_text(), kty="RSA")
    JWT_PUBLIC_KEYS = [
        jwk.dumps(pathlib.Path(pub).read_text(), kty="RSA")
        for pub in env.list("JWT_PUBLIC_KEYS")
    ]

JWT_CONFIG = {
    "key": jwt_privkey,
    "alg": jwt_alg,
    "iss": env.str("JWT_ISS", default="http://sso.lokal.hswro.org/"),
    "exp": env.int("JWT_EXP", default=3600),
}

LOGGING_LEVEL = env.str("LOGGING_LEVEL", default=None)
