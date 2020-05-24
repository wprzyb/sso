from environs import Env

env = Env()
env.read_env()

SECRET_KEY = env.str("SECRET_KEY", default="randomstring")

db_username = env.str("DATABASE_USERNAME", default="postgres")
db_password = env.str("DATABASE_PASSWORD", default="secret")
db_hostname = env.str("DATABASE_HOSTNAME", default="postgres")
db_name = env.str("DATABASE_NAME", default="postgres")
SQLALCHEMY_DATABASE_URI = env.str(
    "DATABASE_URI",
    default="postgresql+psycopg2://%s:%s@%s/%s"
    % (db_username, db_password, db_hostname, db_name),
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

LDAP_BIND_DN = env.str(
    "LDAP_BIND_DN", default="cn=auth,ou=Services,dc=hackerspace,dc=pl"
)
LDAP_BIND_PASSWORD = env.str("LDAP_BIND_PASSWORD", default="insert password here")
SQLALCHEMY_TRACK_MODIFICATIONS = False

PROXYFIX_ENABLE = env.bool('PROXYFIX_ENABLE', default=True)
PROXYFIX_NUM_PROXIES = env.int('PROXYFIX_NUM_PROXIES', default=1)

JWT_CONFIG = {
    "key": "secret-key",
    "alg": "HS256",
    "iss": "https://sso.hackerspace.pl",
    "exp": 3600,
}
