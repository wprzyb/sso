import re
import requests
import ldap
import logging
from cached_property import cached_property
from flask import current_app as app
from sso.extensions import login_manager


def connect_to_ldap():
    conn = ldap.initialize(app.config["LDAP_URL"])
    conn.simple_bind_s(app.config["LDAP_BIND_DN"], app.config["LDAP_BIND_PASSWORD"])
    return conn


def check_credentials(username, password):
    if app.config.get("TESTING") == True:
        return True

    conn = ldap.initialize(app.config["LDAP_URL"])
    try:
        conn.simple_bind_s(app.config["LDAP_DN_STRING"] % username, password)
        return True
    except ldap.LDAPError:
        return False


class LDAPUserProxy(object):
    def __init__(self, username):
        self.username = re.sub(app.config["LDAP_STRIP_RE"], "", username)
        self.is_authenticated = True
        self.is_anonymous = False

        if app.config.get("TESTING") == True:
            self.gecos = "Testing User"
            self.mifare_hashes = []
            self.phone = "123456789"
            self.personal_email = "testing@gmail.com"
            return

        conn = connect_to_ldap()
        res = conn.search_s(
            app.config["LDAP_PEOPLE_BASEDN"],
            ldap.SCOPE_SUBTREE,
            app.config["LDAP_UID_FILTER"] % self.username,
        )
        if len(res) != 1:
            raise Exception("No such username.")
        dn, data = res[0]

        self.username = data.get("uid", [b""])[0].decode() or None
        self.gecos = data.get("gecos", [b""])[0].decode() or None
        self.mifare_hashes = data.get("mifareIDHash", [])
        self.phone = data.get("mobile", [b""])[0].decode() or None
        self.personal_email = data.get("mailRoutingAddress", [b""])[0].decode() or None

    def __repr__(self):
        active = "active" if self.is_active else "inactive"
        return "<LDAPUserProxy {}, {}>".format(self.username, active)

    @property
    def email(self):
        return self.username + "@hackerspace.pl"

    @cached_property
    def is_active(self):
        url = "https://kasownik.hackerspace.pl/api/judgement/{}.json"
        try:
            r = requests.get(url.format(self.username))
            return bool(r.json()["content"])
        except Exception as e:
            logging.error("When getting data from Kasownik: {}".format(e))
            # Fail-safe.
            return True

    def get_id(self):
        return self.username

    # Required by authlib sqla integration
    def get_user_id(self):
        return self.get_id()


@login_manager.user_loader
def load_user(user_id):
    return LDAPUserProxy(user_id)
