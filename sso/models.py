from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin,
)
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from sso.extensions import db
from sso.directory import LDAPUserProxy


class Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(db.String(40), nullable=True)

    def __repr__(self):
        return "<Client %s>" % (self.client_id,)

    @property
    def scope(self):
        return self.client_metadata.get("scope", [])

    def get_allowed_scope(self, scope):
        if not scope:
            return ""
        allowed = set(self.scope)
        scopes = scope_to_list(scope)
        return list_to_scope([s for s in scopes if s in allowed])


class AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(40), nullable=False)


class Token(db.Model, OAuth2TokenMixin):
    __tablename__ = "oauth2_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(40), nullable=False)

    @property
    def user(self):
        return LDAPUserProxy(self.user_id)

    client_id = db.Column(db.String(48))
    client = db.relationship(
        "Client",
        primaryjoin="Token.client_id == Client.client_id",
        foreign_keys=[client_id],
    )
