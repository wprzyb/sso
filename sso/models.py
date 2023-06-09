from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin,
)
from authlib.oauth2.rfc6749.util import scope_to_list, list_to_scope
from sso.extensions import db
from sso.directory import LDAPUserProxy
from datetime import datetime


class Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(db.String(40), nullable=True)

    membership_required = db.Column(
        db.Boolean, nullable=False, default=True, server_default="1"
    )

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

    def revoke_tokens(self):
        """Revoke all active access/refresh tokens and authorization codes"""
        Token.query.filter(Token.client_id == self.client_id).delete()
        AuthorizationCode.query.filter(
            AuthorizationCode.client_id == self.client_id
        ).delete()


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

    @property
    def expires_at_dt(self):
        return datetime.fromtimestamp(self.get_expires_at())
