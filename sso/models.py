from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2TokenMixin,
    OAuth2AuthorizationCodeMixin,
)
from sso.extensions import db
from sso.directory import LDAPUserProxy


class Client(db.Model, OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    id = db.Column(db.Integer, primary_key=True)


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
