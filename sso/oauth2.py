from authlib.integrations.flask_oauth2 import AuthorizationServer, ResourceProtector
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_bearer_token_validator,
)
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core.grants import (
    OpenIDCode as _OpenIDCode,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.oidc.core import UserInfo
from authlib.common.urls import urlparse, url_decode
from werkzeug.security import gen_salt
from .extensions import db
from .models import Client, AuthorizationCode, Token
from .directory import LDAPUserProxy
from flask import current_app as app
import logging

log = logging.getLogger(__name__)


DUMMY_JWT_CONFIG = {
    "key": "secret-key",
    "alg": "HS256",
    "iss": "https://sso.hackerspace.pl",
    "exp": 3600,
}


def exists_nonce(nonce, req):
    exists = AuthorizationCode.query.filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)


def generate_user_info(user, scope):
    return UserInfo(sub=str(user.get_user_id()), name=user.username)


def create_authorization_code(client, grant_user, request):
    code = gen_salt(48)
    nonce = request.data.get("nonce")
    item = AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id=grant_user.get_id(),
        nonce=nonce,
    )
    db.session.add(item)
    db.session.commit()
    return code


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    def create_authorization_code(self, client, grant_user, request):
        return create_authorization_code(client, grant_user, request)

    def parse_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id
        ).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return LDAPUserProxy(authorization_code.user_id)


class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return app.config.get("JWT_CONFIG")

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


class ImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):
        return app.config.get("JWT_CONFIG")

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


class HybridGrant(_OpenIDHybridGrant):
    def create_authorization_code(self, client, grant_user, request):
        return create_authorization_code(client, grant_user, request)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self):
        return DUMMY_JWT_CONFIG

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


def _validate_client(query_client, client_id, state=None, status_code=400):
    if client_id is None:
        raise InvalidClientError(state=state, status_code=status_code)

    client = query_client(client_id)
    if not client:
        raise InvalidClientError(state=state, status_code=status_code)

    return client


def authenticate_client_secret_get(query_client, request):
    """Authenticates clients providing their secret via query args (either via GET or POST) request"""
    data = request.args
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    if client_id and client_secret:
        client = _validate_client(query_client, client_id, request.state)
        if client.check_token_endpoint_auth_method(
            "client_secret_get"
        ) and client.check_client_secret(client_secret):
            log.debug('Authenticate %s via "client_secret_get" ' "success", client_id)
            return client
    log.debug('Authenticate %s via "client_secret_get" ' "failed", client_id)


def save_token(token, request):
    if request.user:
        user_id = request.user.get_user_id()
    else:
        user_id = None
    client = request.client

    # FIXME: is this the correct way of handling this? left for backward
    # compatiblity
    toks = Token.query.filter_by(client_id=client.client_id, user_id=user_id)

    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    item = Token(client_id=client.client_id, user_id=user_id, **token)
    db.session.add(item)
    db.session.commit()


class CustomAuthorizationCodeGrant(AuthorizationCodeGrant):
    # kill me (inventory)
    TOKEN_ENDPOINT_HTTP_METHODS = ["GET", "POST"]
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_get",
        "none",
    ]

    def validate_token_request(self):
        # TODO apply this hack only on client_secret_get authentication method
        self.request.form = self.request.data

        return super(CustomAuthorizationCodeGrant, self).validate_token_request()


class CustomResourceProtector(ResourceProtector):
    def validate_request(self, scope, request, scope_operator="AND"):
        # damn you gerrit
        args = dict(url_decode(urlparse.urlparse(request.uri).query))
        if args.get("access_token"):
            token_string = args.get("access_token")
            return self._token_validators["bearer"](
                token_string, scope, request, scope_operator
            )

        return super(CustomResourceProtector, self).validate_request(
            scope, request, scope_operator
        )


authorization = AuthorizationServer()
require_oauth = CustomResourceProtector()


def config_oauth(app):
    query_client = create_query_client_func(db.session, Client)
    authorization.init_app(app, query_client=query_client, save_token=save_token)
    authorization.register_client_auth_method(
        "client_secret_get", authenticate_client_secret_get
    )

    # support all openid grants
    authorization.register_grant(
        CustomAuthorizationCodeGrant, [OpenIDCode(require_nonce=False)]
    )
    authorization.register_grant(ImplicitGrant)
    authorization.register_grant(HybridGrant)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, Token)
    require_oauth.register_token_validator(bearer_cls())
