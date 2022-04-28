from flask import (
    Blueprint,
    render_template,
    abort,
    redirect,
    request,
    url_for,
    flash,
    jsonify,
    current_app,
)
import uuid
from functools import wraps
from flask_login import login_required, current_user, login_user, logout_user
from sso.extensions import csrf
from sso.directory import LDAPUserProxy, check_credentials
from sso.models import db, Token, Client
from sso.forms import LoginForm, ClientForm
from sso.utils import get_object_or_404
from sso.oauth2 import authorization, require_oauth, generate_user_info
from authlib.oauth2 import OAuth2Error
from authlib.common.security import generate_token
from authlib.integrations.flask_oauth2 import current_token


bp = Blueprint("sso", __name__)


def membership_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        print(current_user.is_membership_active)
        if current_user.is_anonymous or not current_user.is_membership_active:
            return render_template("membership_required.html")
        return fn(*args, **kwargs)

    return wrapped


@bp.route("/")
@bp.route("/profile")
@login_required
def profile():
    return render_template(
        "profile.html",
        tokens=Token.query.filter(Token.user_id == current_user.get_user_id()),
        clients=Client.query.filter(Client.owner_id == current_user.get_user_id()),
    )


@bp.route("/token/<int:id>/revoke", methods=["POST"])
@login_required
def token_revoke(id):
    token = Token.query.filter(
        Token.user_id == current_user.username, Token.id == id
    ).first()
    if not token:
        abort(404)
    db.session.delete(token)
    db.session.commit()
    return redirect("/")


@bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    next = request.args.get("next")
    if form.validate_on_submit():
        username, password = form.data["username"], form.data["password"]
        if not check_credentials(username, password):
            flash("Invalid username or password")
            return render_template("login_oauth.html", form=form, next=next)
        login_user(LDAPUserProxy(username), form.data["remember"])

        flash("Logged in successfully.")

        return redirect(next or url_for(".profile"))

    return render_template("login_oauth.html", form=form, next=next)


@bp.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@bp.route("/client/create", methods=["GET", "POST"])
@login_required
@membership_required
def client_create():
    form = ClientForm()

    if form.validate_on_submit():
        client = Client()
        client.client_id = str(uuid.uuid4())
        client.client_secret = generate_token()
        client.owner_id = current_user.get_user_id()
        client.set_client_metadata(form.data)

        db.session.add(client)
        db.session.commit()
        flash("Client has been created.", "success")
        return redirect(url_for(".client_edit", client_id=client.id))

    return render_template("client_edit.html", form=form)


@bp.route("/client/<client_id>", methods=["GET", "POST"])
@login_required
@membership_required
def client_edit(client_id):
    client = get_object_or_404(
        Client, Client.id == client_id, Client.owner_id == current_user.get_user_id()
    )

    form = ClientForm(obj=client)

    if form.validate_on_submit():
        client.set_client_metadata(form.data)
        db.session.commit()
        flash("Client has been changed.", "success")
        return redirect(url_for(".client_edit", client_id=client.id))

    return render_template("client_edit.html", client=client, form=form)


@bp.route("/client/<client_id>/destroy", methods=["GET", "POST"])
@login_required
@membership_required
def client_destroy(client_id):
    client = get_object_or_404(
        Client, Client.id == client_id, Client.owner_id == current_user.get_user_id()
    )

    if request.method == "POST":
        db.session.delete(client)
        client.revoke_tokens()
        db.session.commit()
        flash("Client destroyed.", "success")
        return redirect(url_for(".profile"))

    return render_template("confirm_destroy.html", client=client)


@bp.route("/client/<client_id>/regenerate", methods=["GET", "POST"])
@login_required
@membership_required
def client_regenerate_secret(client_id):
    client = get_object_or_404(
        Client, Client.id == client_id, Client.owner_id == current_user.get_user_id()
    )

    if request.method == "POST":
        client.client_secret = generate_token()

        if request.form.get("revoke") == "yes":
            client.revoke_tokens()

        db.session.commit()
        flash("Client secret regenerated.", "success")
        return redirect(url_for(".client_edit", client_id=client.id))

    return render_template("confirm_regenerate.html", client=client)


# OAuth API
@bp.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    try:
        grant = authorization.validate_consent_request(end_user=current_user)
    except OAuth2Error as error:
        return render_template("authorization_error.html", error=dict(error.get_body()))

    if grant.client.membership_required and not current_user.is_membership_active:
        return render_template("membership_required.html")

    if request.method == "GET":
        if Token.query.filter(
            Token.client_id == grant.client.client_id,
            Token.user_id == current_user.get_user_id(),
            Token.scope == grant.request.scope,
        ).count():
            # User has unrevoked token already - grant by default
            return authorization.create_authorization_response(grant_user=current_user)

        return render_template(
            "oauthorize.html",
            user=current_user,
            grant=grant,
            client=grant.client,
            scopes=grant.request.scope.split(),
        )

    if request.form["confirm"]:
        grant_user = current_user
    else:
        grant_user = None

    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route("/oauth/token", methods=["GET", "POST"])
@csrf.exempt
def issue_token():
    return authorization.create_token_response()


# HSWAW specific endpoint
@bp.route("/api/profile")
@bp.route("/api/1/profile")
@require_oauth("profile:read openid", "OR")
def api_profile():
    user = current_token.user

    if current_token.client.membership_required and not user.is_membership_active:
        abort(402)

    return jsonify(
        email=user.email,
        username=user.username,
        gecos=user.gecos,
        phone=user.phone,
        personal_email=user.personal_email,
    )


# OpenIDConnect userinfo
@bp.route("/api/1/userinfo")
@require_oauth("profile:read openid", "OR")
def api_userinfo():
    user = current_token.user

    if current_token.client.membership_required and not user.is_membership_active:
        abort(402)

    return jsonify(generate_user_info(user, current_token.scope))


@bp.route("/.well-known/jwks.json")
def jwks_endpoint():
    return jsonify({"keys": current_app.config["JWT_PUBLIC_KEYS"]})


@bp.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify(
        {
            "issuer": current_app.config["JWT_CONFIG"]["iss"],
            "authorization_endpoint": url_for(".authorize", _external=True),
            "token_endpoint": url_for(".issue_token", _external=True),
            "userinfo_endpoint": url_for(".api_userinfo", _external=True),
            "jwks_uri": url_for(".jwks_endpoint", _external=True),
            "response_types_supported": ["code", "id_token", "token id_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
        }
    )
