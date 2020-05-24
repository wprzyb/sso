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
from flask_login import login_required, current_user, login_user, logout_user
from sso.directory import LDAPUserProxy, check_credentials
from sso.models import db, Token
from sso.forms import LoginForm
from sso.oauth2 import authorization, require_oauth
from authlib.oauth2 import OAuth2Error
from authlib.integrations.flask_oauth2 import current_token


bp = Blueprint("sso", __name__)


@bp.route("/")
@bp.route("/profile")
@login_required
def profile():
    return render_template(
        "profile.html",
        tokens=Token.query.filter(Token.user_id == current_user.username),
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

        return redirect(next or url_for("profile"))

    return render_template("login_oauth.html", form=form, next=next)


@bp.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@bp.route("/oauth/authorize", methods=["GET", "POST"])
@login_required
def authorize():
    if request.method == "GET":
        try:
            grant = authorization.validate_consent_request(end_user=current_user)
        except OAuth2Error as error:
            return jsonify(dict(error.get_body()))
        return render_template(
            "oauthorize.html", user=current_user, grant=grant, client=grant.client
        )

    if request.form["confirm"]:
        grant_user = current_user
    else:
        grant_user = None

    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route("/oauth/token", methods=["POST"])
def issue_token():
    return authorization.create_token_response()


# HSWAW specific endpoint
@bp.route("/api/profile")
@bp.route("/api/1/profile")
@require_oauth("profile:read")
def api_profile():
    user = current_token.user
    print(user.email, user.username, user.gecos, user.phone, user.personal_email)
    return jsonify(
        email=user.email,
        username=user.username,
        gecos=user.gecos,
        phone=user.phone,
        personal_email=user.personal_email,
    )


# OpenIDConnect userinfo
@bp.route("/api/1/userinfo")
# @require_oauth("profile:read")
@require_oauth("openid")
def api_userinfo():
    user = current_token.user
    # user = LDAPUserProxy(flask.request.oauth.user)
    return jsonify(
        sub=user.username,
        name=user.gecos,
        email=user.email,
        preferred_username=user.username,
        nickname=user.username,
    )


@bp.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify(
        {
            "issuer": current_app.config['JWT_CONFIG']['iss'],
            "authorization_endpoint": url_for(".authorize", _external=True),
            "token_endpoint": url_for(".issue_token", _external=True),
            "userinfo_endpoint": url_for(".api_userinfo", _external=True),
            "response_types_supported": ["code", "id_token", "token id_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
        }
    )
