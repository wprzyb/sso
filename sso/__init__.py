import flask
from sso.extensions import db, migrate, login_manager
from sso.oauth2 import config_oauth


def create_app():
    app = flask.Flask(
        __name__, template_folder="../templates", static_folder="../static"
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.from_object("sso.settings")

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    config_oauth(app)

    import sso.views

    app.register_blueprint(sso.views.bp)

    from werkzeug.middleware.proxy_fix import ProxyFix
    if app.config.get('PROXYFIX_ENABLE'):
        print('gnuj')
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            app.config.get('PROXYFIX_NUM_PROXIES'),
            app.config.get('PROXYFIX_NUM_PROXIES'),
            app.config.get('PROXYFIX_NUM_PROXIES'),
            app.config.get('PROXYFIX_NUM_PROXIES'),
        )

    return app
