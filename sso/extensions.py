import flask_sqlalchemy
import flask_migrate
import flask_login
from flask_wtf.csrf import CSRFProtect


db = flask_sqlalchemy.SQLAlchemy()
migrate = flask_migrate.Migrate()
login_manager = flask_login.LoginManager()
login_manager.login_view = "/login"
csrf = CSRFProtect()
