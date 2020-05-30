from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    SelectField,
    SelectMultipleField,
    FieldList,
    widgets,
)
from wtforms.validators import DataRequired, URL


class MultiCheckboxField(SelectMultipleField):
    """
    A multiple-select, except displays a list of checkboxes.

    Iterating the field will produce subfields, allowing custom rendering of
    the enclosed checkbox fields.
    """

    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class LoginForm(FlaskForm):
    username = StringField("username", validators=[DataRequired()])
    password = PasswordField("password", validators=[DataRequired()])
    remember = BooleanField("remember me")


class ClientForm(FlaskForm):
    client_name = StringField("Client name", validators=[DataRequired()])
    client_uri = StringField("Client URI", validators=[DataRequired(), URL()])
    redirect_uris = FieldList(
        StringField("Redirect URI", validators=[DataRequired(), URL()]), min_entries=1
    )
    grant_types = MultiCheckboxField(
        "Grant types",
        choices=[("authorization_code", "authorization_code")],
        validators=[DataRequired()],
        default=["authorization_code"],
    )
    response_types = MultiCheckboxField(
        "Response types",
        choices=[("code", "code")],
        validators=[DataRequired()],
        default=["code"],
    )

    token_endpoint_auth_method = SelectField(
        "Token endpoint authentication method",
        choices=[("client_secret_basic", "Basic"), ("client_secret_post", "POST"), ("client_secret_get", "Query args (DEPRECATED)")],
        validators=[DataRequired()],
    )

    scope = MultiCheckboxField(
        "Allowed scopes",
        choices=[("profile:read", "profile:read"), ("openid", "openid")],
        validators=[DataRequired()],
        default=["openid"],
    )
