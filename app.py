from datetime import timedelta

from flask import Flask, render_template, session
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import db, User

mail = Mail()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    CSRFProtect(app)
    mail.init_app(app)

    # Auto-logout por inatividade (30 minutos)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Faça login para acessar esta página.'
    login_manager.login_message_category = 'error'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from routes import auth, org, vault, api
    app.register_blueprint(auth)
    app.register_blueprint(org)
    app.register_blueprint(vault)
    app.register_blueprint(api)

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
