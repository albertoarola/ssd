from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_ldap3_login.forms import LDAPLoginForm
from ldap3 import Server, Connection, ALL, HASHED_SALTED_SHA256, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended.exceptions import NoAuthorizationError

app = Flask(__name__)

app.secret_key = 'your_secret_key'


@app.route('/homedoc')
def home():
    username = request.cookies.get('username')
    if username:
        return render_template('homepage.html', username=username)
    else:
        # L'utente non è loggato, reindirizza alla pagina di login
        return redirect('http://localhost/login')
    
@app.route('/logoutdoc')
def logout():
    # Reindirizza alla prima applicazione per eseguire il logout completo
    return redirect('http://localhost/invalidate')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
