from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_ldap3_login.forms import LDAPLoginForm
from ldap3 import Server, Connection, ALL, HASHED_SALTED_SHA256, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended.exceptions import NoAuthorizationError
import requests

app = Flask(__name__)

app.secret_key = 'your_secret_key'

LDAP_HOST = 'ldap://ldap-server'
LDAP_BASE_DN = 'dc=mycompany,dc=com'
LDAP_BIND_USER_DN = 'cn=admin,dc=mycompany,dc=com'
LDAP_BIND_USER_PASSWORD = 'admin_password'

def get_user_title(username):
    try:
        server = Server(LDAP_HOST, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_USER_DN, password=LDAP_BIND_USER_PASSWORD, auto_bind=True)
        search_filter = f'(cn={username})'
        conn.search(search_base=LDAP_BASE_DN, search_filter=search_filter, attributes=['title'])
        if conn.entries:
            user_entry = conn.entries[0]
            user_title = user_entry['title'].value
            
            return user_title  # Assuming role is a single value
        else:
            return "User not found"
    except Exception as e:
        print(e)
        return "Error during LDAP operation"

def evaluate_xacml_policy(username, resource):
    # Crea il payload della richiesta da inviare al PDP
    request_data = {
        "username": username,
        "resource": resource
    }

    # Invia la richiesta al PDP
    response = requests.post("http://pdp_microservice:5015/evaluate", json=request_data)
    response.raise_for_status()

    # Leggi la risposta JSON dal PDP
    response_data = response.json()

    # Ottieni la decisione restituita dal PDP
    access_granted = response_data.get("access_granted")

    return access_granted

    
@app.route('/homedoc')
def homedoc():
    username = request.cookies.get('username')
    if evaluate_xacml_policy(username, '/homedoc'):
        return render_template('homepage.html', username=username)
    else:
        return 'Accesso negato'
    
@app.route('/logoutdoc')
def logout():
    # Reindirizza alla prima applicazione per eseguire il logout completo
    return redirect('http://localhost/invalidate')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
