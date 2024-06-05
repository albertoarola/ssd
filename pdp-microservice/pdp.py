from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_ldap3_login.forms import LDAPLoginForm
from ldap3 import Server, Connection, ALL, HASHED_SALTED_SHA256, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from flask_jwt_extended.exceptions import NoAuthorizationError
import requests
import json
from py_abac import Policy, AccessRequest, PDP
from py_abac.storage.memory import MemoryStorage

app = Flask(__name__)

app.secret_key = 'your_secret_key'

LDAP_HOST = 'ldap://ldap-server'
LDAP_BASE_DN = 'dc=mycompany,dc=com'
LDAP_BIND_USER_DN = 'cn=admin,dc=mycompany,dc=com'
LDAP_BIND_USER_PASSWORD = 'admin_password'

# Carica la policy dal file JSON
with open('policy.json', 'r') as f:
    policies_json = json.load(f)

storage = MemoryStorage()

for policy_json in policies_json:
    # Parse JSON and create policy object
    policy = Policy.from_json(policy_json)
    storage.add(policy)

# Inizializza il motore di controllo degli accessi con lo storage
pdp = PDP(storage)

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

@app.route('/evaluate', methods=['POST'])
def evaluate():
    # Parse JSON from request
    request_data = request.json

    # Estrai lo username e la risorsa dalla richiesta
    username = request_data.get('username')
    resource = request_data.get('resource')

    # Recupera il ruolo dell'utente (simulato per ora)
    # Qui potresti utilizzare una funzione o un servizio per recuperare il ruolo dell'utente in base allo username
    # In questo esempio, simuliamo il recupero del ruolo "medico" per tutti gli utenti
    user_role = get_user_title(username)

    # Crea l'oggetto AccessRequest utilizzando il ruolo dell'utente, la risorsa e l'azione "read"
    request_xacml = AccessRequest(subject={"id": username, "attributes": {"role": user_role}},
                            resource={"id": "", "attributes": {"name": resource}},
                            action={"id": "", "attributes": {"method": "read"}},
                            context={})

    # Valuta la richiesta
    decision = pdp.is_allowed(request_xacml)

    # Restituisci la decisione come risposta JSON
    return jsonify({"access_granted": decision})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5015)
