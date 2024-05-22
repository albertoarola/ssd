from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_ldap3_login.forms import LDAPLoginForm
from ldap3 import Server, Connection, ALL, HASHED_SALTED_SHA256, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException

app = Flask(__name__)

app.secret_key = 'your_secret_key'

# Configurazione per LDAP
app.config['LDAP_HOST'] = 'ldap://ldap-server'
app.config['LDAP_BASE_DN'] = 'dc=mycompany,dc=com'
app.config['LDAP_BIND_USER_DN'] = 'cn=admin,dc=mycompany,dc=com'
app.config['LDAP_BIND_USER_PASSWORD'] = 'admin_password'
app.config['LDAP_USER_SEARCH_SCOPE'] = 'SUBTREE'
app.config['LDAP_USER_OBJECT_FILTER'] = '(cn=%s)'
app.config['LDAP_USER_LOGIN_ATTR'] = 'cn'

# Configura il manager di login LDAP
ldap_manager = LDAP3LoginManager(app)

LDAP_HOST = 'ldap://ldap-server'
LDAP_BASE_DN = 'dc=mycompany,dc=com'
LDAP_BIND_USER_DN = 'cn=admin,dc=mycompany,dc=com'
LDAP_BIND_USER_PASSWORD = 'admin_password'

def add_user_to_ldap(username, firstname, lastname, email, password):
    try:
        server = Server(LDAP_HOST, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_USER_DN, password=LDAP_BIND_USER_PASSWORD, auto_bind=True)

        # Creazione del DN per il nuovo utente
        dn = f'cn={username},{LDAP_BASE_DN}'

        # Definizione degli attributi dell'utente
        attributes = {
            'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'cn': username,
            'givenName': firstname,
            'sn': lastname,
            'mail': email,
            'userPassword': password
        }

        # Aggiunta dell'utente al server LDAP
        conn.add(dn, attributes=attributes)

        # Controllo se l'aggiunta è andata a buon fine
        if conn.result['description'] == 'success':
            return True
        else:
            print(conn.result)
            return False

    except Exception as e:
        print(e)
        return False

def authenticate_ldap(username, password):
    try:
        server = Server(LDAP_HOST, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_USER_DN, password=LDAP_BIND_USER_PASSWORD, auto_bind=True)
        search_filter = f'(cn={username})'
        conn.search(search_base=LDAP_BASE_DN, search_filter=search_filter, attributes=['cn'])
        if conn.entries and conn.bind():
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False

@app.route('/')
def root():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    form = LDAPLoginForm()
    return render_template('login.html', form=form)


# Pagina di registrazione
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['first_name']
        lastname = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
    
        if add_user_to_ldap(username, firstname, lastname, email, password):
            return redirect(url_for('dashboard'))
        else:
            return "Aggiunta dell'utente fallita"

    return render_template('register.html')

# Autenticazione degli utenti con LDAP
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate_ldap(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return 'Autenticazione fallita'
    return render_template('login.html')
   
# Pagina di dashboard dopo il login
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')