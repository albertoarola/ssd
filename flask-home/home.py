from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_ldap3_login.forms import LDAPLoginForm
from ldap3 import Server, Connection, ALL, HASHED_SALTED_SHA256, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException

app = Flask(__name__)

app.secret_key = 'your_secret_key'


@app.route('/home')
def home():
    return render_template('homepage.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
