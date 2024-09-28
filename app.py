from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import MySQLdb.cursors
import re
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configurations de la base de données
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Initialisation de MySQL
mysql = MySQL(app)

@app.route('/')
def home():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE user_id = %s', (session['user_id'],))
        user = cursor.fetchone()
        return render_template('home.html', username=user['user_login'], user_date_new=user['user_date_new'], user_date_login=user['user_date_login'], loggedin=True)
    else:        
        flash("Vous n'êtes pas connecté, veuillez vous connecter.", 'info')
        return render_template('home.html', loggedin=False)

@app.route('/logout')
def logout():
    session.pop('_flashes', None)
    session.pop('loggedin', None)
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out !', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Vérification que les champs sont remplis
        if not email or not password:
            flash('Tous les champs sont obligatoires !', 'danger')
            return redirect(url_for('login'))

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE user_mail = %s', (email,))
        user = cursor.fetchone()

        # Vérification du mot de passe
        if user and bcrypt.check_password_hash(user['user_password'], password):
            cursor.execute('UPDATE user SET user_date_login = NOW() WHERE user_id = %s', (user['user_id'],))
            mysql.connection.commit()

            session['loggedin'] = True
            session['user_id'] = user['user_id']
            session['username'] = user['user_login']
            return redirect(url_for('home'))
        else:
            flash('Email ou mot de passe incorrect !', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        recheck_password = request.form.get('recheck_password')

        # Vérification que tous les champs sont remplis
        if not email or not username or not password or not recheck_password:
            flash('Tous les champs sont obligatoires !', 'danger')
            return redirect(url_for('register'))

        # Vérification du format de l'email
        if not is_valid_email(email):
            flash("L'adresse email n'est pas valide !", 'danger')
            return redirect(url_for('register'))

        # Vérification de la correspondance des mots de passe
        if password != recheck_password:
            flash('Les mots de passe ne correspondent pas !', 'danger')
            return redirect(url_for('register'))

        # Hash du mot de passe
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE user_mail = %s', (email,))
        account = cursor.fetchone()

        # Vérification si l'email est déjà utilisé
        if account:
            flash('Un compte existe déjà avec cet email !', 'danger')
        else:
            # Insertion des données de l'utilisateur dans la base de données
            cursor.execute('INSERT INTO user (user_login, user_password, user_mail, user_compte_id) VALUES (%s, %s, %s, %s)', (username, hashed_password, email, 0))
            mysql.connection.commit()
            flash('Compte créé avec succès!', 'success')

            # Connexion automatique après enregistrement
            session['loggedin'] = True
            session['user_id'] = cursor.lastrowid
            session['username'] = username

            return redirect(url_for('home'))

    return render_template('register.html')


def is_valid_email(email):
    # Expression régulière pour valider un format d'email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)


if __name__ == '__main__':
    app.run(debug=True)