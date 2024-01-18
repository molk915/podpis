from flask import Flask, render_template, request, redirect, url_for, flash
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['UPLOAD_FOLDER'] = 'tmp'

def generate_key_pair():
    key = RSA.generate(2048)
    private_key, public_key = key.export_key().decode(), key.publickey().export_key().decode()
    return private_key, public_key

def import_key(key, is_private=True):
    try:
        return RSA.import_key(key)
    except ValueError as e:
        print(f"Error importing {'private' if is_private else 'public'} key: {e}")
        return None
def sign_file(private_key, file_path):
    try:
       private_key = RSA.import_key(private_key)

    except ValueError as e:
        print(f"Error importing private key: {e}")
        return None

    try:
        with open(file_path, 'rb') as file:
            data = file.read()
            if not data:
                print("Error: File is empty.")
                return None

        h = SHA256.new(data)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature
    except Exception as e:
        print(f"Error signing file: {e}")
        return None


def verify_signature(public_key, file_path, signature):
    with open(file_path, 'rb') as file:
        data = file.read()
    key = import_key(public_key, is_private=False)
    if key:
        h = SHA256.new(data)
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    private_key, public_key = generate_key_pair()
    flash(f'Private key:\n{private_key}\nPublic key:\n{public_key}')
    return redirect(url_for('index'))

@app.route('/verify_signature', methods=['POST'])
def verify_signature_route():
    public_key, file_path, signature = request.form['public_key'], request.form['file_path'], request.form['signature']
    result_message = 'Podpis jest poprawny.' if verify_signature(public_key, file_path, signature) else 'Podpis jest niepoprawny.'
    flash(result_message)
    return redirect(url_for('index'))

@app.route('/sign_file', methods=['POST'])
def sign_file_route():
    private_key = request.form['private_key']
    file = request.files['file']

    if not file or file.filename == '':
        flash('Brak lub nieprawidłowy plik')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    signature = sign_file(private_key, file_path)

    if signature:
        flash('Plik został podpisany pomyślnie.')
        flash(f'Podpis:\n{signature}')
        with open(file_path + ".sig", 'wb') as signature_file:
            signature_file.write(signature)
    else:
        flash('Błąd podczas podpisywania pliku.')

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)