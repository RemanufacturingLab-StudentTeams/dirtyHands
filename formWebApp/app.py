#app.py
from flask import Flask, Response,render_template, redirect, url_for, request, flash, session, jsonify, get_flashed_messages, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from datetime import datetime
from functools import wraps
import json
import csv
import io

### DISASSEMBLY APP HHS ###

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# date = datetime.now()
# date = date.strftime("%Y/%m/%d, %H:%M:%S")

# date = datetime.now().strftime("%Y/%m/%d, %H:%M:%S")

# User model

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False, unique=True)
    comment = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Product model
class ProductInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    brand_name = db.Column(db.String(100), nullable=False)
    model = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    parts = db.relationship('PartData', backref='product', lazy=True)
    date = db.Column(db.DateTime)

# Parts model
class PartData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product_info.id'), nullable=False)
    brand_name = db.Column(db.String(100))
    handling_id = db.Column(db.Integer)
    model = db.Column(db.String(100))
    id_number = db.Column(db.String(50))
    part_name = db.Column(db.String(50))
    parent_type = db.Column(db.String(50))
    parent_part = db.Column(db.String(50))
    part_number = db.Column(db.String(50))
    orientation = db.Column(db.String(50))
    connection_type = db.Column(db.String(50))
    tool_type = db.Column(db.String(50))
    force_required = db.Column(db.String(50))
    accessibility = db.Column(db.String(50))
    disassemble_time = db.Column(db.Integer)
    repetitions = db.Column(db.Integer)
    reusability = db.Column(db.String(50))
    comments = db.Column(db.Text)
    date = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)  # HTTP 403 Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    if current_user.is_authenticated:
        total_products = ProductInfo.query.count()
        last_10_products = ProductInfo.query.order_by(ProductInfo.id.desc()).limit(10).all()
        title = "Home"
        return render_template('home.html', title=title, products=last_10_products, total_products=total_products)
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    title = "Login"
    if request.method == 'POST':
        print(request.form)  # Debug: Print the entire form data
        if 'username' not in request.form:
            print("Key 'email' is missing in the form submission.")
            flash("Gebruikersnaam vereist.")
            return render_template('login.html', title=title)

        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login mislukt. Controleer gebruikersnaam en wachtwoord.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', title=title)

@app.route('/dashboard')
@login_required
def dashboard():
    title = "Dashboard"
    return render_template('dashboard.html', username=current_user.username, title=title)

@app.route('/disassemble')
@login_required
def disassemble():
    title = "Disassemble"
    return render_template('form.html', username=current_user.username, title=title)

import traceback

@app.route('/disassemble/submit', methods=['POST'])
@login_required
def submit_disassembly():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        # Date
        date = datetime.now()

        # date = datetime.now().strftime("%Y/%m/%d, %H:%M:%S")

        # Save Product Info
        product_info = ProductInfo(
            brand_name=data['productInfo']['brandName'],
            model=data['productInfo']['model'],
            description=data['productInfo']['description'],
            username=current_user.username,
            date = date
        )
        db.session.add(product_info)
        db.session.flush()  # Ensure product_info.id is available

        # Save Parts Data
        for part in data['partsData']:
            part_data = PartData(
                product_id=product_info.id,
                brand_name=data['productInfo']['brandName'],
                model=data['productInfo']['model'],
                handling_id = part.get('handlingId'),
                part_name=part.get('partDescription'),
                id_number=part.get('partId'),
                parent_type=part.get('parentType'),
                parent_part=part.get('parentPart'),
                part_number=part.get('partNumber'),
                orientation=part.get('orientation'),
                connection_type=part.get('connectionType'),
                tool_type=part.get('toolType'),
                force_required=part.get('forceRequired'),
                accessibility=part.get('accessibility'),
                disassemble_time=part.get('disassembleTime'),
                repetitions=part.get('repetitions'),
                reusability=part.get('reusability'),
                comments=part.get('comments'),
                date = date
            )
            db.session.add(part_data)

        db.session.commit()
        return jsonify({'success': True, 'message': 'Disassembly data submitted successfully!'})
    except Exception as e:
        db.session.rollback()
        traceback.print_exc()  # Print the full traceback to the terminal
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def users():
    title = "Users"

    if request.method == 'POST':
        username = request.form['username']
        comment = request.form['comment']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # Convert is_admin checkbox value to boolean
        is_admin = request.form.get('is_admin') == 'on'

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Gebruikersnaam bestaat al. Kies een andere gebruikersnaam.', 'danger')
            return redirect(url_for('users'))
        
        # If no user exists, create a new one
        new_user = User(username=username, comment=comment, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('Account aangemaakt.', 'success')
        print(get_flashed_messages())
        return redirect(url_for('users'))

    # Fetch users
    last_10_users = User.query.order_by(User.id.desc()).limit(10).all()
    return render_template('users.html', username=current_user.username, title=title, users=last_10_users)



@app.route('/users/edit', methods=['POST'])
@login_required
@admin_required
def edit_user():
    data = request.get_json()
    user_id = data.get('user_id')
    user = User.query.get_or_404(user_id)

    username = data.get('username')
    comment = data.get('comment')

    # Validate the new username if necessary
    if username and User.query.filter(User.username == username, User.id != user_id).first():
        return jsonify({'success': False, 'message': 'Gebruikersnaam bestaat al.'})

    user.username = username or user.username
    user.comment = comment or user.comment

    db.session.commit()
    return jsonify({'success': True})


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Gebruiker verwijderd.', 'success')
    return redirect(url_for('users'))

@app.route('/data')
@login_required
@admin_required
def data():
    last_10_products = ProductInfo.query.order_by(ProductInfo.id.desc()).limit(10).all()
    title = 'Data'
    return render_template('data.html', title=title, products=last_10_products)

import json
from datetime import datetime

@app.route('/data/download', methods=['GET'])
@login_required
@admin_required
def download_file():
    file_type = request.args.get('type', 'csv')  # Haal bestandstype uit query string
    data = PartData.query.all()  # Haal alle gegevens op uit de tabel
    columns = [column.name for column in PartData.__table__.columns]  # Dynamisch kolomnamen ophalen

    if file_type == 'csv':
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";")
        # Schrijf header dynamisch
        writer.writerow(columns)
        # Schrijf rijen
        for product in data:
            writer.writerow([getattr(product, column) for column in columns])
        output.seek(0)
        return Response(
            output,
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=products.csv"}
        )
    
    elif file_type == 'csv_comma':
        output = io.StringIO()
        writer = csv.writer(output)
        # Schrijf header dynamisch
        writer.writerow(columns)
        # Schrijf rijen
        for product in data:
            writer.writerow([getattr(product, column) for column in columns])
        output.seek(0)
        return Response(
            output,
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=products.csv"}
        )

    elif file_type == 'json':
        # Zet data om naar een lijst van dictionaries
        def custom_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()  # Converteer datetime naar ISO 8601 string
            raise TypeError(f"Type {type(obj)} is not JSON serializable")

        json_data = [{column: getattr(product, column) for column in columns} for product in data]
        return Response(
            response=json.dumps(json_data, ensure_ascii=False, default=custom_serializer),  # Serialize data naar JSON
            mimetype='application/json',
            headers={"Content-Disposition": "attachment;filename=products.json"}
        )

    return "Invalid file type", 400


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        #DEFAULT USER INIT
        if not User.query.filter_by(username='admin').first():
            default_user = User(
                username='admin',  
                password= bcrypt.generate_password_hash('admin'),
                comment='DEFAULT USER ADMIN',
                is_admin=True  
            )
            db.session.add(default_user)
            db.session.commit()
    app.run(debug=True)
