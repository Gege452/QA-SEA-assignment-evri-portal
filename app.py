# 
# 
#  IMPORTS
# 
# 

from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'S3cr3tK3y!!2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 
# 
#  Models
# 
# 

class CourierAdmin(UserMixin, db.Model):
    cra_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))

    def get_id(self):
        return f"admin-{self.cra_id}"

class Courier(UserMixin, db.Model):
    cr_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    region = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(100))
    active = db.Column(db.Boolean, default=True)
    pin_hash = db.Column(db.String(200))
    crtd_by_cra_id = db.Column(db.Integer, db.ForeignKey('courier_admin.cra_id'))

    def get_id(self):
        return f"courier-{self.cr_id}"

class CourierQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    submitted_by = db.Column(db.Integer, db.ForeignKey('courier.cr_id'))

# 
# 
#  Login manager
# 
# 

@login_manager.user_loader
def load_user(user_id):
    role, uid = user_id.split("-")
    if role == "admin":
        return CourierAdmin.query.get(int(uid))
    elif role == "courier":
        return Courier.query.get(int(uid))
    return None

# 
# 
#  Logout
# 
# 

    
@app.route('/logout')
# This part of the code will handle traffic to /logout
def logout():
    logout_user()
    # log the user out
    session.clear()
    # clear session details, making sure nothing remains stored
    return redirect(url_for('login'))
    # redirect user to the login page


# 
# 
#  Login
# 
# 


# Handling the login functionality on the website
# If statement will run based on whether the checkbox is checked on the login page or not
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        is_admin = request.form.get('is_admin')
        # Getting the value from the "form" or checkbox that is on the front-end
        if is_admin:
            # Rertrieving the email and password put in to the boxes on the login page
            email = request.form['email'].lower()
            password = request.form['password']
            # Variable will store the admin or false if the email and/or password doesn't match with what we stored in the database
            admin = CourierAdmin.query.filter_by(email=email).first()
            if admin and check_password_hash(admin.password_hash, password):
                # If the password hash of the admin entity matches with the password the user put in, the user will be logged in with the admin entity and gets redirected to the admin_dashboard page
                login_user(admin)
                return redirect(url_for('admin_dashboard'))
            else:
                # If the email does not exist or the password stored for it doesnt match, an error with 'Invalid admin credentials, please try again.' will show
                flash('Invalid admin credentials, please try again.')
        else:
            # Rertrieving the id and pin put in to the boxes on the login page
            cr_id = request.form['cr_id']
            pin = request.form['pin']
            # Variable will return the admin or false if the cr_id and/or pin doesn't match with what we stored in the database
            courier = Courier.query.filter_by(cr_id=cr_id).first()
            if courier and check_password_hash(courier.pin_hash, pin):
                # If the PIN hash of the courier entity matches with the PIN the user put in, the user will be logged in with the courier entity and gets redirected to the courier_dashboard page
                login_user(courier)
                return redirect(url_for('courier_dashboard'))
            else:
                # If the cr_id does not exist or the password stored for it doesnt match, an error with 'Invalid admin credentials, please try again.' will show
                flash('Invalid courier credentials, please try again.')
    return render_template('login.html')
    # load in login.html


# 
# 
#  Registration
# 
# 


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        is_admin = request.form.get('is_admin')
        if is_admin:
            # Admin registration logic
            name = request.form['admin_name']
            email = request.form['admin_email'].lower()
            password = request.form['admin_password']
            confirm = request.form['admin_confirm_password']

            if password != confirm:
                flash('Error: Passwords do not match.')
                return redirect(url_for('register'))
            
            if not email.endswith('@evri.com'):
                flash('Error: You must use your corporate email address (must end with @evri.com).')
                return redirect(url_for('register'))


            existing = CourierAdmin.query.filter_by(email=email).first()
            if existing:
                flash('Error: Email already registered.')
                return redirect(url_for('register'))

            new_admin = CourierAdmin(
                name=name,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_admin)
            db.session.commit()
            flash(f'Info: Admin account created successfully. Your admin email is {new_admin.cra_id}. Please use this to log in.')
            return redirect(url_for('login'))

        else:
            # Courier registration logic
            name = request.form['name']
            region = request.form['region']
            phone = request.form['phone']
            email = request.form['email']
            pin = request.form['pin']

            if not pin.isdigit() or len(pin) != 4:
                flash('Error: PIN must be exactly 4 digits.')
                return redirect(url_for('register'))

            new_courier = Courier(
                name=name,
                region=region,
                phone=phone,
                email=email,
                pin_hash=generate_password_hash(pin),
                crtd_by_cra_id=None  # Default if unknown
            )
            db.session.add(new_courier)
            db.session.commit()
            flash(f'Info: Courier account created. Your ID is {new_courier.cr_id}. Please use this ID to log in.')
            return redirect(url_for('login'))

    return render_template('register.html')


# 
# 
#  Admin dashboard
# 
# 


@app.route('/admin/dashboard')
# This part of the code will handle traffic to /admin/dashboard
@login_required
# We require the user to be logged in
def admin_dashboard():
    if not isinstance(current_user, CourierAdmin):
        # if logged in user is not admin, redirect user back to the login page
        return redirect(url_for('login'))
    couriers = Courier.query.all()
    # get a list of couriers, then render the admin dashboard with the couriers retrieved from the query above
    return render_template('admin_dashboard.html', couriers=couriers)
    # load in admin_dashboard.html


@app.route('/admin/queries')
@login_required
def admin_queries():
    if not isinstance(current_user, CourierAdmin):
        # if logged in user is not admin, redirect user back to the login page
        return redirect(url_for('login'))
    queries = CourierQuery.query.all()
    return render_template('admin_queries.html', queries=queries)


@app.route('/admin/create', methods=['GET', 'POST'])
# This part of the code will handle traffic to /admin/create
@login_required
# We require the user to be logged in
def create_courier():
    if not isinstance(current_user, CourierAdmin):
        # if logged in user is not admin, redirect user back to the login page
        return redirect(url_for('login'))
    if request.method == 'POST':
        cr_id = request.form['cr_id']
        name = request.form['name']
        region = request.form['region']
        phone = request.form['phone']
        email = request.form['email'].lower()
        pin = request.form['pin']
        # Above we are storing all the details retrieved from boxes/form on front-end in variables
        courier = Courier(
            cr_id=cr_id,
            name=name,
            region=region,
            phone=phone,
            email=email,
            pin_hash=generate_password_hash(pin),
            crtd_by_cra_id=current_user.cra_id
        )
        # Above we are creating a new courier entity with the details on the variables before this, while also hashing the pin, then storing the courier entity on a courier variable
        db.session.add(courier)
        db.session.commit()
        # Then we add the courier entity to the database and commit the changes
        flash('Courier created successfully.')
        # Show an info message saying 'Courier created successfully.'
        return redirect(url_for('admin_dashboard'))
        # return user back to the admin_dashboard page
    return render_template('create_courier.html')
    # load in create_courier.html

@app.route('/admin/edit/<int:cr_id>', methods=['GET', 'POST'])
# This part of the code will handle traffic to /admin/edit/{cr_id} - {cr_id} will always be different
@login_required
# We require the user to be logged in
def edit_courier(cr_id):
    # in this function we will get the cr_id arguement from the URL
    if not isinstance(current_user, CourierAdmin):
        # if logged in user is not admin, redirect user back to the login page
        return redirect(url_for('login'))
    courier = Courier.query.get_or_404(cr_id)
    # We'll query the DB for the courier entity or return a 404 and store that on the 'courier' variable
    if request.method == 'POST':
        courier.name = request.form['name']
        courier.region = request.form['region']
        courier.phone = request.form['phone']
        courier.email = request.form['email'].lower()
        courier.active = 'active' in request.form
        db.session.commit()
        # Above we will store all of the details from the form(front-end) for courier entity defined just above the if statement, then commit these changes to the db
        flash('Courier updated successfully.')
        # Show an info message saying 'Courier updated successfully.'
        return redirect(url_for('admin_dashboard'))
    # return user back to the admin_dashboard page
    return render_template('edit_courier.html', courier=courier)
    # load in edit_courier.html

@app.route('/admin/delete/<int:cr_id>', methods=['POST'])
# This part of the code will handle traffic to /admin/delete/{cr_id} - {cr_id} will always be different
@login_required
# We require the user to be logged in
def delete_courier(cr_id):
    # in this function we will get the cr_id arguement from the URL
    if not isinstance(current_user, CourierAdmin):
        # if logged in user is not admin, redirect user back to the login page
        return redirect(url_for('login'))
    courier = Courier.query.get_or_404(cr_id)
    # We'll query the DB for the courier entity or return a 404 and store that on the 'courier' variable
    db.session.delete(courier)
    db.session.commit()
    # We'll delete the record of this entity from the db and commit the changes
    flash('Courier deleted successfully.')
    # Show an info message saying 'Courier deleted successfully.'
    return redirect(url_for('admin_dashboard'))
    # return user back to the admin_dashboard page


# 
# 
#  Courier dashboard
# 
# 


@app.route('/courier/dashboard')
# This part of the code will handle traffic to /courier/dashboard
@login_required
# We require the user to be logged in
def courier_dashboard():
    if not isinstance(current_user, Courier):
        # if logged in user is not courier, redirect user back to the login page
        return redirect(url_for('login'))
    return render_template('courier_dashboard.html', courier=current_user)
    # load in courier_dashboard.html

@app.route('/courier/edit', methods=['GET', 'POST'])
# This part of the code will handle traffic to /courier/edit
@login_required
# We require the user to be logged in
def edit_own_info():
    if not isinstance(current_user, Courier):
        # if logged in user is not courier, redirect user back to the login page
        return redirect(url_for('login'))
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.region = request.form['region']
        current_user.phone = request.form['phone']
        current_user.email = request.form['email'].lower()
        db.session.commit()
        # Above we will store all of the details from the form(front-end) for the current courier entity, then commit these changes to the db
        flash('Profile updated successfully.')
        # Show an info message saying 'Profile updated successfully.'
        return redirect(url_for('courier_dashboard'))
        # return user back to the courier_dashboard page
    return render_template('edit_own_info.html', courier=current_user)
    # load in edit_own_info.html


# 
# 
#  Courier Queries
# 
# 


@app.route('/courier/queries')
@login_required
def view_queries():
    if not isinstance(current_user, Courier):
        return redirect(url_for('login'))
    queries = CourierQuery.query.filter_by(submitted_by=current_user.cr_id).all()
    return render_template('courier_queries.html', queries=queries)

@app.route('/courier/queries/new', methods=['GET', 'POST'])
@login_required
def new_query():
    if not isinstance(current_user, Courier):
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']
        query = CourierQuery(title=title, message=message, submitted_by=current_user.cr_id)
        db.session.add(query)
        db.session.commit()
        flash('Feedback submitted successfully.')
        return redirect(url_for('view_queries'))
    return render_template('new_query.html')

@app.route('/courier/queries/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_query(id):
    if not isinstance(current_user, Courier):
        return redirect(url_for('login'))
    query = CourierQuery.query.get_or_404(id)
    if query.submitted_by != current_user.cr_id:
        flash('Access denied.')
        return redirect(url_for('view_queries'))
    if request.method == 'POST':
        query.title = request.form['title']
        query.message = request.form['message']
        db.session.commit()
        flash('Feedback updated successfully.')
        return redirect(url_for('view_queries'))
    return render_template('edit_query.html', query=query)

@app.route('/courier/queries/delete/<int:id>', methods=['POST'])
@login_required
def delete_query(id):
    if not isinstance(current_user, Courier):
        return redirect(url_for('login'))
    query = CourierQuery.query.get_or_404(id)
    if query.submitted_by != current_user.cr_id:
        flash('Access denied.')
        return redirect(url_for('view_queries'))
    db.session.delete(query)
    db.session.commit()
    flash('Feedback deleted successfully.')
    return redirect(url_for('view_queries'))












if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)