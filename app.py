from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, jsonify
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from wtforms import StringField, TextAreaField, SelectField, DateField, IntegerField, PasswordField, EmailField, TelField, BooleanField
from wtforms.validators import DataRequired, NumberRange, Email, EqualTo, Optional
from models import db, Workplan, Deliverable, KPI, User, Evidence, AuditLog
from datetime import date, datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import json
from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import A4, letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import cm
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_change_this_in_production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///workplans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_NAME'] = 'workplan_session'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',
    'mp4', 'mov', 'avi', 'mkv', 'webm',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'
}

os.makedirs(os.path.join(app.root_path, app.config['UPLOAD_FOLDER']), exist_ok=True)

db.init_app(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Helper function for audit logging
def log_audit(action, entity_type, entity_id=None, entity_name=None, old_values=None, new_values=None):
    """Create an audit log entry"""
    if current_user.is_authenticated:
        audit = AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            entity_name=entity_name,
            old_values=json.dumps(old_values, default=str) if old_values else None,
            new_values=json.dumps(new_values, default=str) if new_values else None,
            ip_address=request.remote_addr
        )
        db.session.add(audit)
        db.session.commit()

# Helper function to check allowed files
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Forms
class LoginForm(FlaskForm):
    class Meta:
        csrf = False  # Completely disable CSRF for login
    
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me', default=False)
    
class RegisterForm(FlaskForm):
    class Meta:
        csrf = False  # Temporarily disable CSRF for testing
    
    username = StringField('Username', validators=[DataRequired()])
    mda_name = StringField('MDA Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = TelField('Phone Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('User', 'User'), ('Admin', 'Admin'), ('Superadmin', 'Superadmin')], default='User')
    
class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    mda_name = StringField('MDA Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = TelField('Phone Number', validators=[DataRequired()])
    password = PasswordField('New Password', validators=[Optional()])
    confirm_password = PasswordField('Confirm Password', validators=[Optional(), EqualTo('password')])
    role = SelectField('Role', choices=[('User', 'User'), ('Admin', 'Admin'), ('Superadmin', 'Superadmin')], default='User')

class WorkplanForm(FlaskForm):
    mda = StringField('MDA (Ministry/Department/Agency)', validators=[DataRequired()])
    project_title = StringField('Project Title', validators=[DataRequired()])
    objective = TextAreaField('Objective', validators=[DataRequired()])
    assigned_dept = StringField('Assigned Department', validators=[DataRequired()])
    collaborating_dept = StringField('Collaborating Department')
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    duration = IntegerField('Duration (days)', render_kw={'readonly': True})
    status = SelectField('Status', 
                        choices=[('Pending', 'Pending'), ('Started', 'Started'), 
                                ('Ongoing', 'Ongoing'), ('Pause', 'Pause'), ('Completed', 'Completed')],
                        default='Pending')

class EditWorkplanForm(FlaskForm):
    mda = StringField('MDA', validators=[DataRequired()])
    project_title = StringField('Project Title', validators=[DataRequired()])
    objective = TextAreaField('Objective', validators=[DataRequired()])
    assigned_dept = StringField('Assigned Department', validators=[DataRequired()])
    collaborating_dept = StringField('Collaborating Department')
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    duration = IntegerField('Duration (days)', render_kw={'readonly': True})
    status = SelectField('Status', 
                       choices=[('Pending', 'Pending'), ('Started', 'Started'), 
                               ('Ongoing', 'Ongoing'), ('Pause', 'Pause'), ('Completed', 'Completed')],
                       default='Pending')

# Role Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('🛡️ Admin access required!', 'danger')
            return redirect(url_for('users_list'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superadmin():
            flash('👑 Superadmin access required!', 'danger')
            return redirect(url_for('users_list'))
        return f(*args, **kwargs)
    return decorated_function

# Before request handler
@app.before_request
def before_request():
    public_routes = ['login', 'register', 'static']
    if request.endpoint in public_routes:
        return
    if current_user.is_authenticated:
        session['_fresh'] = session.get('_fresh', False)

# Auth Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    print("\n" + "="*60)
    print("🔥 REGISTER ROUTE EXECUTING")
    print("="*60)
    print(f"Request method: {request.method}")
    
    if current_user.is_authenticated:
        print("User already authenticated, logging out")
        logout_user()
        session.clear()
    
    form = RegisterForm()
    
    if request.method == 'POST':
        print("\n📨 POST REQUEST DETAILS:")
        print(f"Form data keys: {list(request.form.keys())}")
        print(f"Username: {request.form.get('username')}")
        print(f"MDA Name: {request.form.get('mda_name')}")
        print(f"Email: {request.form.get('email')}")
        print(f"Phone: {request.form.get('phone')}")
        print(f"Role: {request.form.get('role')}")
        print(f"Password present: {'Yes' if request.form.get('password') else 'No'}")
        print(f"Confirm password present: {'Yes' if request.form.get('confirm_password') else 'No'}")
        
        # Check CSRF
        csrf_token = request.form.get('csrf_token')
        print(f"CSRF token present: {'Yes' if csrf_token else 'No'}")
    
    if form.validate_on_submit():
        print("\n✅ FORM VALIDATION SUCCESSFUL")
        print(f"Username: {form.username.data}")
        print(f"Email: {form.email.data}")
        print(f"Role: {form.role.data}")
        
        # Check if email already exists
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            print(f"❌ Email already exists: {form.email.data}")
            flash('Email already registered!', 'danger')
            return render_template('register.html', form=form)
        
        # Check if username already exists
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            print(f"❌ Username already exists: {form.username.data}")
            flash('Username already taken! Please choose another one.', 'danger')
            return render_template('register.html', form=form)
        
        try:
            print("Creating new user...")
            user = User(
                username=form.username.data,
                mda_name=form.mda_name.data,
                email=form.email.data,
                phone=form.phone.data,
                role=form.role.data,
                edit_attempts=0
            )
            user.set_password(form.password.data)
            print(f"User object created: {user.username}")
            
            db.session.add(user)
            print("Added to session")
            
            db.session.commit()
            print(f"✅ COMMITTED to database with ID: {user.id}")
            
            log_audit('CREATE', 'User', user.id, user.username, None, 
                     {'username': user.username, 'email': user.email, 'role': user.role})
            
            flash('✅ Registration successful! Please log in.', 'success')
            print("✅ Registration complete, redirecting to login")
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ ERROR creating user: {str(e)}")
            import traceback
            traceback.print_exc()
            flash(f'Registration failed: {str(e)}', 'danger')
    else:
        if request.method == 'POST':
            print("\n❌ FORM VALIDATION FAILED")
            print(f"Form errors: {form.errors}")
            if form.errors:
                for field, errors in form.errors.items():
                    print(f"  {field}: {errors}")
    
    print("\n" + "="*60)
    print("Rendering register template")
    print("="*60 + "\n")
    
    return render_template('register.html', form=form)

# FIXED: Login route - properly named and implemented
@app.route('/login', methods=['GET', 'POST'])
def login():
    print("\n" + "="*60)
    print("🔥 LOGIN ROUTE EXECUTING")
    print("="*60)
    print(f"Request method: {request.method}")
    print(f"User authenticated: {current_user.is_authenticated}")
    
    # If user is already logged in, log them out first
    if current_user.is_authenticated:
        print("User already authenticated, logging out")
        logout_user()
        session.clear()
    
    form = LoginForm()
    
    if request.method == 'POST':
        print("\n📨 POST REQUEST DETAILS:")
        print(f"Form data keys: {list(request.form.keys())}")
        print(f"Email field present: {'email' in request.form}")
        print(f"Password field present: {'password' in request.form}")
        print(f"CSRF token present: {'csrf_token' in request.form}")
        
        # Try to validate the form
        print("\n🔄 Attempting form validation...")
        is_valid = form.validate_on_submit()
        print(f"Form validation result: {is_valid}")
        
        if not is_valid:
            print(f"❌ Form errors: {form.errors}")
            
            # Check individual field errors
            if form.email.errors:
                print(f"   Email errors: {form.email.errors}")
            if form.password.errors:
                print(f"   Password errors: {form.password.errors}")
            if form.remember.errors:
                print(f"   Remember errors: {form.remember.errors}")
        
        if is_valid:
            print("\n✅ Form validation passed!")
            email = form.email.data
            password = form.password.data
            remember = form.remember.data
            
            print(f"Looking up user with email: {email}")
            user = User.query.filter_by(email=email).first()
            
            if user:
                print(f"✅ User found: {user.username} (ID: {user.id}, Role: {user.role})")
                print(f"Checking password...")
                if user.check_password(password):
                    print("✅ Password correct!")
                    
                    # Set up session
                    session['_fresh'] = True
                    session.permanent = remember
                    
                    # Login user
                    login_user(user, remember=remember)
                    print(f"✅ User logged in successfully")
                    
                    # Log audit
                    log_audit('LOGIN', 'User', user.id, user.username)
                    
                    flash(f'✅ Welcome back, {user.username}!', 'success')
                    
                    # 🔥 REDIRECT BASED ON ROLE
                    if user.is_admin():
                        print("🔄 Redirecting admin to users_list")
                        return redirect(url_for('users_list'))
                    else:
                        print(f"🔄 Redirecting user to their projects (ID: {user.id})")
                        return redirect(url_for('user_projects', user_id=user.id))
                else:
                    print("❌ Password incorrect")
            else:
                print(f"❌ No user found with email: {email}")
            
            flash('❌ Invalid email or password!', 'danger')
        else:
            print("\n❌ Form validation failed - showing form again")
    else:
        print("✅ GET request - showing login form")
    
    print("\n" + "="*60)
    print("Rendering login template")
    print("="*60 + "\n")
    
    return render_template('login.html', form=form)

# FIXED: Logout route - properly separated
@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        log_audit('LOGOUT', 'User', current_user.id, current_user.username)
        logout_user()
        session.clear()
    flash('👋 You have been logged out.', 'info')
    return redirect(url_for('login'))

# Main Routes
@app.route('/')
def root():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # 🔥 REDIRECT BASED ON ROLE
    if current_user.is_admin():
        print(f"🔄 Root - Admin {current_user.username} redirected to users_list")
        return redirect(url_for('users_list'))
    else:
        print(f"🔄 Root - User {current_user.username} redirected to their projects")
        return redirect(url_for('user_projects', user_id=current_user.id))

@app.route('/users')
@login_required
def users_list():
    if not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Get project counts for each user
    for user in users.items:
        user.project_count = Workplan.query.filter_by(created_by=user.id).count()
        user.completed_count = Workplan.query.filter_by(created_by=user.id, status='Completed').count()
    
    # Get status counts for navbar
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    return render_template('users_list.html', users=users, status_counts=status_counts)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_superadmin():
        flash('Access denied!', 'danger')
        return redirect(url_for('users_list'))
    
    form = RegisterForm()
    
    # Get status counts for navbar
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already exists!', 'danger')
            return render_template('add_user.html', form=form, status_counts=status_counts)
        
        user = User(
            username=form.username.data,
            mda_name=form.mda_name.data,
            email=form.email.data,
            phone=form.phone.data,
            role=form.role.data,
            edit_attempts=0
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        
        log_audit('CREATE', 'User', user.id, user.username)
        flash(f'User {user.username} created successfully!', 'success')
        return redirect(url_for('users_list'))
    
    return render_template('add_user.html', form=form, status_counts=status_counts)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.is_superadmin():
        flash('Access denied!', 'danger')
        return redirect(url_for('users_list'))
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Cannot edit your own account!', 'danger')
        return redirect(url_for('users_list'))
    
    form = EditUserForm(obj=user)
    
    # Get status counts for navbar
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    if form.validate_on_submit():
        if User.query.filter(User.email == form.email.data, User.id != id).first():
            flash('Email already exists!', 'danger')
            return render_template('edit_user.html', form=form, user=user, status_counts=status_counts)
        
        user.username = form.username.data
        user.mda_name = form.mda_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.role = form.role.data
        if form.password.data:
            user.set_password(form.password.data)
        
        db.session.commit()
        log_audit('UPDATE', 'User', user.id, user.username)
        flash(f'User {user.username} updated!', 'success')
        return redirect(url_for('users_list'))
    
    return render_template('edit_user.html', form=form, user=user, status_counts=status_counts)

@app.route('/users/delete/<int:id>')
@login_required
def delete_user(id):
    if not current_user.is_superadmin():
        flash('Access denied!', 'danger')
        return redirect(url_for('users_list'))
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Cannot delete your own account!', 'danger')
        return redirect(url_for('users_list'))
    
    try:
        username = user.username
        
        # Delete associated audit logs first
        AuditLog.query.filter_by(user_id=id).delete()
        
        # Now delete the user
        db.session.delete(user)
        db.session.commit()
        
        log_audit('DELETE', 'User', id, username)
        flash(f'User {username} deleted!', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user: {str(e)}")
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('users_list'))

@app.route('/user/<int:user_id>/projects')
@login_required
def user_projects(user_id):
    # 🔥 PERMISSION CHECK - Users can only see their own projects, admins can see any
    if not current_user.is_admin() and current_user.id != user_id:
        flash('Access denied! You can only view your own projects.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    search_term = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    
    # Get status counts for navbar
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    # Get user's workplans with filters
    query = Workplan.query.filter_by(created_by=user_id)
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if search_term:
        workplans = query.filter(
            db.or_(
                Workplan.mda.ilike(f'%{search_term}%'),
                Workplan.project_title.ilike(f'%{search_term}%')
            )
        ).order_by(Workplan.created_at.desc()).all()
    else:
        workplans = query.order_by(Workplan.created_at.desc()).all()
    
    # Calculate stats
    if workplans:
        total_completion = sum(float(wp.completion_from_deliverables or 0) for wp in workplans)
        avg_completion = round(total_completion / len(workplans), 1)
        project_count = len(workplans)
    else:
        avg_completion = 0.0
        project_count = 0
    
    # 🔥 DEBUG OUTPUT
    print(f"\n{'='*50}")
    print(f"USER PROJECTS PAGE - User: {user.username} (Role: {user.role})")
    print(f"Viewing by: {current_user.username} (Role: {current_user.role})")
    print(f"Projects found: {project_count}")
    print(f"{'='*50}\n")
    
    return render_template('user_projects.html', 
                         workplans=workplans,
                         user=user,
                         status_counts=status_counts,
                         avg_completion=avg_completion,
                         project_count=project_count,
                         search_term=search_term,
                         current_filter=status_filter)

@app.route('/mda-performance')
@login_required
def mda_performance():
    if not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    # Get all users grouped by MDA
    users = User.query.all()
    mda_performance = {}
    
    for user in users:
        mda = user.mda_name
        if mda not in mda_performance:
            mda_performance[mda] = {
                'total_projects': 0,
                'completed_projects': 0,
                'avg_completion': 0,
                'total_completion': 0,
                'users': [],
                'projects': []
            }
        
        mda_performance[mda]['users'].append(user.username)
        projects = Workplan.query.filter_by(created_by=user.id).all()
        for project in projects:
            mda_performance[mda]['projects'].append(project)
            mda_performance[mda]['total_projects'] += 1
            mda_performance[mda]['total_completion'] += project.completion_from_deliverables
            if project.status == 'Completed':
                mda_performance[mda]['completed_projects'] += 1
    
    # Calculate averages
    for mda, data in mda_performance.items():
        if data['total_projects'] > 0:
            data['avg_completion'] = round(data['total_completion'] / data['total_projects'], 1)
    
    # Sort by average completion
    mda_performance = dict(sorted(mda_performance.items(), 
                                 key=lambda x: x[1]['avg_completion'], 
                                 reverse=True))
    
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    return render_template('mda_performance.html', 
                         mda_performance=mda_performance,
                         status_counts=status_counts,
                         can_edit=current_user.is_superadmin())

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_workplan():
    form = WorkplanForm()
    
    if form.validate_on_submit():
        duration = (form.end_date.data - form.start_date.data).days + 1
        workplan = Workplan(
            created_by=current_user.id,
            mda=form.mda.data,
            project_title=form.project_title.data,
            objective=form.objective.data,
            assigned_dept=form.assigned_dept.data,
            collaborating_dept=form.collaborating_dept.data or None,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            duration=duration,
            completion_percentage=0,
            status=form.status.data
        )
        db.session.add(workplan)
        db.session.commit()
        
        log_audit('CREATE', 'Workplan', workplan.id, workplan.project_title, None, {
            'title': workplan.project_title,
            'mda': workplan.mda,
            'status': workplan.status
        })
        
        flash(f'✅ Workplan "{workplan.project_title}" created!', 'success')
        return redirect(url_for('edit_workplan', id=workplan.id))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'❌ {field}: {error}', 'danger')
    
    # Get status counts for navbar
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    return render_template('add.html', form=form, status_counts=status_counts)

@app.route('/view/<int:id>')
@login_required
def view_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    # 🔥 FIXED: Check if user can edit using workplan.edit_attempts instead of user.can_edit_project()
    if current_user.is_admin() or current_user.is_superadmin():
        can_edit = True
    elif workplan.created_by == current_user.id:
        can_edit = workplan.edit_attempts < 5  # Allow edit if under 5 attempts
    else:
        can_edit = False
    
    return render_template('view.html', workplan=workplan, status_counts=status_counts, can_edit=can_edit)
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    # Permission check with edit attempt limit
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    # Check edit attempts for regular users
    if not current_user.is_admin() and workplan.created_by == current_user.id:
        if workplan.edit_attempts >= 5:
            flash('❌ You have reached the maximum number of edits (5) for this project. Contact admin for changes.', 'danger')
            return redirect(url_for('view_workplan', id=workplan.id))
    
    # Store original values for audit
    original_data = {
        'mda': workplan.mda,
        'project_title': workplan.project_title,
        'objective': workplan.objective,
        'assigned_dept': workplan.assigned_dept,
        'collaborating_dept': workplan.collaborating_dept,
        'start_date': str(workplan.start_date) if workplan.start_date else None,
        'end_date': str(workplan.end_date) if workplan.end_date else None,
        'status': workplan.status
    }
    
    form = EditWorkplanForm(obj=workplan)
    
    if form.validate_on_submit():
        # Check for critical changes
        critical_changes = (
            form.mda.data != original_data['mda'] or
            form.project_title.data != original_data['project_title'] or
            form.objective.data != original_data['objective'] or
            form.assigned_dept.data != original_data['assigned_dept'] or
            form.collaborating_dept.data != original_data['collaborating_dept'] or
            str(form.start_date.data) != original_data['start_date'] or
            str(form.end_date.data) != original_data['end_date']
        )
        
        was_approved = (workplan.status == 'Approved')
        
        # Capture new values before update
        new_data = {
            'mda': form.mda.data,
            'project_title': form.project_title.data,
            'objective': form.objective.data,
            'assigned_dept': form.assigned_dept.data,
            'collaborating_dept': form.collaborating_dept.data,
            'start_date': str(form.start_date.data),
            'end_date': str(form.end_date.data),
            'status': form.status.data
        }
        
        form.populate_obj(workplan)
        workplan.duration = (workplan.end_date - workplan.start_date).days + 1
        
        # Only reset approval if critical fields changed
        if critical_changes and was_approved:
            workplan.status = 'Pending'
            workplan.approved_at = None
            workplan.approver_id = None
            workplan.admin_comment = None
            approval_reset = True
        else:
            approval_reset = False
        
        workplan.completion_percentage = workplan.completion_from_deliverables
        
        # Increment edit attempts for this workplan
        if not current_user.is_admin() and workplan.created_by == current_user.id:
            workplan.edit_attempts += 1
        
        db.session.commit()
        
        # Log the edit
        log_audit('UPDATE', 'Workplan', workplan.id, workplan.project_title, original_data, new_data)
        
        if was_approved:
            if approval_reset:
                flash('⚠️ Workplan updated. Status reset to PENDING - needs re-approval.', 'warning')
            else:
                flash('✅ Workplan updated. Status remains APPROVED.', 'success')
        else:
            flash('✅ Workplan updated successfully!', 'success')
        
        return redirect(url_for('view_workplan', id=workplan.id))
    
    # Get status counts for navbar
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    return render_template('edit.html', workplan=workplan, form=form, status_counts=status_counts)

# 🔥 RESET ROUTES - Only these two, no duplicates
@app.route('/users/reset-edits/<int:id>')
@login_required
def reset_user_edits(id):
    """Reset edit attempts for all workplans of a specific user (Superadmin only)"""
    if not current_user.is_superadmin():
        flash('Access denied! Superadmin privileges required.', 'danger')
        return redirect(url_for('users_list'))
    
    user = User.query.get_or_404(id)
    
    if user.role != 'User':
        flash('Can only reset edit attempts for regular users.', 'warning')
        return redirect(url_for('users_list'))
    
    # Reset all workplans for this user
    workplans = Workplan.query.filter_by(created_by=id).all()
    count = 0
    
    for workplan in workplans:
        if workplan.edit_attempts > 0:
            workplan.edit_attempts = 0
            count += 1
    
    db.session.commit()
    
    log_audit('UPDATE', 'User', user.id, user.username, 
             {'action': 'reset_workplan_edits'}, {'workplans_reset': count})
    
    flash(f'✅ Reset edit attempts for {count} workplans belonging to {user.username}', 'success')
    return redirect(url_for('users_list'))

@app.route('/users/reset-all-edits')
@login_required
def reset_all_user_edits():
    """Reset edit attempts for ALL workplans (Superadmin only)"""
    if not current_user.is_superadmin():
        flash('Access denied! Superadmin privileges required.', 'danger')
        return redirect(url_for('users_list'))
    
    workplans = Workplan.query.all()
    count = 0
    
    for workplan in workplans:
        if workplan.edit_attempts > 0:
            workplan.edit_attempts = 0
            count += 1
    
    db.session.commit()
    
    log_audit('UPDATE', 'Workplan', 0, 'Bulk Reset', 
             {'action': 'reset_all_edits'}, {'workplans_reset': count})
    
    flash(f'✅ Reset edit attempts for {count} workplans', 'success')
    return redirect(url_for('users_list'))

@app.route('/approve/<int:workplan_id>', methods=['POST'])
@login_required
def approve_workplan(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    if not current_user.is_admin():
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('view_workplan', id=workplan_id))
    
    admin_comment = request.form.get('admin_comment', '').strip()
    
    old_status = workplan.status
    workplan.status = 'Approved'
    workplan.admin_comment = admin_comment
    workplan.approved_at = datetime.utcnow()
    workplan.approver_id = current_user.id
    
    db.session.commit()
    
    log_audit('APPROVE', 'Workplan', workplan.id, workplan.project_title, 
             {'status': old_status}, {'status': 'Approved'})
    
    flash(f'✅ "{workplan.project_title}" approved!', 'success')
    return redirect(url_for('user_projects', user_id=workplan.created_by))

@app.route('/reject/<int:workplan_id>', methods=['POST'])
@login_required
def reject_workplan(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    if not current_user.is_admin():
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('view_workplan', id=workplan_id))
    
    admin_comment = request.form.get('admin_comment', '').strip()
    if not admin_comment:
        flash('❌ Rejection reason required!', 'danger')
        return redirect(url_for('view_workplan', id=workplan_id))
    
    old_status = workplan.status
    workplan.status = 'Rejected'
    workplan.admin_comment = admin_comment
    workplan.approved_at = None
    workplan.approver_id = current_user.id
    
    db.session.commit()
    
    log_audit('REJECT', 'Workplan', workplan.id, workplan.project_title,
             {'status': old_status}, {'status': 'Rejected'})
    
    flash(f'❌ "{workplan.project_title}" rejected!', 'danger')
    return redirect(url_for('user_projects', user_id=workplan.created_by))

@app.route('/toggle_deliverable/<int:deliverable_id>', methods=['POST'])
@login_required
def toggle_deliverable(deliverable_id):
    deliverable = Deliverable.query.get_or_404(deliverable_id)
    workplan = Workplan.query.get(deliverable.workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if evidence is required and missing
    if deliverable.requires_evidence and not deliverable.completed:
        if not deliverable.evidence_files or len(deliverable.evidence_files) == 0:
            return jsonify({'error': 'Evidence required before marking as complete'}), 400
    
    old_completed = deliverable.completed
    deliverable.completed = not deliverable.completed
    
    if deliverable.completed:
        deliverable.completed_at = datetime.utcnow()
        deliverable.completed_by = current_user.id
    else:
        deliverable.completed_at = None
        deliverable.completed_by = None
    
    db.session.commit()
    
    new_completion = workplan.completion_from_deliverables
    workplan.completion_percentage = new_completion
    db.session.commit()
    
    log_audit('UPDATE', 'Deliverable', deliverable.id, deliverable.description,
             {'completed': old_completed}, {'completed': deliverable.completed})
    
    return jsonify({
        'success': True,
        'completed': deliverable.completed,
        'new_completion': new_completion,
        'completed_count': sum(1 for d in workplan.deliverables if d.completed),
        'total_count': len(workplan.deliverables)
    })

@app.route('/upload_evidence/<int:deliverable_id>', methods=['POST'])
@login_required
def upload_evidence(deliverable_id):
    deliverable = Deliverable.query.get_or_404(deliverable_id)
    workplan = Workplan.query.get(deliverable.workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = int(time.time())
    safe_filename = f"{timestamp}_{filename}"
    
    deliverable_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], f"deliverable_{deliverable_id}")
    os.makedirs(deliverable_folder, exist_ok=True)
    
    file_path = os.path.join(deliverable_folder, safe_filename)
    file.save(file_path)
    
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp']:
        file_type = 'image'
    elif ext in ['mp4', 'mov', 'avi', 'mkv', 'webm']:
        file_type = 'video'
    else:
        file_type = 'document'
    
    evidence = Evidence(
        deliverable_id=deliverable_id,
        filename=filename,
        file_path=os.path.join(f"deliverable_{deliverable_id}", safe_filename),
        file_type=file_type,
        file_size=os.path.getsize(file_path),
        uploaded_by=current_user.id
    )
    
    db.session.add(evidence)
    db.session.commit()
    
    log_audit('CREATE', 'Evidence', evidence.id, filename, None, {
        'filename': filename,
        'deliverable_id': deliverable_id,
        'file_type': file_type
    })
    
    # Auto-mark deliverable as completed if evidence is uploaded
    if not deliverable.completed:
        deliverable.completed = True
        deliverable.completed_at = datetime.utcnow()
        deliverable.completed_by = current_user.id
        workplan.completion_percentage = workplan.completion_from_deliverables
        db.session.commit()
    
    return jsonify({
        'success': True,
        'evidence': {
            'id': evidence.id,
            'filename': evidence.filename,
            'file_type': evidence.file_type,
            'file_size': evidence.file_size,
            'file_size_formatted': evidence.file_size_formatted,
            'uploaded_at': evidence.uploaded_at.strftime('%Y-%m-%d %H:%M'),
            'icon_class': evidence.icon_class,
            'url': url_for('download_evidence', evidence_id=evidence.id)
        }
    })

@app.route('/download_evidence/<int:evidence_id>')
@login_required
def download_evidence(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    deliverable = evidence.deliverable
    workplan = deliverable.workplan
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    file_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], evidence.file_path)
    
    if not os.path.exists(file_path):
        flash('❌ File not found!', 'danger')
        return redirect(url_for('view_workplan', id=workplan.id))
    
    log_audit('DOWNLOAD', 'Evidence', evidence.id, evidence.filename)
    
    return send_file(file_path, as_attachment=True, download_name=evidence.filename)

@app.route('/delete_evidence/<int:evidence_id>', methods=['POST'])
@login_required
def delete_evidence(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    deliverable = evidence.deliverable
    workplan = deliverable.workplan
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    file_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], evidence.file_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(evidence)
    db.session.commit()
    
    log_audit('DELETE', 'Evidence', evidence_id, evidence.filename, {'filename': evidence.filename}, None)
    
    return jsonify({'success': True})

@app.route('/add_deliverable/<int:workplan_id>', methods=['POST'])
@login_required
def add_deliverable(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('edit_workplan', id=workplan_id))
    
    description = request.form.get('description', '').strip()
    requires_evidence = request.form.get('requires_evidence') == 'on'
    
    if not description:
        flash('❌ Description required!', 'danger')
        return redirect(url_for('edit_workplan', id=workplan_id))
    
    deliverable = Deliverable(
        workplan_id=workplan.id, 
        description=description, 
        completed=False,
        requires_evidence=requires_evidence
    )
    db.session.add(deliverable)
    db.session.commit()
    
    workplan.completion_percentage = workplan.completion_from_deliverables
    db.session.commit()
    
    log_audit('CREATE', 'Deliverable', deliverable.id, description, None, {
        'description': description,
        'requires_evidence': requires_evidence
    })
    
    flash(f'✅ Added: "{description}"', 'success')
    return redirect(url_for('edit_workplan', id=workplan_id))

@app.route('/delete_deliverable/<int:deliverable_id>')
@login_required
def delete_deliverable(deliverable_id):
    deliverable = Deliverable.query.get_or_404(deliverable_id)
    workplan = Workplan.query.get(deliverable.workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    description = deliverable.description
    db.session.delete(deliverable)
    db.session.commit()
    
    workplan.completion_percentage = workplan.completion_from_deliverables
    db.session.commit()
    
    log_audit('DELETE', 'Deliverable', deliverable_id, description, {'description': description}, None)
    
    flash(f'🗑️ Deliverable deleted: "{description}"', 'success')
    return redirect(url_for('edit_workplan', id=workplan.id))

@app.route('/add_kpi/<int:workplan_id>', methods=['POST'])
@login_required
def add_kpi(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('edit_workplan', id=workplan_id))
    
    description = request.form.get('description', '').strip()
    if description:
        existing = KPI.query.filter_by(
            workplan_id=workplan.id, description=description
        ).first()
        if not existing:
            kpi = KPI(workplan_id=workplan.id, description=description)
            db.session.add(kpi)
            db.session.commit()
            
            log_audit('CREATE', 'KPI', kpi.id, description, None, {'description': description})
            
            flash(f'✅ KPI added: "{description}"', 'success')
        else:
            flash(f'⚠️ Duplicate KPI exists', 'warning')
    else:
        flash('❌ Enter KPI description', 'danger')
    return redirect(url_for('edit_workplan', id=workplan_id))

@app.route('/delete_kpi/<int:kpi_id>')
@login_required
def delete_kpi(kpi_id):
    kpi = KPI.query.get_or_404(kpi_id)
    workplan = Workplan.query.get(kpi.workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    description = kpi.description
    db.session.delete(kpi)
    db.session.commit()
    
    log_audit('DELETE', 'KPI', kpi_id, description, {'description': description}, None)
    
    flash(f'🗑️ KPI deleted: "{description}"', 'success')
    return redirect(url_for('edit_workplan', id=workplan.id))

@app.route('/delete_workplan/<int:id>')
@login_required
def delete_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    title = workplan.project_title
    db.session.delete(workplan)
    db.session.commit()
    
    log_audit('DELETE', 'Workplan', id, title, {'title': title}, None)
    
    flash(f'🗑️ Workplan "{title}" deleted successfully!', 'success')
    return redirect(url_for('user_projects', user_id=workplan.created_by))

@app.route('/admin/pending_workplans')
@login_required
def pending_workplans():
    if not current_user.is_admin():
        abort(403)
    pending = Workplan.query.filter_by(status='Pending').order_by(Workplan.created_at.desc()).all()
    
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    return render_template('pending_workplans.html', pending=pending, status_counts=status_counts)

@app.route('/audit-log')
@login_required
def audit_log():
    if not current_user.is_superadmin():
        flash('Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    entity_filter = request.args.get('entity', '')
    
    query = AuditLog.query
    
    if action_filter:
        query = query.filter_by(action=action_filter)
    if entity_filter:
        query = query.filter_by(entity_type=entity_filter)
    
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    # Get unique actions and entity types for filters
    actions = db.session.query(AuditLog.action).distinct().all()
    entities = db.session.query(AuditLog.entity_type).distinct().all()
    
    status_counts = {
        'pending': Workplan.query.filter_by(status='Pending').count(),
        'approved': Workplan.query.filter_by(status='Approved').count(),
        'rejected': Workplan.query.filter_by(status='Rejected').count(),
        'ongoing': Workplan.query.filter_by(status='Ongoing').count(),
        'completed': Workplan.query.filter_by(status='Completed').count(),
        'started': Workplan.query.filter_by(status='Started').count(),
        'pause': Workplan.query.filter_by(status='Pause').count()
    }
    
    return render_template('audit_log.html', 
                         logs=logs, 
                         status_counts=status_counts,
                         actions=[a[0] for a in actions],
                         entities=[e[0] for e in entities],
                         current_action=action_filter,
                         current_entity=entity_filter)

@app.route('/workplan/<int:workplan_id>/pdf')
@login_required
def download_workplan_pdf(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('user_projects', user_id=current_user.id))
    
    pdf_io = BytesIO()
    doc = SimpleDocTemplate(pdf_io, pagesize=A4, topMargin=1*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    
    # ... PDF generation code (keep your existing PDF code) ...
    
    filename = f"Workplan_{workplan.project_title.replace(' ', '_')}_{workplan_id}.pdf"
    return send_file(pdf_io, mimetype='application/pdf', as_attachment=True, download_name=filename)

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            
            # Create default superadmin if none exists
            if User.query.count() == 0:
                admin = User(
                    username='admin',
                    mda_name='System Administration',
                    email='admin@example.com',
                    phone='0000000000',
                    role='Superadmin',
                    edit_attempts=0
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("✅ Default superadmin created (email: admin@example.com, password: admin123)")
        except Exception as e:
            print(f"Database setup: {e}")
    app.run(debug=True)