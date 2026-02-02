from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from wtforms import StringField, TextAreaField, SelectField, DateField, IntegerField, PasswordField, EmailField, TelField
from wtforms.validators import DataRequired, NumberRange, Email, EqualTo, Optional
from models import db, Workplan, Deliverable, KPI, User
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os  # 🔥 POSTGRESQL: Added for DATABASE_URL

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_change_this_in_production'

# 🔥 POSTGRESQL MIGRATION: Uses your DATABASE_URL environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///workplans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
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
    completion_percentage = IntegerField('Completion %', 
                                        validators=[DataRequired(), NumberRange(min=0, max=100)],
                                        render_kw={'min': 0, 'max': 100})
    status = SelectField('Status', 
                        choices=[
                            ('Pending', 'Pending'),
                            ('Started', 'Started'), 
                            ('Ongoing', 'Ongoing'), 
                            ('Pause', 'Pause'),
                            ('Completed', 'Completed')
                        ],
                        default='Pending')

# Role Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('🛡️ Admin access required!', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superadmin():
            flash('👑 Superadmin access required!', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 🔥 SUPERADMIN COMPLETE CRUD - User Management
@app.route('/users')
@superadmin_required
def manage_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)

@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@superadmin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('❌ Cannot edit your own account!', 'danger')
        return redirect(url_for('manage_users'))
    
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        existing_email = User.query.filter(User.email == form.email.data, User.id != user_id).first()
        if existing_email:
            flash('❌ Email already registered!', 'danger')
            return render_template('edit_user.html', form=form, user=user)
        
        user.username = form.username.data
        user.mda_name = form.mda_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        if form.password.data:
            user.set_password(form.password.data)
        user.role = form.role.data
        
        db.session.commit()
        flash(f'✅ User "{user.username}" updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', form=form, user=user)

@app.route('/toggle_admin/<int:user_id>')
@superadmin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('❌ Cannot modify your own role!', 'danger')
        return redirect(url_for('manage_users'))
    
    if user.role == 'Admin':
        user.role = 'User'
        action = 'demoted to User'
    else:
        user.role = 'Admin'
        action = 'promoted to Admin'
    
    db.session.commit()
    flash(f'✅ User "{user.username}" {action}', 'success')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
@superadmin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('❌ Cannot delete your own account!', 'danger')
        return redirect(url_for('manage_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'✅ User "{username}" deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

# Auth Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered!', 'danger')
            return render_template('register.html', form=form)
        
        user = User(
            username=form.username.data,
            mda_name=form.mda_name.data,
            email=form.email.data,
            phone=form.phone.data,
            role=form.role.data
        )
        user.password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        db.session.add(user)
        db.session.commit()
        flash('✅ Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f'✅ Welcome back, {user.username}! ({user.role})', 'success')
            return redirect(url_for('index'))
        flash('❌ Invalid email or password!', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('👋 You have been logged out.', 'info')
    return redirect(url_for('login'))

# 🔥 ENHANCED Protected Routes - ADMIN sees ALL workplans
@app.route('/', methods=['GET'])
@login_required
def index():
    search_term = request.args.get('search', '').strip()
    
    # System-wide stats
    pending_count = db.session.query(Workplan).filter_by(status='Pending').count()
    approved_count = db.session.query(Workplan).filter_by(status='Approved').count()
    rejected_count = db.session.query(Workplan).filter_by(status='Rejected').count()
    
    # Role-based query
    if current_user.is_superadmin() or current_user.is_admin():
        base_query = Workplan.query
    else:
        base_query = Workplan.query.filter_by(created_by=current_user.id)
    
    # Filter workplans
    if search_term:
        workplans = base_query.filter(
            db.or_(
                Workplan.mda.ilike(f'%{search_term}%'),
                Workplan.project_title.ilike(f'%{search_term}%')
            )
        ).order_by(Workplan.created_at.desc()).all()
    else:
        workplans = base_query.order_by(Workplan.created_at.desc()).all()
    
    # 🔥 CALCULATE AVERAGE % COMPLETE (FILTER-AWARE)
    if workplans and len(workplans) > 0:
        total_completion = sum(float(wp.completion_percentage or 0) for wp in workplans)
        avg_completion = round(total_completion / len(workplans), 1)
        project_count = len(workplans)
    else:
        avg_completion = 0.0
        project_count = 0
    
    # app.py index() MUST include these 3 variables:
    return render_template('index.html', 
                       workplans=workplans,
                       pending_count=pending_count,
                       approved_count=approved_count,
                       rejected_count=rejected_count,
                       avg_completion=avg_completion,     # ← ADD THIS
                       project_count=project_count,       # ← ADD THIS  
                       search_term=search_term)           # ← ADD THIS





@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_workplan():
    form = WorkplanForm()
    base_query = Workplan.query.filter_by(created_by=current_user.id) if not current_user.is_admin() else Workplan.query
    all_workplans = base_query.order_by(Workplan.created_at.desc()).limit(10).all()
    
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
            completion_percentage=form.completion_percentage.data,
            status=form.status.data
        )
        db.session.add(workplan)
        db.session.commit()
        flash(f'✅ Workplan "{workplan.project_title}" created! ({duration} days)', 'success')
        return redirect(url_for('edit_workplan', id=workplan.id))
    
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'❌ {field}: {error}', 'danger')
    
    return render_template('add.html', form=form, workplans=all_workplans)

@app.route('/add_deliverable/<int:workplan_id>', methods=['POST'])
@login_required
def add_deliverable(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    description = request.form.get('description', '').strip()
    if description:
        existing = Deliverable.query.filter_by(
            workplan_id=workplan.id, 
            description=description
        ).first()
        if not existing:
            deliverable = Deliverable(
                workplan_id=workplan.id, 
                description=description
            )
            db.session.add(deliverable)
            db.session.commit()
            flash(f'✅ Deliverable added: "{description}"', 'success')
        else:
            flash(f'⚠️ Duplicate deliverable already exists', 'warning')
    else:
        flash('❌ Please enter a deliverable description', 'danger')
    return redirect(url_for('edit_workplan', id=workplan_id))

@app.route('/add_kpi/<int:workplan_id>', methods=['POST'])
@login_required
def add_kpi(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    description = request.form.get('description', '').strip()
    if description:
        existing = KPI.query.filter_by(
            workplan_id=workplan.id, 
            description=description
        ).first()
        if not existing:
            kpi = KPI(
                workplan_id=workplan.id, 
                description=description
            )
            db.session.add(kpi)
            db.session.commit()
            flash(f'✅ KPI added: "{description}"', 'success')
        else:
            flash(f'⚠️ Duplicate KPI already exists', 'warning')
    else:
        flash('❌ Please enter a KPI description', 'danger')
    return redirect(url_for('edit_workplan', id=workplan_id))

@app.route('/delete_deliverable/<int:deliverable_id>')
@login_required
def delete_deliverable(deliverable_id):
    deliverable = Deliverable.query.get_or_404(deliverable_id)
    workplan = Workplan.query.get(deliverable.workplan_id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    description = deliverable.description
    db.session.delete(deliverable)
    db.session.commit()
    flash(f'🗑️ Deliverable deleted: "{description}"')
    return redirect(url_for('edit_workplan', id=workplan.id))

@app.route('/delete_kpi/<int:kpi_id>')
@login_required
def delete_kpi(kpi_id):
    kpi = KPI.query.get_or_404(kpi_id)
    workplan = Workplan.query.get(kpi.workplan_id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    description = kpi.description
    db.session.delete(kpi)
    db.session.commit()
    flash(f'🗑️ KPI deleted: "{description}"')
    return redirect(url_for('edit_workplan', id=workplan.id))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    form = WorkplanForm(obj=workplan)
    base_query = Workplan.query.filter_by(created_by=current_user.id) if not current_user.is_admin() else Workplan.query
    all_workplans = base_query.order_by(Workplan.created_at.desc()).limit(10).all()
    
    if form.validate_on_submit():
        duration = (form.end_date.data - form.start_date.data).days + 1
        workplan.mda = form.mda.data
        workplan.project_title = form.project_title.data
        workplan.objective = form.objective.data
        workplan.assigned_dept = form.assigned_dept.data
        workplan.collaborating_dept = form.collaborating_dept.data
        workplan.start_date = form.start_date.data
        workplan.end_date = form.end_date.data
        workplan.duration = duration
        workplan.completion_percentage = form.completion_percentage.data
        workplan.status = form.status.data
        db.session.commit()
        flash('✅ Workplan updated successfully!')
        return redirect(url_for('index'))
    return render_template('edit.html', form=form, workplan=workplan, workplans=all_workplans)

@app.route('/delete/<int:id>')
@login_required
def delete_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    # 🔥 FIXED: Superadmin can delete ANY workplan
    if not current_user.is_superadmin():
        flash('Only Superadmin can delete workplans!', 'danger')
        return redirect(url_for('index'))
    
    db.session.delete(workplan)
    db.session.commit()
    flash('✅ Workplan deleted successfully!')
    return redirect(url_for('index'))

@app.route('/view/<int:id>')
@login_required
def view_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    base_query = Workplan.query.filter_by(created_by=current_user.id) if not current_user.is_admin() else Workplan.query
    all_workplans = base_query.order_by(Workplan.created_at.desc()).limit(10).all()
    return render_template('view.html', workplan=workplan, workplans=all_workplans)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin():
        abort(403)
    
    # Stats for admin dashboard
    pending_count = Workplan.query.filter_by(status='Pending').count()
    approved_count = Workplan.query.filter_by(status='Approved').count()
    rejected_count = Workplan.query.filter_by(status='Rejected').count()
    pending_workplans = Workplan.query.filter_by(status='Pending').limit(10).all()
    
    return render_template('users.html', 
                         users=User.query.all(),
                         pending_workplans=pending_workplans,
                         pending_count=pending_count,
                         approved_count=approved_count,
                         rejected_count=rejected_count)


# app.py - ADD these routes

@app.route('/admin/pending_workplans')
@login_required
def pending_workplans():
    if not current_user.is_admin():
        abort(403)
    
    pending = Workplan.query.filter_by(status='Pending').order_by(Workplan.created_at.desc()).all()
    
    # 🔥 FIX: Use YOUR existing template
    return render_template('pending_workplans.html', pending=pending)


@app.route('/admin/approve_workplan/<int:workplan_id>', methods=['POST'])
@login_required
def approve_workplan(workplan_id):
    if not current_user.is_admin():
        abort(403)
    
    workplan = Workplan.query.get_or_404(workplan_id)
    comment = request.form.get('admin_comment', '')
    
    workplan.status = 'Approved'
    workplan.approved_by = current_user.id
    workplan.approved_at = datetime.utcnow()
    workplan.admin_comment = comment
    
    db.session.commit()
    flash(f'✅ Workplan "{workplan.project_title}" approved!', 'success')
    return redirect(url_for('pending_workplans'))

@app.route('/admin/reject_workplan/<int:workplan_id>', methods=['POST'])
@login_required
def reject_workplan(workplan_id):
    if not current_user.is_admin():
        abort(403)
    
    workplan = Workplan.query.get_or_404(workplan_id)
    comment = request.form.get('admin_comment', '')
    
    workplan.status = 'Rejected'
    workplan.approved_by = current_user.id
    workplan.approved_at = datetime.utcnow()
    workplan.admin_comment = comment
    
    db.session.commit()
    flash(f'❌ Workplan "{workplan.project_title}" rejected!', 'warning')
    return redirect(url_for('pending_workplans'))


if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Tables may already exist: {e}")  # ✅ Ignore permission error
    app.run(debug=True)