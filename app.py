from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from wtforms import StringField, TextAreaField, SelectField, DateField, IntegerField, PasswordField, EmailField, TelField
from wtforms.validators import DataRequired, NumberRange, Email, EqualTo, Optional
from models import db, Workplan, Deliverable, KPI, User
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import A4, letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import cm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_change_this_in_production'
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
    return db.session.get(User, int(user_id))

# Forms (KEEP ALL YOUR EXISTING FORMS)
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
    completion_percentage = IntegerField('Completion %', 
                                       validators=[DataRequired(), NumberRange(min=0, max=100)])
    status = SelectField('Status', 
                       choices=[('Pending', 'Pending'), ('Started', 'Started'), 
                               ('Ongoing', 'Ongoing'), ('Pause', 'Pause'), ('Completed', 'Completed')],
                       default='Pending')
    # No submit field needed - your HTML uses <button type="submit">


# 🔥 Role Decorators
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

# 🔥 FIXED SUPERADMIN USER CRUD - NO DUPLICATES!
@app.route('/superadmin/users')
@login_required
def superadmin_users_list():
    if not current_user.is_superadmin():
        flash('👑 Superadmin access required!', 'danger')
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    return render_template('users.html', users=users)


@app.route('/superadmin/users/add', methods=['GET', 'POST'])
@login_required
def superadmin_add_user():
    if not current_user.is_superadmin():
        flash('👑 Superadmin access required!', 'danger')
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('❌ Email already exists!', 'danger')
            return render_template('add_user.html', form=form)
        
        user = User(
            username=form.username.data,
            mda_name=form.mda_name.data,
            email=form.email.data,
            phone=form.phone.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(f'✅ User "{user.username}" created!', 'success')
        return redirect(url_for('superadmin_users_list'))
    
    return render_template('add_user.html', form=form)

@app.route('/superadmin/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def superadmin_edit_user(id):
    if not current_user.is_superadmin():
        flash('👑 Superadmin access required!', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('❌ Cannot edit your own account!', 'danger')
        return redirect(url_for('superadmin_users_list'))
    
    form = EditUserForm(obj=user)
    if form.validate_on_submit():
        if User.query.filter(User.email == form.email.data, User.id != id).first():
            flash('❌ Email already exists!', 'danger')
            return render_template('edit_user.html', form=form, user=user)
        
        user.username = form.username.data
        user.mda_name = form.mda_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.role = form.role.data
        if form.password.data:
            user.set_password(form.password.data)
        
        db.session.commit()
        flash(f'✅ User "{user.username}" updated!', 'success')
        return redirect(url_for('superadmin_users_list'))
    
    return render_template('edit_user.html', form=form, user=user)

@app.route('/superadmin/users/delete/<int:id>')
@login_required
def superadmin_delete_user(id):
    if not current_user.is_superadmin():
        flash('👑 Superadmin access required!', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('❌ Cannot delete your own account!', 'danger')
        return redirect(url_for('superadmin_users_list'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'✅ User "{username}" deleted!', 'success')
    return redirect(url_for('superadmin_users_list'))

# 🔥 FIXED Admin Dashboard - SINGLE ROUTE
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin() and not current_user.is_superadmin():
        flash('Admin access required!', 'danger')
        return redirect(url_for('index'))
    
    pending_count = Workplan.query.filter_by(status='Pending').count()
    approved_count = Workplan.query.filter_by(status='Approved').count()
    rejected_count = Workplan.query.filter_by(status='Rejected').count()
    pending_workplans = Workplan.query.filter_by(status='Pending').limit(10).all()
    
    return render_template('users.html',
                         pending_count=pending_count,
                         approved_count=approved_count,
                         rejected_count=rejected_count,
                         pending_workplans=pending_workplans)

@app.route('/users')
@login_required
def manage_users():
    """Legacy Superadmin Users - redirects to new route"""
    return redirect(url_for('superadmin_users_list'))


# 🔥 Auth Routes (KEEP ALL YOUR EXISTING)
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

# 🔥 ALL YOUR WORKPLAN ROUTES (KEEP EXACTLY AS IS)
@app.route('/', methods=['GET'])
@login_required
def index():
    search_term = request.args.get('search', '').strip()
    
    pending_count = db.session.query(Workplan).filter_by(status='Pending').count()
    approved_count = db.session.query(Workplan).filter_by(status='Approved').count()
    rejected_count = db.session.query(Workplan).filter_by(status='Rejected').count()
    
    if current_user.is_superadmin() or current_user.is_admin():
        base_query = Workplan.query
    else:
        base_query = Workplan.query.filter_by(created_by=current_user.id)
    
    if search_term:
        workplans = base_query.filter(
            db.or_(
                Workplan.mda.ilike(f'%{search_term}%'),
                Workplan.project_title.ilike(f'%{search_term}%')
            )
        ).order_by(Workplan.created_at.desc()).all()
    else:
        workplans = base_query.order_by(Workplan.created_at.desc()).all()
    
    if workplans and len(workplans) > 0:
        total_completion = sum(float(wp.completion_percentage or 0) for wp in workplans)
        avg_completion = round(total_completion / len(workplans), 1)
        project_count = len(workplans)
    else:
        avg_completion = 0.0
        project_count = 0
    
    return render_template('index.html', 
                         workplans=workplans,
                         pending_count=pending_count,
                         approved_count=approved_count,
                         rejected_count=rejected_count,
                         avg_completion=avg_completion,
                         project_count=project_count,
                         search_term=search_term)

# 🔥 Keep ALL your other workplan routes exactly as they are...
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_workplan():
    form = WorkplanForm()
    
    # Show recent workplans in sidebar
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
    
    # Show form errors
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'❌ {field}: {error}', 'danger')
    
    return render_template('add.html', form=form, workplans=all_workplans)


@app.route('/view/<int:id>')
@login_required
def view_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    # Permission check
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('index'))
    
    # Recent workplans sidebar
    base_query = Workplan.query.filter_by(created_by=current_user.id) if not current_user.is_admin() else Workplan.query
    all_workplans = base_query.order_by(Workplan.created_at.desc()).limit(10).all()
    
    return render_template('view.html', workplan=workplan, workplans=all_workplans)

@app.route('/approve/<int:workplan_id>', methods=['POST'])
@login_required
def approve_workplan(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    # Permission check
    if not current_user.is_admin() and not current_user.is_superadmin():
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('view_workplan', id=workplan_id))
    
    # Get optional comment
    admin_comment = request.form.get('admin_comment', '').strip()
    
    # Update workplan
    workplan.status = 'Approved'
    workplan.admin_comment = admin_comment
    workplan.approved_at = datetime.utcnow()
    workplan.approver_id = current_user.id  # Assuming you have approver_id field
    
    db.session.commit()
    flash(f'✅ "{workplan.project_title}" approved!', 'success')
    return redirect(url_for('index'))

@app.route('/reject/<int:workplan_id>', methods=['POST'])
@login_required
def reject_workplan(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    # Permission check
    if not current_user.is_admin() and not current_user.is_superadmin():
        flash('❌ Admin access required!', 'danger')
        return redirect(url_for('view_workplan', id=workplan_id))
    
    # Get required comment
    admin_comment = request.form.get('admin_comment', '').strip()
    if not admin_comment:
        flash('❌ Rejection reason required!', 'danger')
        return redirect(url_for('view_workplan', id=workplan_id))
    
    # Update workplan
    workplan.status = 'Rejected'
    workplan.admin_comment = admin_comment
    workplan.approved_at = None
    workplan.approver_id = current_user.id
    
    db.session.commit()
    flash(f'❌ "{workplan.project_title}" rejected!', 'danger')
    return redirect(url_for('index'))



# 🔥 DELIVERABLE & KPI ROUTES
@app.route('/add_deliverable/<int:workplan_id>', methods=['POST'])
@login_required
def add_deliverable(workplan_id):
    print(f"🔍 DEBUG: POST /add_deliverable/{workplan_id}")
    
    workplan = Workplan.query.get_or_404(workplan_id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('edit_workplan', id=workplan_id))
    
    description = request.form.get('description', '').strip()
    print(f"🔍 DEBUG: Description: '{description}'")
    
    if not description:
        flash('❌ Description required!', 'danger')
        return redirect(url_for('edit_workplan', id=workplan_id))
    
    # Create deliverable
    deliverable = Deliverable(workplan_id=workplan.id, description=description)
    db.session.add(deliverable)
    db.session.commit()
    
    print("✅ Deliverable SAVED!")
    flash(f'✅ Added: "{description}"', 'success')
    return redirect(url_for('edit_workplan', id=workplan_id))


@app.route('/delete_deliverable/<int:deliverable_id>')
@login_required
def delete_deliverable(deliverable_id):
    deliverable = Deliverable.query.get_or_404(deliverable_id)
    workplan = Workplan.query.get(deliverable.workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('index'))
    
    description = deliverable.description
    db.session.delete(deliverable)
    db.session.commit()
    flash(f'🗑️ Deliverable deleted: "{description}"', 'success')
    return redirect(url_for('edit_workplan', id=workplan.id))

@app.route('/add_kpi/<int:workplan_id>', methods=['POST'])
@login_required
def add_kpi(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('index'))
    
    description = request.form.get('description', '').strip()
    if description:
        # Check for duplicate
        existing = KPI.query.filter_by(
            workplan_id=workplan.id, description=description
        ).first()
        if not existing:
            kpi = KPI(workplan_id=workplan.id, description=description)
            db.session.add(kpi)
            db.session.commit()
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
        return redirect(url_for('index'))
    
    description = kpi.description
    db.session.delete(kpi)
    db.session.commit()
    flash(f'🗑️ KPI deleted: "{description}"', 'success')
    return redirect(url_for('edit_workplan', id=workplan.id))

@app.route('/delete_workplan/<int:id>')
@login_required
def delete_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    # Permission check - only owner or admin can delete
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied! You can only delete your own workplans.', 'danger')
        return redirect(url_for('index'))
    
    # Delete associated deliverables and KPIs first
    for deliverable in workplan.deliverables:
        db.session.delete(deliverable)
    for kpi in workplan.kpis:
        db.session.delete(kpi)
    
    title = workplan.project_title
    db.session.delete(workplan)
    db.session.commit()
    
    flash(f'🗑️ Workplan "{title}" deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_workplan(id):
    workplan = Workplan.query.get_or_404(id)
    
    # Permission check
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('index'))
    
    # Use EditWorkplanForm
    form = EditWorkplanForm(obj=workplan)
    
    if form.validate_on_submit():
        # Update workplan
        was_approved = (workplan.status == 'Approved')
        
        form.populate_obj(workplan)
        
        # Revert to Pending on edit
        workplan.status = 'Pending'
        workplan.approved_at = None
        workplan.approver_id = None
        workplan.admin_comment = None
        
        # Recalculate duration
        workplan.duration = (workplan.end_date - workplan.start_date).days + 1
        
        db.session.commit()
        
        if was_approved:
            flash('✅ Updated! Status → PENDING (needs re-approval)', 'warning')
        else:
            flash('✅ Workplan updated successfully!', 'success')
        
        return redirect(url_for('view_workplan', id=workplan.id))
    
    return render_template('edit.html', workplan=workplan, form=form)



# ✅ ADD DELIVERABLE ROUTE

# ✅ ADD KPI ROUTE  





@app.route('/admin/pending_workplans')
@login_required
def pending_workplans():
    if not current_user.is_admin():
        abort(403)
    pending = Workplan.query.filter_by(status='Pending').order_by(Workplan.created_at.desc()).all()
    return render_template('pending_workplans.html', pending=pending)
# 🔥 PDF DOWNLOAD ROUTE - ADD THIS
@app.route('/workplan/<int:workplan_id>/pdf')
@login_required
def download_workplan_pdf(workplan_id):
    workplan = Workplan.query.get_or_404(workplan_id)
    
    if workplan.created_by != current_user.id and not current_user.is_admin():
        flash('❌ Access denied!', 'danger')
        return redirect(url_for('index'))
    
    pdf_io = BytesIO()
    doc = SimpleDocTemplate(pdf_io, pagesize=A4, topMargin=1*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    
    # Custom styles matching your view.html design
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.HexColor('#007bff'),
        alignment=1  # Center
    )
    
    section_style = ParagraphStyle(
        'Section',
        fontSize=14,
        spaceAfter=12,
        textColor=colors.HexColor('#007bff'),
        fontName='Helvetica-Bold',
        leftIndent=0
    )
    
    badge_style = ParagraphStyle(
        'Badge',
        fontSize=12,
        spaceAfter=20,
        alignment=1  # Center
    )
    
    list_style = ParagraphStyle(
        'List',
        fontSize=11,
        leftIndent=20,
        spaceAfter=4,
        bulletIndent=10
    )
    
    info_style = ParagraphStyle(
        'Info',
        fontSize=10,
        spaceAfter=8,
        leftIndent=20
    )
    
    story = []
    
    # 1. HEADER - Exact match to your h1 + badges
    story.append(Paragraph(workplan.project_title, title_style))
    
    # MDA + Status Badges (centered, exact spacing)
    badge_row = Paragraph(
        f'<font color="#007bff"><b>MDA</b></font>&nbsp;&nbsp;&nbsp;&nbsp;'
        f'<font color="#007bff">{workplan.mda}</font><br/><br/>'
        f'<font color="#28a745"><b>Status</b></font>&nbsp;&nbsp;&nbsp;&nbsp;'
        f'<font color="#28a745">{"✅ APPROVED" if workplan.status == "Approved" else workplan.status}</font>',
        badge_style
    )
    story.append(badge_row)
    story.append(Spacer(1, 20))
    
    # 2. STATUS SUMMARY (Approved/Rejected/Pending)
    if workplan.status == 'Approved':
        status_para = Paragraph(
            f'<font color="#28a745">✅ APPROVED by Admin on {workplan.approved_at.strftime("%Y-%m-%d") if workplan.approved_at else "Today"}</font>',
            section_style
        )
    elif workplan.status == 'Rejected':
        status_para = Paragraph('<font color="#dc3545">❌ REJECTED - Awaiting admin review</font>', section_style)
    else:
        status_para = Paragraph('<font color="#ffc107">⏳ PENDING APPROVAL - Awaiting admin review</font>', section_style)
    story.append(status_para)
    story.append(Spacer(1, 20))
    
    # 3. OBJECTIVE
    if workplan.objective.strip():
        story.append(Paragraph("Objective", section_style))
        story.append(Paragraph(workplan.objective.strip(), list_style))
        story.append(Spacer(1, 16))
    
    # 4. LEFT COLUMN - Deliverables + KPIs (2-col layout simulation)
    # Deliverables
    deliverables_count = len(workplan.deliverables)
    story.append(Paragraph(f"Deliverables  <font color='#28a745' size=12>({deliverables_count})</font>", section_style))
    for deliverable in workplan.deliverables:
        story.append(Paragraph(f"• {deliverable.description}", list_style))
    story.append(Spacer(1, 16))
    
    # KPIs  
    kpis_count = len(workplan.kpis)
    story.append(Paragraph(f"KPIs  <font color='#0d6efd' size=12>({kpis_count})</font>", section_style))
    for kpi in workplan.kpis:
        story.append(Paragraph(f"• {kpi.description}", list_style))
    story.append(Spacer(1, 20))
    
    # 5. RIGHT COLUMN - Timeline + Progress + Departments
    # Timeline
    story.append(Paragraph("Timeline", section_style))
    timeline_table_data = [
        ['Start:', workplan.start_date.strftime('%Y-%m-%d')],
        ['End:', workplan.end_date.strftime('%Y-%m-%d')],
        [f'{workplan.duration} days', '']
    ]
    from reportlab.platypus import Table
    timeline_table = Table(timeline_table_data, colWidths=[3*cm, 4*cm])
    timeline_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 16))
    
    # Progress
    story.append(Paragraph("Progress", section_style))
    story.append(Paragraph(f"{workplan.completion_percentage}%<br/>{workplan.completion_percentage}% Complete", info_style))
    story.append(Spacer(1, 16))
    
    # Departments
    story.append(Paragraph("Departments", section_style))
    depts_para = Paragraph(
        f"<font size=10>Assigned: {workplan.assigned_dept}<br/>"
        f"Collaborating: {workplan.collaborating_dept or 'None'}</font>",
        info_style
    )
    story.append(depts_para)
    
    # Build PDF
    doc.build(story)
    pdf_io.seek(0)
    
    filename = f"Workplan_{workplan.project_title.replace(' ', '_')}_{workplan_id}.pdf"
    return send_file(pdf_io, mimetype='application/pdf', as_attachment=True, download_name=filename)



# ... ALL OTHER ROUTES STAY THE SAME ...

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Tables may already exist: {e}")
    app.run(debug=True)
