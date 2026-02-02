from flask_sqlalchemy import SQLAlchemy
from datetime import date, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    mda_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), default='User')
    
    # 🔥 FIXED: Use backref with foreign_keys
    workplans = db.relationship('Workplan', 
                               foreign_keys='Workplan.created_by',
                               backref='user',
                               lazy=True, 
                               cascade='all, delete-orphan')
    
    # 🔥 Approved workplans - different backref name
    approved_workplans = db.relationship('Workplan', 
                                        foreign_keys='Workplan.approved_by',
                                        backref='approver',
                                        lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role in ['Admin', 'Superadmin']
    
    def is_superadmin(self):
        return self.role == 'Superadmin'

class Deliverable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workplan_id = db.Column(db.Integer, db.ForeignKey('workplan.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    workplan = db.relationship('Workplan', 
                              backref=db.backref('deliverables', 
                                               lazy=True, 
                                               cascade='all, delete-orphan'))

class KPI(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workplan_id = db.Column(db.Integer, db.ForeignKey('workplan.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    workplan = db.relationship('Workplan', 
                              backref=db.backref('kpis', 
                                               lazy=True, 
                                               cascade='all, delete-orphan'))

class Workplan(db.Model):
    __tablename__ = 'workplan'
    
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mda = db.Column(db.String(100), nullable=False, default='Edo State Govt')
    project_title = db.Column(db.String(200), nullable=False)
    objective = db.Column(db.Text, nullable=False)
    assigned_dept = db.Column(db.String(100), nullable=False)
    collaborating_dept = db.Column(db.String(100))
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    duration = db.Column(db.Integer, nullable=False, default=0)
    completion_percentage = db.Column(db.Integer, default=0)
    
    # 🔥 APPROVAL FIELDS
    status = db.Column(db.String(20), default='Pending')
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    admin_comment = db.Column(db.Text, nullable=True)
    
    # 🔥 Backrefs AUTOMATICALLY created above
    # workplan.user     ← from User.workplans backref
    # workplan.approver ← from User.approved_workplans backref
    
    @property
    def duration_days(self):
        if self.start_date and self.end_date:
            return (self.end_date - self.start_date).days + 1
        return self.duration

    @property
    def completion_progress(self):
        if self.status == 'Completed':
            return 100
        return self.completion_percentage
    
    @property
    def status_badge_class(self):
        return {
            'Pending': 'warning',
            'Approved': 'success', 
            'Rejected': 'danger',
            'Ongoing': 'info',
            'Completed': 'success'
        }.get(self.status, 'secondary')
