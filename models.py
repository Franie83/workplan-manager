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
    # 🔥 REMOVED: edit_attempts - moved to Workplan model (per project)
    
    # Relationships
    workplans = db.relationship('Workplan', 
                               foreign_keys='Workplan.created_by',
                               backref='user',
                               lazy=True, 
                               cascade='all, delete-orphan')
    
    approved_workplans = db.relationship('Workplan', 
                                        foreign_keys='Workplan.approved_by',
                                        backref='approver',
                                        lazy=True)
    
    uploaded_evidence = db.relationship('Evidence', 
                                       foreign_keys='Evidence.uploaded_by',
                                       backref='uploader',
                                       lazy=True)
    
    # Audit trail relationship
    audit_logs = db.relationship('AuditLog', 
                                foreign_keys='AuditLog.user_id',
                                backref='user',
                                lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role in ['Admin', 'Superadmin']
    
    def is_superadmin(self):
        return self.role == 'Superadmin'

# Audit Log Model
class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)  # Store username at time of action
    action = db.Column(db.String(50), nullable=False)  # CREATE, UPDATE, DELETE, APPROVE, REJECT, LOGIN, LOGOUT
    entity_type = db.Column(db.String(50), nullable=False)  # Workplan, Deliverable, KPI, Evidence, User
    entity_id = db.Column(db.Integer, nullable=True)
    entity_name = db.Column(db.String(200), nullable=True)  # Store name/title for easy reference
    old_values = db.Column(db.Text, nullable=True)  # JSON string of old values
    new_values = db.Column(db.Text, nullable=True)  # JSON string of new values
    ip_address = db.Column(db.String(50), nullable=True)
    
    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username} at {self.timestamp}>'

class Deliverable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workplan_id = db.Column(db.Integer, db.ForeignKey('workplan.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    completed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # Require evidence before marking complete
    requires_evidence = db.Column(db.Boolean, default=False, nullable=False)
    
    workplan = db.relationship('Workplan', 
                              backref=db.backref('deliverables', 
                                               lazy=True, 
                                               cascade='all, delete-orphan'))
    
    evidence_files = db.relationship('Evidence', 
                                    backref='deliverable', 
                                    lazy=True, 
                                    cascade='all, delete-orphan',
                                    foreign_keys='Evidence.deliverable_id')

class KPI(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workplan_id = db.Column(db.Integer, db.ForeignKey('workplan.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    workplan = db.relationship('Workplan', 
                              backref=db.backref('kpis', 
                                               lazy=True, 
                                               cascade='all, delete-orphan'))

class Evidence(db.Model):
    __tablename__ = 'evidence'
    
    id = db.Column(db.Integer, primary_key=True)
    deliverable_id = db.Column(db.Integer, db.ForeignKey('deliverable.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)
    description = db.Column(db.String(500), nullable=True)
    
    @property
    def file_size_formatted(self):
        if self.file_size < 1024:
            return f"{self.file_size} B"
        elif self.file_size < 1024 * 1024:
            return f"{self.file_size / 1024:.1f} KB"
        else:
            return f"{self.file_size / (1024 * 1024):.1f} MB"
    
    @property
    def icon_class(self):
        if self.file_type == 'image':
            return 'bi-file-image text-success'
        elif self.file_type == 'video':
            return 'bi-file-play text-danger'
        elif self.file_type == 'pdf':
            return 'bi-file-pdf text-danger'
        elif self.file_type in ['doc', 'docx']:
            return 'bi-file-word text-primary'
        elif self.file_type in ['xls', 'xlsx']:
            return 'bi-file-excel text-success'
        else:
            return 'bi-file-text text-secondary'

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
    
    # 🔥 NEW: Track edits per project
    edit_attempts = db.Column(db.Integer, default=0)  # Tracks number of edits for this specific workplan
    
    # Approval fields
    status = db.Column(db.String(20), default='Pending')
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    admin_comment = db.Column(db.Text, nullable=True)
    
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
    def completion_from_deliverables(self):
        if not self.deliverables:
            return 0
        completed_count = sum(1 for d in self.deliverables if d.completed)
        return int((completed_count / len(self.deliverables)) * 100)
    
    @property
    def all_evidence(self):
        evidence = []
        for deliverable in self.deliverables:
            evidence.extend(deliverable.evidence_files)
        return evidence
    
    @property
    def evidence_count(self):
        return sum(len(deliverable.evidence_files) for deliverable in self.deliverables)
    
    @property
    def status_badge_class(self):
        return {
            'Pending': 'warning',
            'Approved': 'success', 
            'Rejected': 'danger',
            'Ongoing': 'info',
            'Started': 'primary',
            'Pause': 'secondary',
            'Completed': 'success'
        }.get(self.status, 'secondary')
    
    # 🔥 NEW: Check if this workplan can be edited by a user
    def can_edit(self, user):
        """Check if a user can edit this workplan"""
        if user.is_admin():
            return True  # Admins can always edit
        if self.created_by != user.id:
            return False  # Not the owner
        return self.edit_attempts < 5  # Max 5 edits per project