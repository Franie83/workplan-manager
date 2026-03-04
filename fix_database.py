# fix_database.py
import sqlite3
import os

print("🔧 Fixing database schema...")
print("=" * 50)

# Path to your database
db_path = 'instance/workplans.db'

if not os.path.exists(db_path):
    print(f"❌ Database not found at {db_path}")
    # Try root directory as fallback
    db_path = 'workplans.db'
    if os.path.exists(db_path):
        print(f"✅ Found database at: {db_path}")
    else:
        print("❌ Database not found in either location.")
        exit(1)
else:
    print(f"✅ Found database at: {db_path}")

# Connect to database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# ============================================
# CHECK USER TABLE
# ============================================
print("\n📊 Checking USER table...")
cursor.execute("PRAGMA table_info(user)")
user_columns = cursor.fetchall()
user_column_names = [col[1] for col in user_columns]

print("Current columns in user table:")
for col in user_columns:
    print(f"  - {col[1]} ({col[2]})")

# Note: edit_attempts is being moved from user to workplan
if 'edit_attempts' in user_column_names:
    print("\n⚠️  'edit_attempts' found in user table - this should be moved to workplan table")
    print("   Keeping it for now to avoid data loss. It will be ignored by the application.")
    # Option to remove it (commented out for safety)
    # try:
    #     cursor.execute("ALTER TABLE user DROP COLUMN edit_attempts")
    #     conn.commit()
    #     print("✅ Removed edit_attempts from user table")
    # except Exception as e:
    #     print(f"❌ Error removing edit_attempts: {e}")

# ============================================
# CHECK WORKPLAN TABLE
# ============================================
print("\n📊 Checking WORKPLAN table...")
cursor.execute("PRAGMA table_info(workplan)")
workplan_columns = cursor.fetchall()
workplan_column_names = [col[1] for col in workplan_columns]

print("Current columns in workplan table:")
for col in workplan_columns:
    print(f"  - {col[1]} ({col[2]})")

# Check if edit_attempts column exists in workplan
if 'edit_attempts' not in workplan_column_names:
    print("\n⚠️  'edit_attempts' column missing in workplan table. Adding it now...")
    try:
        cursor.execute("ALTER TABLE workplan ADD COLUMN edit_attempts INTEGER DEFAULT 0")
        conn.commit()
        print("✅ Successfully added 'edit_attempts' column to workplan table!")
    except Exception as e:
        print(f"❌ Error adding edit_attempts to workplan: {e}")
else:
    print("✅ 'edit_attempts' column already exists in workplan table")

# ============================================
# CHECK DELIVERABLE TABLE
# ============================================
print("\n📊 Checking DELIVERABLE table...")
cursor.execute("PRAGMA table_info(deliverable)")
deliverable_columns = cursor.fetchall()
deliverable_column_names = [col[1] for col in deliverable_columns]

print("Current columns in deliverable table:")
for col in deliverable_columns:
    print(f"  - {col[1]} ({col[2]})")

# Check if requires_evidence column exists
if 'requires_evidence' not in deliverable_column_names:
    print("\n⚠️  'requires_evidence' column missing. Adding it now...")
    try:
        cursor.execute("ALTER TABLE deliverable ADD COLUMN requires_evidence BOOLEAN DEFAULT 0")
        conn.commit()
        print("✅ Successfully added 'requires_evidence' column to deliverable table!")
    except Exception as e:
        print(f"❌ Error adding requires_evidence: {e}")
else:
    print("✅ 'requires_evidence' column already exists")

# Check if completed_at column exists
if 'completed_at' not in deliverable_column_names:
    print("\n⚠️  'completed_at' column missing. Adding it now...")
    try:
        cursor.execute("ALTER TABLE deliverable ADD COLUMN completed_at DATETIME")
        conn.commit()
        print("✅ Successfully added 'completed_at' column to deliverable table!")
    except Exception as e:
        print(f"❌ Error adding completed_at: {e}")
else:
    print("✅ 'completed_at' column already exists")

# Check if completed_by column exists
if 'completed_by' not in deliverable_column_names:
    print("\n⚠️  'completed_by' column missing. Adding it now...")
    try:
        cursor.execute("ALTER TABLE deliverable ADD COLUMN completed_by INTEGER REFERENCES user(id)")
        conn.commit()
        print("✅ Successfully added 'completed_by' column to deliverable table!")
    except Exception as e:
        print(f"❌ Error adding completed_by: {e}")
else:
    print("✅ 'completed_by' column already exists")

# ============================================
# CHECK AUDIT LOG TABLE
# ============================================
print("\n📊 Checking AUDIT_LOG table...")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
if not cursor.fetchone():
    print("\n⚠️  'audit_log' table missing.")
    print("   This table will be created automatically when you restart Flask.")
    print("   The app will run db.create_all() on startup.")
else:
    print("✅ 'audit_log' table exists")
    
    # Check audit_log table structure
    cursor.execute("PRAGMA table_info(audit_log)")
    audit_columns = cursor.fetchall()
    print("Current columns in audit_log table:")
    for col in audit_columns:
        print(f"  - {col[1]} ({col[2]})")

# ============================================
# CHECK EVIDENCE TABLE
# ============================================
print("\n📊 Checking EVIDENCE table...")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='evidence'")
if not cursor.fetchone():
    print("\n⚠️  'evidence' table missing.")
    print("   This table will be created automatically when you restart Flask.")
else:
    print("✅ 'evidence' table exists")

# ============================================
# CHECK KPI TABLE
# ============================================
print("\n📊 Checking KPI table...")
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='kpi'")
if not cursor.fetchone():
    print("\n⚠️  'kpi' table missing.")
    print("   This table will be created automatically when you restart Flask.")
else:
    print("✅ 'kpi' table exists")

# ============================================
# SUMMARY
# ============================================
print("\n" + "=" * 50)
print("✅ DATABASE FIX COMPLETED!")
print("=" * 50)
print("\n📋 Summary of changes:")

changes_made = False

if 'edit_attempts' not in workplan_column_names:
    print("  - Added edit_attempts to workplan table")
    changes_made = True
if 'requires_evidence' not in deliverable_column_names:
    print("  - Added requires_evidence to deliverable table")
    changes_made = True
if 'completed_at' not in deliverable_column_names:
    print("  - Added completed_at to deliverable table")
    changes_made = True
if 'completed_by' not in deliverable_column_names:
    print("  - Added completed_by to deliverable table")
    changes_made = True

if not changes_made:
    print("  No changes needed - all columns already exist")

print("\n📋 Tables status:")
print(f"  - User table: {len(user_columns)} columns")
print(f"  - Workplan table: {len(workplan_columns)} columns (+1 if edit_attempts was added)")
print(f"  - Deliverable table: {len(deliverable_columns)} columns")

conn.close()

print("\n" + "=" * 50)
print("🔧 NEXT STEPS:")
print("1. Run this fix script: python fix_database.py")
print("2. Restart your Flask app: python app.py")
print("3. The audit_log, evidence, and kpi tables will be created automatically")
print("4. All missing columns have been added")
print("=" * 50)