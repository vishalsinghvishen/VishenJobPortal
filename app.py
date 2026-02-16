from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'change_this_in_production_xyz123'
DATABASE = 'job_portal.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','employer','jobseeker')),
        company TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL, description TEXT NOT NULL,
        location TEXT NOT NULL, salary TEXT, job_type TEXT,
        employer_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(employer_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL, jobseeker_id INTEGER NOT NULL,
        cover_letter TEXT, status TEXT DEFAULT 'pending',
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(job_id) REFERENCES jobs(id),
        FOREIGN KEY(jobseeker_id) REFERENCES users(id))''')
    if not c.execute("SELECT id FROM users WHERE role='admin'").fetchone():
        c.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)",
                  ('Admin','admin@jobportal.com',generate_password_hash('admin123'),'admin'))
    conn.commit(); conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in.','warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                flash('Access denied.','danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'].strip(), request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session.update({'user_id':user['id'],'name':user['name'],'role':user['role'],'email':user['email']})
            flash(f'Welcome back, {user["name"]}!','success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.','danger')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name,email,password,role = (request.form['name'].strip(),
            request.form['email'].strip(),request.form['password'],request.form['role'])
        company = request.form.get('company','').strip()
        if role not in ('employer','jobseeker'):
            flash('Invalid role.','danger'); return redirect(url_for('register'))
        conn = get_db()
        if conn.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone():
            conn.close(); flash('Email already registered.','danger')
            return redirect(url_for('register'))
        conn.execute("INSERT INTO users (name,email,password,role,company) VALUES (?,?,?,?,?)",
                     (name,email,generate_password_hash(password),role,company))
        conn.commit(); conn.close()
        flash('Registered! Please log in.','success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear(); flash('Logged out.','info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role, conn = session['role'], get_db()
    if role == 'admin':
        now = datetime.now()
        periods = {'daily':now-timedelta(days=1),'weekly':now-timedelta(weeks=1),
                   'monthly':now-timedelta(days=30),'yearly':now-timedelta(days=365)}
        stats = {}
        for p,since in periods.items():
            s = since.strftime('%Y-%m-%d %H:%M:%S')
            stats[p] = {
                'jobs':conn.execute("SELECT COUNT(*) FROM jobs WHERE created_at>=?",(s,)).fetchone()[0],
                'employers':conn.execute("SELECT COUNT(*) FROM users WHERE role='employer' AND created_at>=?",(s,)).fetchone()[0],
                'jobseekers':conn.execute("SELECT COUNT(*) FROM users WHERE role='jobseeker' AND created_at>=?",(s,)).fetchone()[0]}
        totals = {'jobs':conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0],
                  'employers':conn.execute("SELECT COUNT(*) FROM users WHERE role='employer'").fetchone()[0],
                  'jobseekers':conn.execute("SELECT COUNT(*) FROM users WHERE role='jobseeker'").fetchone()[0]}
        conn.close()
        return render_template('admin_dashboard.html', stats=stats, totals=totals)
    elif role == 'employer':
        jobs = conn.execute(
            "SELECT j.*, COUNT(a.id) as app_count FROM jobs j "
            "LEFT JOIN applications a ON a.job_id=j.id WHERE j.employer_id=? GROUP BY j.id ORDER BY j.created_at DESC",
            (session['user_id'],)).fetchall()
        conn.close(); return render_template('employer_dashboard.html', jobs=jobs)
    else:
        jobs = conn.execute(
            "SELECT j.*, u.name as employer_name, u.company,"
            "(SELECT id FROM applications WHERE job_id=j.id AND jobseeker_id=?) as applied "
            "FROM jobs j JOIN users u ON u.id=j.employer_id ORDER BY j.created_at DESC",
            (session['user_id'],)).fetchall()
        conn.close(); return render_template('jobseeker_dashboard.html', jobs=jobs)

# ─── ADMIN ───────────────────────────────────────────────────────────────────
@app.route('/admin/jobs')
@role_required('admin')
def admin_jobs():
    conn = get_db()
    jobs = conn.execute("SELECT j.*,u.name as employer_name,u.company,COUNT(a.id) as app_count "
        "FROM jobs j JOIN users u ON u.id=j.employer_id "
        "LEFT JOIN applications a ON a.job_id=j.id GROUP BY j.id ORDER BY j.created_at DESC").fetchall()
    conn.close(); return render_template('admin_jobs.html', jobs=jobs)

@app.route('/admin/jobs/delete/<int:job_id>', methods=['POST'])
@role_required('admin')
def admin_delete_job(job_id):
    conn = get_db()
    conn.execute("DELETE FROM applications WHERE job_id=?",(job_id,))
    conn.execute("DELETE FROM jobs WHERE id=?",(job_id,))
    conn.commit(); conn.close(); flash('Job deleted.','success')
    return redirect(url_for('admin_jobs'))

@app.route('/admin/employers')
@role_required('admin')
def admin_employers():
    conn = get_db()
    employers = conn.execute("SELECT u.*,COUNT(j.id) as job_count FROM users u "
        "LEFT JOIN jobs j ON j.employer_id=u.id WHERE u.role='employer' GROUP BY u.id ORDER BY u.created_at DESC").fetchall()
    conn.close(); return render_template('admin_employers.html', employers=employers)

@app.route('/admin/employers/delete/<int:user_id>', methods=['POST'])
@role_required('admin')
def admin_delete_employer(user_id):
    conn = get_db()
    for jid in [r[0] for r in conn.execute("SELECT id FROM jobs WHERE employer_id=?",(user_id,)).fetchall()]:
        conn.execute("DELETE FROM applications WHERE job_id=?",(jid,))
    conn.execute("DELETE FROM jobs WHERE employer_id=?",(user_id,))
    conn.execute("DELETE FROM users WHERE id=?",(user_id,))
    conn.commit(); conn.close(); flash('Employer removed.','success')
    return redirect(url_for('admin_employers'))

@app.route('/admin/jobseekers')
@role_required('admin')
def admin_jobseekers():
    conn = get_db()
    seekers = conn.execute("SELECT u.*,COUNT(a.id) as app_count FROM users u "
        "LEFT JOIN applications a ON a.jobseeker_id=u.id WHERE u.role='jobseeker' GROUP BY u.id ORDER BY u.created_at DESC").fetchall()
    conn.close(); return render_template('admin_jobseekers.html', seekers=seekers)

@app.route('/admin/jobseekers/delete/<int:user_id>', methods=['POST'])
@role_required('admin')
def admin_delete_jobseeker(user_id):
    conn = get_db()
    conn.execute("DELETE FROM applications WHERE jobseeker_id=?",(user_id,))
    conn.execute("DELETE FROM users WHERE id=?",(user_id,))
    conn.commit(); conn.close(); flash('Jobseeker removed.','success')
    return redirect(url_for('admin_jobseekers'))

# ─── EMPLOYER ─────────────────────────────────────────────────────────────────
@app.route('/employer/post-job', methods=['GET','POST'])
@role_required('employer')
def post_job():
    if request.method == 'POST':
        conn = get_db()
        conn.execute("INSERT INTO jobs (title,description,location,salary,job_type,employer_id) VALUES (?,?,?,?,?,?)",
                     (request.form['title'].strip(),request.form['description'].strip(),
                      request.form['location'].strip(),request.form.get('salary','').strip(),
                      request.form.get('job_type','Full-time'),session['user_id']))
        conn.commit(); conn.close()
        flash('Job posted!','success'); return redirect(url_for('dashboard'))
    return render_template('post_job.html')

@app.route('/employer/applications/<int:job_id>')
@role_required('employer')
def view_applications(job_id):
    conn = get_db()
    job = conn.execute("SELECT * FROM jobs WHERE id=? AND employer_id=?",
                       (job_id,session['user_id'])).fetchone()
    if not job: conn.close(); flash('Not found.','danger'); return redirect(url_for('dashboard'))
    apps = conn.execute("SELECT a.*,u.name,u.email FROM applications a "
        "JOIN users u ON u.id=a.jobseeker_id WHERE a.job_id=? ORDER BY a.applied_at DESC",(job_id,)).fetchall()
    conn.close(); return render_template('view_applications.html', job=job, applications=apps)

@app.route('/employer/application/status/<int:app_id>/<status>', methods=['POST'])
@role_required('employer')
def update_app_status(app_id, status):
    if status not in ('pending','accepted','rejected'):
        flash('Invalid status.','danger'); return redirect(url_for('dashboard'))
    conn = get_db()
    conn.execute("UPDATE applications SET status=? WHERE id=?",(status,app_id))
    conn.commit(); conn.close(); flash(f'Marked as {status}.','success')
    return redirect(request.referrer or url_for('dashboard'))

# ─── JOBSEEKER ────────────────────────────────────────────────────────────────
@app.route('/jobs/<int:job_id>')
@login_required
def job_detail(job_id):
    conn = get_db()
    job = conn.execute("SELECT j.*,u.name as employer_name,u.company,u.email as employer_email "
        "FROM jobs j JOIN users u ON u.id=j.employer_id WHERE j.id=?",(job_id,)).fetchone()
    if not job: conn.close(); flash('Not found.','danger'); return redirect(url_for('dashboard'))
    applied = conn.execute("SELECT id FROM applications WHERE job_id=? AND jobseeker_id=?",
        (job_id,session['user_id'])).fetchone() if session['role']=='jobseeker' else None
    conn.close(); return render_template('job_detail.html', job=job, already_applied=applied)

@app.route('/jobs/apply/<int:job_id>', methods=['POST'])
@role_required('jobseeker')
def apply_job(job_id):
    conn = get_db()
    if conn.execute("SELECT id FROM applications WHERE job_id=? AND jobseeker_id=?",
                    (job_id,session['user_id'])).fetchone():
        conn.close(); flash('Already applied.','warning')
        return redirect(url_for('job_detail',job_id=job_id))
    conn.execute("INSERT INTO applications (job_id,jobseeker_id,cover_letter) VALUES (?,?,?)",
                 (job_id,session['user_id'],request.form.get('cover_letter','').strip()))
    conn.commit(); conn.close()
    flash('Application submitted!','success'); return redirect(url_for('my_applications'))

@app.route('/my-applications')
@role_required('jobseeker')
def my_applications():
    conn = get_db()
    apps = conn.execute("SELECT a.*,j.title,j.location,j.job_type,u.name as employer_name,u.company "
        "FROM applications a JOIN jobs j ON j.id=a.job_id JOIN users u ON u.id=j.employer_id "
        "WHERE a.jobseeker_id=? ORDER BY a.applied_at DESC",(session['user_id'],)).fetchall()
    conn.close(); return render_template('my_applications.html', applications=apps)

@app.route('/profile', methods=['GET','POST'])
@role_required('jobseeker')
def profile():
    conn = get_db()
    if request.method == 'POST':
        name = request.form['name'].strip()
        pw = request.form.get('password','').strip()
        if pw: conn.execute("UPDATE users SET name=?,password=? WHERE id=?",
                            (name,generate_password_hash(pw),session['user_id']))
        else:  conn.execute("UPDATE users SET name=? WHERE id=?",(name,session['user_id']))
        conn.commit(); session['name']=name; flash('Profile updated!','success')
        conn.close(); return redirect(url_for('profile'))
    user = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    conn.close(); return render_template('profile.html', user=user)

if __name__ == '__main__':
    init_db(); app.run(debug=True)