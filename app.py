from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

DATABASE = 'pushups.db'

def init_db():
   with sqlite3.connect(DATABASE) as conn:
       conn.execute('''CREATE TABLE IF NOT EXISTS users
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT)''')
       
       conn.execute('''CREATE TABLE IF NOT EXISTS pushups
                       (id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        date TEXT,
                        target INTEGER,
                        done INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        UNIQUE(user_id, date))''')  # Composite unique key for user_id and date

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login')
    
    # Get today's date
    today = datetime.today().date()

    # Get the date range from the request or default to the last 30 days
    start_date, end_date, date_range = get_date_range_from_request(request)
    print("Date Range:", date_range)
   
    # Get the database entries
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")  # Fetch all users
        all_users = cursor.fetchall()

        cursor.execute("""
            SELECT pushups.*, users.username 
            FROM pushups
            JOIN users ON pushups.user_id = users.id
        """)
        all_entries = cursor.fetchall()
       
        cursor.execute("SELECT * FROM pushups WHERE user_id = ?", (session['user_id'],))
        user_entries = cursor.fetchall()

    # Safe access to session attribute, defaults to None if not set
    selected_partner_id = session.get('selected_partner', None)

    # Convert entries to dicts keyed by date
    user_pushups = {entry[2]: entry[4] for entry in user_entries if start_date.strftime('%Y-%m-%d') <= entry[2] <= end_date.strftime('%Y-%m-%d')}
    target_pushups = {entry[2]: entry[3] for entry in user_entries if start_date.strftime('%Y-%m-%d') <= entry[2] <= end_date.strftime('%Y-%m-%d')}

    partner_pushups = {
        entry[2]: entry[4]
        for entry in all_entries
        if entry[0] == selected_partner_id and start_date.strftime('%Y-%m-%d') <= entry[2] <= end_date.strftime('%Y-%m-%d')
    }

    print("user_data", user_pushups)
    print("target_pushups", target_pushups)
    print("partner_pushups", partner_pushups)
    print("selected_partner_id", selected_partner_id)

    # Align all series with the date range
    user_pushups = [user_pushups.get(date, 0) for date in date_range]
    target_pushups = [target_pushups.get(date, 0) for date in date_range]
    partner_pushups = [partner_pushups.get(date, 0) for date in date_range]

    return render_template('index.html',
                           data_range=date_range,
                           start_date=start_date.strftime('%Y-%m-%d'),
                           end_date=end_date.strftime('%Y-%m-%d'),
                           user_pushups=user_pushups,
                           target_pushups=target_pushups,
                           partner_pushups=partner_pushups,
                           today=today, 
                           all_users=all_users, 
                           user_entries=user_entries, 
                           all_entries=all_entries,
                           selected_partner=selected_partner_id)  # Pass the selected user to the template


@app.route('/register', methods=['GET', 'POST'])
def register():
   if request.method == 'POST':
       username = request.form['username']
       password = request.form['password']
       hashed_password = generate_password_hash(password)
       
       try:
           with sqlite3.connect(DATABASE) as conn:
               conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
           flash("Registration successful! Please log in.", "success")
           return redirect('/login')
       except:
           flash("Username already exists!", "danger")
           return redirect('/register')
   
   return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
   if request.method == 'POST':
       username = request.form['username']
       password = request.form['password']
       
       with sqlite3.connect(DATABASE) as conn:
           cursor = conn.cursor()
           cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
           user = cursor.fetchone()
       
       if user and check_password_hash(user[2], password):
           session['user_id'] = user[0]
           session['username'] = user[1]  # Store the username in the session
           flash("Logged in successfully!", "success")
           return redirect('/')
       else:
           flash("Invalid username or password!", "danger")
   
   return render_template('login.html')

@app.route('/logout')
def logout():
   session.pop('user_id', None)
   session.pop('username', None)
   flash("Logged out successfully!", "success")
   return redirect('/login')

@app.route('/add', methods=['POST'])
def add_entry():
   if 'user_id' not in session:
       return redirect('/login')

   date = request.form['date']
   target = request.form['target']
   done = request.form['done']

   with sqlite3.connect(DATABASE) as conn:
       cursor = conn.cursor()
       cursor.execute("SELECT * FROM pushups WHERE user_id = ? AND date = ?", (session['user_id'], date))
       existing_entry = cursor.fetchone()

       if existing_entry:
           flash("An entry for this date already exists. Please update it instead.", "danger")
           return redirect('/')
       else:
           cursor.execute("INSERT INTO pushups (user_id, date, target, done) VALUES (?, ?, ?, ?)",
                          (session['user_id'], date, target, done))
           flash("Push-up entry added successfully!", "success")
   return redirect('/')

@app.route('/fix', methods=['POST'])
def fix_entry():
   if 'user_id' not in session:
       return redirect('/login')

   date = request.form['date']
   done = request.form['done']

   with sqlite3.connect(DATABASE) as conn:
       cursor = conn.cursor()
       cursor.execute("UPDATE pushups SET done = done + ? WHERE user_id = ? AND date = ?", (done, session['user_id'], date))
   return redirect('/')


@app.route('/delete_entry', methods=['POST'])
def delete_entry():
   if 'user_id' not in session:
       return redirect('/login')

   date = request.form['date']
   user_id = request.form['user_id']  # This should be the ID of the user owning the entry

   with sqlite3.connect(DATABASE) as conn:
       cursor = conn.cursor()
       cursor.execute("DELETE FROM pushups WHERE user_id = ? AND date = ?", (user_id, date))
   flash("Entry removed successfully!", "success")
   
   return redirect('/')



@app.route('/select_user', methods=['POST'])
def select_user():
   if 'user_id' not in session:
       return redirect('/login')

   selected_partner_id = request.form['selected_partner']

   with sqlite3.connect(DATABASE) as conn:
       cursor = conn.cursor()
       
       # Get the selected user's username for display purposes
       cursor.execute("SELECT username FROM users WHERE id = ?", (selected_partner_id,))
       selected_partner = cursor.fetchone()

       # Store the selected user in the session
       session['selected_partner'] = selected_partner_id
       if selected_partner:
           session['selected_partnername'] = selected_partner[0]  # Store the username

       cursor.execute("SELECT * FROM users")
       all_users = cursor.fetchall()

       cursor.execute("""
           SELECT pushups.*, users.username 
           FROM pushups
           JOIN users ON pushups.user_id = users.id
           WHERE user_id = ? OR user_id = ?
       """, (session['user_id'], selected_partner_id))  # Fetch both users' entries
       all_entries = cursor.fetchall()
       
       cursor.execute("SELECT * FROM pushups WHERE user_id = ?", (session['user_id'],))
       user_entries = cursor.fetchall()

   return redirect('/')  # Redirect back to the home page


def get_date_range_from_request(request, default_days=7):

    # Get date range from request args or default to last 7 days
    end_date_str = request.args.get("end_date")
    start_date_str = request.args.get("start_date")

    try:
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d") if end_date_str else datetime.today()
    except:
        end_date = datetime.today()

    try:
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d") if start_date_str else end_date - timedelta(days=29)
    except:
        start_date = end_date - timedelta(days=29)

    # Ensure proper ordering
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    # Generate date range labels
    date_range = [(start_date + timedelta(days=i)).strftime('%Y-%m-%d')
                  for i in range((end_date - start_date).days + 1)]
    
    return start_date, end_date, date_range


if __name__ == '__main__':
   init_db()
   app.run(host='127.0.0.1', port=5000)

