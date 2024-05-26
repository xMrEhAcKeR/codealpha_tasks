from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Route to handle user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # SQL Injection vulnerability
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        user = cursor.fetchone()
        
        if user:
            return 'Logged in successfully'
        else:
            return 'Invalid credentials'
    
    return render_template_string('''<form method="POST">
                                        Username: <input type="text" name="username"><br>
                                        Password: <input type="password" name="password"><br>
                                        <input type="submit" value="Login">
                                      </form>''')

# Route to display user profile
@app.route('/profile/<username>')
def profile(username):
    return f'Welcome, {username}!'

if __name__ == '__main__':
    app.run(debug=True)
