from flask import Flask, request, render_template_string, render_template, jsonify
from time import sleep, time
import logging


# Set up logging
logging.basicConfig(level=logging.DEBUG)


app = Flask(__name__)

USER_DB = {
    'admin': 'password123',
    'user1': 'password456',
    'user2': 'password789'
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Application</title>
</head>
<body>
    <h2>Test Application Login</h2>
    <form method="post" action="/login">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    print("Received username:", username)  # For debugging purposes

   # Simulated Error-Based SQL Injection Detection
    if "' OR '1'='1" in username or "'; IF (1=1) WAITFOR DELAY '0:0:5' --" in username:
        app.logger.warning(f"Simulated error-based SQL injection detected: {username}")
        return "SQL syntax error: Incorrect SQL query", 500

    # Union-Based SQL Injection Response
    elif "UNION SELECT" in username:
        app.logger.warning(f"Simulated union-based SQL injection detected: {username}")
        simulated_data = "Username: admin, Password: pass123<br>Username: user2, Password: userpass2"
        return simulated_data

    # Blind/Time-Based/Out-of-Band SQL Injection Response
    elif "' AND 1=1 -- " in username or "' OR SLEEP(5) --" in username:
        app.logger.warning(f"Simulated time-based SQL injection detected: {username}")
        sleep(5)  # Simulating time delay
        return "Time delay detected - potential SQL injection"

    elif "xp_cmdshell" in username or "EXEC" in username:
        app.logger.warning(f"Simulated out-of-band SQL injection detected: {username}")
        return "Out-of-band interaction detected - potential SQL injection"

    # Standard login logic
    try:
        if username in USER_DB and USER_DB[username] == password:
            app.logger.info(f"Login successful for username: {username}")
            return "Logged in successfully!"
        else:
            app.logger.warning(f"Login failed for username: {username}")
            return render_template_string(HTML_TEMPLATE, error="Login failed. Incorrect username or password.")

    except Exception as e:
        app.logger.error(f"Exception occurred during login for username {username}: {e}")
        return render_template_string(HTML_TEMPLATE, error="An error occurred during login.")

    return render_template_string(HTML_TEMPLATE, error="Login failed. Incorrect username or password.")

if __name__ == "__main__":
    app.run(debug=True)

if __name__ == "__main__":
    app.run(debug=True)