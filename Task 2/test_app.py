from flask import Flask, request

app = Flask(__name__)

# Dummy login page vulnerable to SQL injection
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: unsanitized SQL query (simulation)
        if username == "' OR '1'='1" or password == "' OR '1'='1":
            return "Logged in as admin (SQLi detected!)"
        return f"Login failed for {username}"
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

# Reflected XSS vulnerability
@app.route("/", methods=["GET"])
def home():
    q = request.args.get("q", "")
    return f"<h1>Search Results for: {q}</h1>"

if __name__ == "__main__":
    app.run(debug=True)
