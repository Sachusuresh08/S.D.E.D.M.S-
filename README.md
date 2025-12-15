# Simple Flask Login/Register (SQLite)

This small app provides a login page and a registration page. Registered users are stored locally in `users.db` (SQLite). Only logged-in users can access the protected page which shows "You got it".

Files added:
- `app.py` — Flask application (creates `users.db` automatically).
- `templates/index.html` — login + register forms (toggle between them).
- `templates/protected.html` — protected page shown after login.
- `requirements.txt` — Python dependencies.

Quick start (PowerShell):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

Notes:
- Passwords are stored hashed (Werkzeug).
- For production, change `app.secret_key` and disable `debug=True`.

User roles
- The app stores a `role` for each user: `user`, `staff`, or `admin`.
- The registration form includes a role selector for demo purposes; in a real
	deployment you should only allow trusted admins to assign elevated roles.
