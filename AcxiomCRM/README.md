# AcxiomCRM
Simple role-based CRM built with Python (Flask), SQLite, HTML and CSS.

## Run
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000

## Demo logins
- Admin: admin@acxiom.com / Admin@123
- Manager: manager@acxiom.com / Manager@123
- Sales: sales@acxiom.com / Sales@123

## Features
Login/Register/Logout, hashed passwords, password policy, lockout (3 fails = 5 min), roles (Admin/Manager/SalesExecutive),
Customers, Leads (+convert), Opportunities, Follow-Ups, Dashboard + Chart.js, Audit Log, User admin,
client + server validation, CSRF protection, REST API (/api/customers, /api/leads, /api/opportunities, /api/followups).
