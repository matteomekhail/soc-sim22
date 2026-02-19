#!/usr/bin/env python3
"""
Scenario 13: Vulnerable Flask Web Application with SQL Injection flaws.

WARNING: This application is INTENTIONALLY VULNERABLE for educational purposes.
DO NOT deploy this in any production or internet-facing environment.
"""

import os
import sqlite3

from flask import Flask, request, jsonify, g

app = Flask(__name__)
DATABASE = os.path.join(os.path.dirname(__file__), "vuln_app.db")


def get_db():
    """Get database connection (stored in Flask's g object)."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with sample data."""
    db = sqlite3.connect(DATABASE)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            full_name TEXT
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL,
            description TEXT,
            category TEXT
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount REAL,
            description TEXT,
            card_number TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        -- Sample users (passwords are intentionally plaintext for demo)
        INSERT OR IGNORE INTO users (id, username, password, email, role, full_name) VALUES
            (1, 'admin', 'admin123!', 'admin@acmecorp.local', 'admin', 'System Administrator'),
            (2, 'john.doe', 'password123', 'john@acmecorp.local', 'user', 'John Doe'),
            (3, 'jane.smith', 'letmein', 'jane@acmecorp.local', 'user', 'Jane Smith'),
            (4, 'bob.wilson', 'qwerty2024', 'bob@acmecorp.local', 'manager', 'Bob Wilson'),
            (5, 'svc_backup', 'BackupS3rv1ce!', 'svc@acmecorp.local', 'service', 'Backup Service');

        -- Sample products
        INSERT OR IGNORE INTO products (id, name, price, description, category) VALUES
            (1, 'Enterprise License', 49999.99, 'Full enterprise software license', 'software'),
            (2, 'Support Plan', 9999.99, 'Annual support and maintenance', 'service'),
            (3, 'Training Package', 2499.99, 'Staff training program', 'training');

        -- Sample transactions
        INSERT OR IGNORE INTO transactions (id, user_id, amount, description, card_number) VALUES
            (1, 2, 150.00, 'Monthly subscription', '4111-XXXX-XXXX-1234'),
            (2, 3, 299.99, 'Annual plan upgrade', '5500-XXXX-XXXX-5678'),
            (3, 4, 49999.99, 'Enterprise purchase', '3782-XXXX-XXXX-9012');
    """)
    db.commit()
    db.close()


# ============================================================
# VULNERABLE ENDPOINTS (intentionally insecure)
# ============================================================

@app.route("/")
def index():
    return jsonify({
        "app": "WCACE Vulnerable Web App",
        "warning": "INTENTIONALLY VULNERABLE - Educational use only",
        "endpoints": ["/login", "/search", "/users", "/products", "/transactions"],
    })


@app.route("/login", methods=["POST"])
def login():
    """VULNERABLE: SQL injection in login form."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: Direct string formatting in SQL query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    db = get_db()
    try:
        result = db.execute(query).fetchone()
        if result:
            return jsonify({
                "status": "success",
                "message": f"Welcome {result['full_name']}",
                "role": result["role"],
            })
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    except Exception as e:
        # VULNERABLE: Exposes SQL error details
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/search")
def search():
    """VULNERABLE: SQL injection in search parameter."""
    query_param = request.args.get("q", "")
    category = request.args.get("category", "")

    # VULNERABLE: Direct string interpolation
    if category:
        query = f"SELECT * FROM products WHERE category='{category}' AND name LIKE '%{query_param}%'"
    else:
        query = f"SELECT * FROM products WHERE name LIKE '%{query_param}%'"

    db = get_db()
    try:
        results = db.execute(query).fetchall()
        return jsonify({
            "results": [dict(r) for r in results],
            "count": len(results),
            "query": query_param,
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/users")
def list_users():
    """VULNERABLE: SQL injection in sort/filter parameters."""
    sort_by = request.args.get("sort", "id")
    order = request.args.get("order", "ASC")

    # VULNERABLE: Unvalidated column name and sort order
    query = f"SELECT id, username, email, role, full_name FROM users ORDER BY {sort_by} {order}"

    db = get_db()
    try:
        results = db.execute(query).fetchall()
        return jsonify({"users": [dict(r) for r in results]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/transactions")
def transactions():
    """VULNERABLE: SQL injection in user_id filter."""
    user_id = request.args.get("user_id", "")

    if not user_id:
        return jsonify({"error": "user_id parameter required"}), 400

    # VULNERABLE: Direct interpolation
    query = f"SELECT * FROM transactions WHERE user_id={user_id}"

    db = get_db()
    try:
        results = db.execute(query).fetchall()
        return jsonify({"transactions": [dict(r) for r in results]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    init_db()
    print("[*] Vulnerable web app starting on http://localhost:5000")
    print("[!] WARNING: This app is intentionally vulnerable!")
    app.run(host="0.0.0.0", port=5000, debug=False)
