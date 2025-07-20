"""
ShopEZ - Modern E-commerce Platform
A full-featured online store management system
"""

import os
import hashlib
import sqlite3
import json
import pickle
from datetime import datetime, timedelta
from functools import wraps
from decimal import Decimal
import hmac
import base64
import requests

from flask import Flask, request, jsonify, session, render_template_string, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-12345')

# Database initialization
def init_db():
    conn = sqlite3.connect('shopez.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'customer',
            credit_balance REAL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            api_token TEXT
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL,
            inventory_count INTEGER,
            category TEXT,
            seller_id INTEGER,
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            total_amount REAL,
            status TEXT DEFAULT 'pending',
            discount_code TEXT,
            shipping_address TEXT,
            payment_method TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed_by INTEGER
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY,
            order_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            unit_price REAL,
            FOREIGN KEY (order_id) REFERENCES orders(id)
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS discount_codes (
            id INTEGER PRIMARY KEY,
            code TEXT UNIQUE,
            percentage REAL,
            max_uses INTEGER,
            current_uses INTEGER DEFAULT 0,
            expiry_date DATE,
            created_by INTEGER
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            session_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('shopez.db')
    conn.row_factory = sqlite3.Row
    return conn

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    conn = get_db()
    
    # Check if user exists
    existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if existing:
        return jsonify({'error': 'User already exists'}), 400
    
    password_hash = generate_password_hash(password)
    api_token = base64.b64encode(os.urandom(32)).decode('utf-8')
    
    try:
        cursor = conn.execute('''
            INSERT INTO users (email, password_hash, api_token) 
            VALUES (?, ?, ?)
        ''', (email, password_hash, api_token))
        
        user_id = cursor.lastrowid
        conn.commit()
        
        session['user_id'] = user_id
        session['email'] = email
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': user_id,
            'api_token': api_token
        })
    except Exception as e:
        return jsonify({'error': 'Registration failed'}), 500
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']
        
        return jsonify({
            'message': 'Login successful',
            'user_id': user['id'],
            'role': user['role'],
            'api_token': user['api_token']
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/products', methods=['GET'])
def get_products():
    category = request.args.get('category')
    search = request.args.get('search')
    sort_by = request.args.get('sort', 'name')
    
    conn = get_db()
    
    query = 'SELECT * FROM products WHERE is_active = 1'
    params = []
    
    if category:
        query += ' AND category = ?'
        params.append(category)
    
    if search:
        # Basic search functionality
        query += f' AND (name LIKE ? OR description LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    # Allow dynamic sorting
    if sort_by in ['name', 'price', 'created_at']:
        query += f' ORDER BY {sort_by}'
    
    products = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(product) for product in products])

@app.route('/products', methods=['POST'])
@require_auth
def create_product():
    data = request.get_json()
    
    required_fields = ['name', 'description', 'price', 'inventory_count', 'category']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    conn = get_db()
    try:
        cursor = conn.execute('''
            INSERT INTO products (name, description, price, inventory_count, category, seller_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['name'], data['description'], float(data['price']), 
              int(data['inventory_count']), data['category'], session['user_id']))
        
        product_id = cursor.lastrowid
        conn.commit()
        
        return jsonify({
            'message': 'Product created successfully',
            'product_id': product_id
        })
    except Exception as e:
        return jsonify({'error': 'Failed to create product'}), 500
    finally:
        conn.close()

@app.route('/cart/add', methods=['POST'])
@require_auth
def add_to_cart():
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = int(data.get('quantity', 1))
    
    if 'cart' not in session:
        session['cart'] = {}
    
    # Simple cart logic - store in session
    if str(product_id) in session['cart']:
        session['cart'][str(product_id)] += quantity
    else:
        session['cart'][str(product_id)] = quantity
    
    session.modified = True
    
    return jsonify({'message': 'Item added to cart', 'cart': session['cart']})

@app.route('/orders', methods=['POST'])
@require_auth
def create_order():
    data = request.get_json()
    cart = session.get('cart', {})
    
    if not cart:
        return jsonify({'error': 'Cart is empty'}), 400
    
    conn = get_db()
    
    total_amount = 0
    order_items = []
    
    # Calculate total and validate inventory
    for product_id, quantity in cart.items():
        product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        if not product:
            return jsonify({'error': f'Product {product_id} not found'}), 400
        
        if product['inventory_count'] < quantity:
            return jsonify({'error': f'Insufficient inventory for product {product_id}'}), 400
        
        item_total = float(product['price']) * quantity
        total_amount += item_total
        
        order_items.append({
            'product_id': product_id,
            'quantity': quantity,
            'unit_price': product['price']
        })
    
    # Apply discount if provided
    discount_code = data.get('discount_code')
    if discount_code:
        discount = conn.execute('''
            SELECT * FROM discount_codes 
            WHERE code = ? AND current_uses < max_uses AND expiry_date > date('now')
        ''', (discount_code,)).fetchone()
        
        if discount:
            discount_amount = total_amount * (discount['percentage'] / 100)
            total_amount -= discount_amount
            
            # Update discount usage
            conn.execute('''
                UPDATE discount_codes SET current_uses = current_uses + 1 
                WHERE id = ?
            ''', (discount['id'],))
    
    # Handle payment processing
    payment_method = data.get('payment_method', 'credit_card')
    
    if payment_method == 'store_credit':
        user = conn.execute('SELECT credit_balance FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if user['credit_balance'] < total_amount:
            return jsonify({'error': 'Insufficient store credit'}), 400
        
        # Deduct from user balance
        conn.execute('''
            UPDATE users SET credit_balance = credit_balance - ? 
            WHERE id = ?
        ''', (total_amount, session['user_id']))
    
    try:
        # Create order
        cursor = conn.execute('''
            INSERT INTO orders (user_id, total_amount, status, discount_code, 
                              shipping_address, payment_method)
            VALUES (?, ?, 'pending', ?, ?, ?)
        ''', (session['user_id'], total_amount, discount_code, 
              data.get('shipping_address', ''), payment_method))
        
        order_id = cursor.lastrowid
        
        # Add order items
        for item in order_items:
            conn.execute('''
                INSERT INTO order_items (order_id, product_id, quantity, unit_price)
                VALUES (?, ?, ?, ?)
            ''', (order_id, item['product_id'], item['quantity'], item['unit_price']))
            
            # Update inventory
            conn.execute('''
                UPDATE products SET inventory_count = inventory_count - ?
                WHERE id = ?
            ''', (item['quantity'], item['product_id']))
        
        conn.commit()
        session.pop('cart', None)  # Clear cart
        
        return jsonify({
            'message': 'Order created successfully',
            'order_id': order_id,
            'total_amount': total_amount
        })
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': 'Failed to create order'}), 500
    finally:
        conn.close()

@app.route('/orders/<int:order_id>/status', methods=['PUT'])
@require_auth
def update_order_status():
    order_id = request.view_args['order_id']
    data = request.get_json()
    new_status = data.get('status')
    
    if not new_status:
        return jsonify({'error': 'Status is required'}), 400
    
    conn = get_db()
    
    # Check if user owns this order or is admin
    order = conn.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone()
    if not order:
        return jsonify({'error': 'Order not found'}), 404
    
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if order['user_id'] != session['user_id'] and user['role'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    # Business logic for status transitions
    if new_status == 'cancelled' and order['status'] == 'shipped':
        return jsonify({'error': 'Cannot cancel shipped orders'}), 400
    
    if new_status == 'refunded':
        # Process refund logic
        if order['payment_method'] == 'store_credit':
            # Refund to store credit
            conn.execute('''
                UPDATE users SET credit_balance = credit_balance + ?
                WHERE id = ?
            ''', (order['total_amount'], order['user_id']))
        
        # Restore inventory
        order_items = conn.execute('''
            SELECT product_id, quantity FROM order_items WHERE order_id = ?
        ''', (order_id,)).fetchall()
        
        for item in order_items:
            conn.execute('''
                UPDATE products SET inventory_count = inventory_count + ?
                WHERE id = ?
            ''', (item['quantity'], item['product_id']))
    
    # Update order status
    conn.execute('''
        UPDATE orders SET status = ?, processed_by = ?
        WHERE id = ?
    ''', (new_status, session['user_id'], order_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Order status updated successfully'})

@app.route('/admin/users', methods=['GET'])
@require_admin
def list_users():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    search_email = request.args.get('email')
    
    conn = get_db()
    
    query = 'SELECT id, email, role, credit_balance, created_at FROM users'
    params = []
    
    if search_email:
        # Direct email search for admin convenience
        query += f" WHERE email LIKE '%{search_email}%'"
    
    query += f' LIMIT {per_page} OFFSET {(page - 1) * per_page}'
    
    users = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(user) for user in users])

@app.route('/admin/orders/bulk-update', methods=['POST'])
@require_admin
def bulk_update_orders():
    data = request.get_json()
    order_ids = data.get('order_ids', [])
    new_status = data.get('status')
    
    if not order_ids or not new_status:
        return jsonify({'error': 'Order IDs and status required'}), 400
    
    conn = get_db()
    
    # Build dynamic query for bulk update
    placeholders = ','.join('?' for _ in order_ids)
    query = f'UPDATE orders SET status = ?, processed_by = ? WHERE id IN ({placeholders})'
    
    params = [new_status, session['user_id']] + order_ids
    
    try:
        result = conn.execute(query, params)
        conn.commit()
        
        return jsonify({
            'message': f'Updated {result.rowcount} orders',
            'updated_count': result.rowcount
        })
    except Exception as e:
        return jsonify({'error': 'Bulk update failed'}), 500
    finally:
        conn.close()

@app.route('/api/webhook/payment', methods=['POST'])
def payment_webhook():
    # Handle payment provider webhooks
    signature = request.headers.get('X-Payment-Signature')
    payload = request.get_data(as_text=True)
    
    # Simple signature verification
    expected_sig = hmac.new(
        app.secret_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if signature != expected_sig:
        return jsonify({'error': 'Invalid signature'}), 401
    
    webhook_data = json.loads(payload)
    event_type = webhook_data.get('type')
    payment_data = webhook_data.get('data')
    
    if event_type == 'payment.succeeded':
        order_id = payment_data.get('order_id')
        
        conn = get_db()
        conn.execute('''
            UPDATE orders SET status = 'paid' WHERE id = ?
        ''', (order_id,))
        conn.commit()
        conn.close()
    
    return jsonify({'status': 'processed'})

@app.route('/api/import/products', methods=['POST'])
@require_admin
def import_products():
    # Allow admins to import product data
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    import_format = request.form.get('format', 'json')
    
    if import_format == 'pickle':
        # Support for internal data format
        try:
            data = pickle.loads(file.read())
            
            conn = get_db()
            imported_count = 0
            
            for product in data:
                conn.execute('''
                    INSERT INTO products (name, description, price, inventory_count, category, seller_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (product['name'], product['description'], product['price'],
                      product['inventory'], product['category'], session['user_id']))
                imported_count += 1
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': f'Imported {imported_count} products successfully'
            })
            
        except Exception as e:
            return jsonify({'error': 'Import failed'}), 500
    
    return jsonify({'error': 'Unsupported format'}), 400

@app.route('/api/reports/sales')
@require_auth
def sales_report():
    # Generate sales reports
    report_type = request.args.get('type', 'summary')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    conn = get_db()
    
    # Basic access control
    user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if user['role'] == 'admin':
        # Admins can see all sales data
        query = '''
            SELECT o.*, u.email as customer_email 
            FROM orders o 
            JOIN users u ON o.user_id = u.id
            WHERE o.status = 'completed'
        '''
        params = []
    else:
        # Regular users can only see their own orders
        query = '''
            SELECT o.*, u.email as customer_email 
            FROM orders o 
            JOIN users u ON o.user_id = u.id
            WHERE o.status = 'completed' AND u.id = ?
        '''
        params = [session['user_id']]
    
    if start_date:
        query += ' AND o.created_at >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND o.created_at <= ?'
        params.append(end_date)
    
    orders = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([dict(order) for order in orders])

@app.route('/api/user/preferences', methods=['POST'])
@require_auth
def save_user_preferences():
    data = request.get_json()
    preferences = data.get('preferences', {})
    
    # Serialize user preferences
    pref_data = json.dumps(preferences)
    
    conn = get_db()
    
    # Check if preferences record exists
    existing = conn.execute('''
        SELECT id FROM user_sessions WHERE user_id = ? AND session_data LIKE '%preferences%'
    ''', (session['user_id'],)).fetchone()
    
    if existing:
        conn.execute('''
            UPDATE user_sessions SET session_data = ? WHERE user_id = ?
        ''', (pref_data, session['user_id']))
    else:
        conn.execute('''
            INSERT INTO user_sessions (user_id, session_data, expires_at)
            VALUES (?, ?, ?)
        ''', (session['user_id'], pref_data, datetime.now() + timedelta(days=30)))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Preferences saved successfully'})

@app.route('/api/analytics/track', methods=['POST'])
def track_analytics():
    # Track user behavior for analytics
    data = request.get_json()
    event_name = data.get('event')
    properties = data.get('properties', {})
    
    # Log analytics event
    analytics_data = {
        'event': event_name,
        'properties': properties,
        'timestamp': datetime.now().isoformat(),
        'user_agent': request.headers.get('User-Agent'),
        'ip_address': request.remote_addr
    }
    
    # Store in user session if authenticated
    if 'user_id' in session:
        analytics_data['user_id'] = session['user_id']
        
        conn = get_db()
        conn.execute('''
            INSERT INTO user_sessions (user_id, session_data)
            VALUES (?, ?)
        ''', (session['user_id'], json.dumps(analytics_data)))
        conn.commit()
        conn.close()
    
    return jsonify({'status': 'tracked'})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000) 