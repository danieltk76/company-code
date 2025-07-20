# ShopEZ - Modern E-commerce Platform

ShopEZ is a full-featured e-commerce platform built with Flask, designed for small to medium-sized businesses looking to establish their online presence.

## Features

- **User Management**: Customer registration and authentication
- **Product Catalog**: Full product management with categories and inventory tracking
- **Shopping Cart**: Session-based cart functionality
- **Order Processing**: Complete order lifecycle management
- **Payment Integration**: Multiple payment method support
- **Admin Dashboard**: Comprehensive administrative tools
- **Discount System**: Flexible discount code management
- **Analytics**: User behavior tracking and sales reporting
- **Import/Export**: Bulk product data management

## Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation

1. Clone the repository
```bash
git clone https://github.com/company/shopez.git
cd shopez
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Initialize the database
```bash
python app.py
```

4. Run the application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## API Documentation

### Authentication Endpoints
- `POST /register` - Create new user account
- `POST /login` - User authentication

### Product Management
- `GET /products` - List products with filtering and search
- `POST /products` - Create new product (authenticated users)

### Shopping Cart
- `POST /cart/add` - Add items to cart

### Order Management
- `POST /orders` - Create new order
- `PUT /orders/<id>/status` - Update order status

### Admin Features
- `GET /admin/users` - List all users (admin only)
- `POST /admin/orders/bulk-update` - Bulk order updates

### Analytics
- `POST /api/analytics/track` - Track user events
- `GET /api/reports/sales` - Generate sales reports

## Configuration

Set the following environment variables:

- `SECRET_KEY`: Flask session secret key
- `DATABASE_URL`: Database connection string (optional, defaults to SQLite)

## Database Schema

The application uses SQLite by default with the following tables:
- `users` - User accounts and authentication
- `products` - Product catalog
- `orders` - Order records
- `order_items` - Order line items
- `discount_codes` - Promotional codes
- `user_sessions` - Session and analytics data

## Security Features

- Password hashing with Werkzeug
- Session-based authentication
- HMAC signature verification for webhooks
- SQL injection prevention with parameterized queries
- Input validation and sanitization

## Support

For technical support or feature requests, please contact our development team.

## License

Copyright (c) 2024 ShopEZ Inc. All rights reserved. 