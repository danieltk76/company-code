# Enterprise API Gateway

A production-ready API gateway solution for microservices architecture, providing centralized authentication, authorization, rate limiting, and service discovery capabilities.

## Architecture Overview

The Enterprise API Gateway serves as the single entry point for all client requests, handling:

- **Authentication & Authorization**: JWT-based auth with role-based permissions
- **Service Discovery**: Dynamic service registration and health monitoring
- **Load Balancing**: Intelligent request routing with failover support
- **Rate Limiting**: Configurable rate limiting per endpoint and user
- **Request/Response Transformation**: Header injection and payload modification
- **Logging & Analytics**: Comprehensive request tracking and metrics collection
- **Security**: CORS, Helmet security headers, and request validation

## Features

### Core Capabilities
- JWT token management with refresh token support
- Redis-based session storage and caching
- Dynamic service registration and health checks
- Configurable rate limiting with Redis backend
- Request logging with structured JSON format
- Error handling with request correlation IDs

### Security Features
- Token blacklisting for secure logout
- Permission-based access control
- Internal service authentication
- Request validation and sanitization
- CORS configuration with origin whitelisting

### Operational Features
- Health check endpoints for all registered services
- Admin cache management
- Service status monitoring
- Graceful shutdown handling
- PM2 process management support

## Quick Start

### Prerequisites
- Node.js 16+ 
- Redis server
- Microservices deployed and accessible

### Installation

```bash
git clone https://github.com/enterprise/api-gateway.git
cd api-gateway
npm install
```

### Configuration

Create a `.env` file:

```env
PORT=3000
JWT_SECRET=your-super-secure-jwt-secret-key
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# Service URLs
USER_SERVICE_URL=http://user-service:3001
ORDER_SERVICE_URL=http://order-service:3002
PAYMENT_SERVICE_URL=http://payment-service:3003
NOTIFICATION_SERVICE_URL=http://notification-service:3004
ANALYTICS_SERVICE_URL=http://analytics-service:3005

# Internal service token
INTERNAL_SERVICE_TOKEN=your-internal-service-token

# CORS origins
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
```

### Running the Application

```bash
# Development mode
npm run dev

# Production mode
npm start

# With PM2
npm run pm2:start
```

## API Documentation

### Authentication Endpoints

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Token Refresh
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "your.refresh.token"
}
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer your.access.token
```

### Protected Endpoints

All API endpoints under `/api/` require authentication via Bearer token.

#### User Management
- `GET /api/users/profile` - Get current user profile
- `PUT /api/users/profile` - Update user profile
- `GET /api/users` - List users (admin only)

#### Order Management
- `GET /api/orders` - List orders (filtered by user role)
- `POST /api/orders` - Create new order
- `GET /api/orders/:orderId` - Get specific order

#### Analytics
- `POST /api/analytics/events` - Track user events
- `GET /api/analytics/dashboard` - Analytics dashboard (requires read:analytics)

### Admin Endpoints

#### Service Status
```http
GET /api/admin/services/status
Authorization: Bearer admin.token
```

#### Cache Management
```http
POST /api/admin/cache/clear
Authorization: Bearer admin.token
Content-Type: application/json

{
  "pattern": "user:*"
}
```

## Service Registration

Services are automatically registered on startup. To add new services:

1. Add service URL to environment variables
2. Update the service registry in `server.js`
3. Ensure the service has a `/health` endpoint

```javascript
await registerService('newService', config.services.newService, '/health');
```

## Rate Limiting

Default rate limits:
- General API endpoints: 100 requests per 15 minutes
- Authentication endpoints: 5 requests per 15 minutes

Configure custom rate limits per endpoint as needed.

## Permissions System

The gateway implements a flexible permission system:

### Roles
- `admin`: Full system access
- `manager`: Order and user read/write access
- `employee`: Order read access
- `customer`: Own order access only

### Permission Formats
- `read:users` - Read user data
- `write:orders` - Create/modify orders
- `admin:services` - Service administration
- `admin:cache` - Cache management

## Monitoring

### Health Checks
- Gateway health: `GET /health`
- Service health: Automatic monitoring every 30 seconds
- Health status available via admin endpoints

### Logging
All requests are logged with structured JSON including:
- Request ID for tracing
- User information
- Response times
- Error details

Log files:
- `logs/combined.log` - All logs
- `logs/error.log` - Error logs only

## Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

```bash
# Build and run
npm run docker:build
npm run docker:run
```

## Production Deployment

### Using PM2
```bash
npm run pm2:start
```

### Environment Variables
Ensure all production environment variables are set:
- Strong JWT secrets
- Production Redis configuration
- Correct service URLs
- Internal service tokens

### Security Considerations
- Use HTTPS in production
- Configure CORS origins appropriately
- Set secure JWT secrets
- Enable Redis authentication
- Monitor failed authentication attempts

## Testing

```bash
# Run tests
npm test

# Watch mode
npm run test:watch

# Linting
npm run lint
npm run lint:fix
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run linting and tests
5. Submit a pull request

## Support

For technical support or feature requests:
- Create an issue in the repository
- Contact the development team
- Check the documentation wiki

## License

MIT License - see LICENSE file for details. 