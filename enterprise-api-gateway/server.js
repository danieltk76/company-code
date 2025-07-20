/**
 * Enterprise API Gateway
 * Centralized API gateway for microservices architecture
 * Handles authentication, routing, rate limiting, and service discovery
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const axios = require('axios');
const crypto = require('crypto');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const uuid = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const config = {
    jwt: {
        secret: process.env.JWT_SECRET || 'enterprise-gateway-secret-key-2024',
        expiresIn: '24h',
        refreshExpiresIn: '7d'
    },
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD || null
    },
    services: {
        userService: process.env.USER_SERVICE_URL || 'http://user-service:3001',
        orderService: process.env.ORDER_SERVICE_URL || 'http://order-service:3002',
        paymentService: process.env.PAYMENT_SERVICE_URL || 'http://payment-service:3003',
        notificationService: process.env.NOTIFICATION_SERVICE_URL || 'http://notification-service:3004',
        analyticsService: process.env.ANALYTICS_SERVICE_URL || 'http://analytics-service:3005'
    },
    rateLimiting: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        skipSuccessfulRequests: false,
        skipFailedRequests: false
    }
};

// Redis client setup
const redisClient = redis.createClient({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    retry_unfulfilled_commands: true,
    retry_strategy: (options) => {
        if (options.error && options.error.code === 'ECONNREFUSED') {
            return new Error('Redis server refused connection');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error('Retry time exhausted');
        }
        if (options.attempt > 10) {
            return undefined;
        }
        return Math.min(options.attempt * 100, 3000);
    }
});

redisClient.on('connect', () => console.log('Redis connected'));
redisClient.on('error', (err) => console.error('Redis error:', err));

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console()
    ]
});

// Middleware setup
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request tracking middleware
app.use((req, res, next) => {
    req.requestId = uuid.v4();
    req.startTime = Date.now();
    
    logger.info({
        requestId: req.requestId,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent')
    });
    
    next();
});

// Service discovery and health check
const serviceRegistry = new Map();
const serviceHealthStatus = new Map();

async function registerService(serviceName, url, healthEndpoint) {
    serviceRegistry.set(serviceName, {
        url: url,
        healthEndpoint: healthEndpoint,
        lastHealthCheck: null,
        isHealthy: false
    });
    
    // Perform initial health check
    await checkServiceHealth(serviceName);
}

async function checkServiceHealth(serviceName) {
    const service = serviceRegistry.get(serviceName);
    if (!service) return false;
    
    try {
        const response = await axios.get(`${service.url}${service.healthEndpoint}`, { timeout: 5000 });
        service.isHealthy = response.status === 200;
        service.lastHealthCheck = new Date();
        serviceHealthStatus.set(serviceName, service.isHealthy);
        
        logger.info(`Service ${serviceName} health check: ${service.isHealthy ? 'HEALTHY' : 'UNHEALTHY'}`);
        return service.isHealthy;
    } catch (error) {
        service.isHealthy = false;
        service.lastHealthCheck = new Date();
        serviceHealthStatus.set(serviceName, false);
        logger.error(`Service ${serviceName} health check failed:`, error.message);
        return false;
    }
}

// Initialize service registry
(async () => {
    await registerService('userService', config.services.userService, '/health');
    await registerService('orderService', config.services.orderService, '/health');
    await registerService('paymentService', config.services.paymentService, '/health');
    await registerService('notificationService', config.services.notificationService, '/health');
    await registerService('analyticsService', config.services.analyticsService, '/health');
})();

// Periodic health checks
setInterval(async () => {
    for (const serviceName of serviceRegistry.keys()) {
        await checkServiceHealth(serviceName);
    }
}, 30000); // Every 30 seconds

// Authentication utilities
function generateTokens(user) {
    const accessToken = jwt.sign(
        { 
            userId: user.id, 
            email: user.email, 
            role: user.role,
            permissions: user.permissions || [],
            iat: Math.floor(Date.now() / 1000)
        },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn }
    );
    
    const refreshToken = jwt.sign(
        { 
            userId: user.id, 
            type: 'refresh',
            iat: Math.floor(Date.now() / 1000)
        },
        config.jwt.secret,
        { expiresIn: config.jwt.refreshExpiresIn }
    );
    
    return { accessToken, refreshToken };
}

// Authentication middleware
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    try {
        // Check if token is blacklisted
        const isBlacklisted = await redisClient.get(`blacklist:${token}`);
        if (isBlacklisted) {
            return res.status(401).json({ error: 'Token has been revoked' });
        }
        
        const decoded = jwt.verify(token, config.jwt.secret);
        
        // Additional validation for token freshness
        const now = Math.floor(Date.now() / 1000);
        if (decoded.iat && (now - decoded.iat) > 86400) { // Token older than 24 hours
            logger.warn(`Old token used by user ${decoded.userId}`);
        }
        
        req.user = decoded;
        next();
    } catch (error) {
        logger.error('Authentication error:', error);
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
}

// Authorization middleware
function requirePermission(permission) {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const userPermissions = req.user.permissions || [];
        const userRole = req.user.role;
        
        // Admin users have all permissions
        if (userRole === 'admin') {
            return next();
        }
        
        // Check specific permission
        if (userPermissions.includes(permission)) {
            return next();
        }
        
        // Check role-based permissions
        const rolePermissions = {
            'manager': ['read:orders', 'write:orders', 'read:users'],
            'employee': ['read:orders'],
            'customer': ['read:own-orders', 'write:own-orders']
        };
        
        if (rolePermissions[userRole] && rolePermissions[userRole].includes(permission)) {
            return next();
        }
        
        logger.warn(`Access denied for user ${req.user.userId} to permission ${permission}`);
        return res.status(403).json({ error: 'Insufficient permissions' });
    };
}

// Rate limiting setup
const limiter = rateLimit(config.rateLimiting);
app.use('/api/', limiter);

// Special rate limiting for sensitive endpoints
const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: false,
    message: { error: 'Too many requests, please try again later' }
});

// Service proxy utility
async function proxyToService(serviceName, path, method, data, headers, query) {
    const service = serviceRegistry.get(serviceName);
    if (!service) {
        throw new Error(`Service ${serviceName} not registered`);
    }
    
    if (!service.isHealthy) {
        throw new Error(`Service ${serviceName} is currently unavailable`);
    }
    
    const serviceHeaders = {
        ...headers,
        'X-Gateway-Request-ID': headers['x-request-id'] || uuid.v4(),
        'X-Forwarded-By': 'api-gateway',
        'Content-Type': 'application/json'
    };
    
    // Remove authorization header for internal service calls in some cases
    if (path.includes('/internal/')) {
        delete serviceHeaders.authorization;
        // Add internal service authentication
        serviceHeaders['X-Internal-Service-Token'] = process.env.INTERNAL_SERVICE_TOKEN || 'internal-token-123';
    }
    
    const config = {
        method: method,
        url: `${service.url}${path}`,
        headers: serviceHeaders,
        timeout: 10000
    };
    
    if (query) {
        config.params = query;
    }
    
    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        config.data = data;
    }
    
    try {
        const response = await axios(config);
        return response;
    } catch (error) {
        logger.error(`Proxy error to ${serviceName}:`, error.message);
        throw error;
    }
}

// Authentication endpoints
app.post('/auth/login', strictLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        // Forward login request to user service
        const loginResponse = await proxyToService('userService', '/api/auth/login', 'POST', 
            { email, password }, req.headers, req.query);
        
        if (loginResponse.status === 200) {
            const user = loginResponse.data.user;
            const tokens = generateTokens(user);
            
            // Store refresh token in Redis with expiry
            await redisClient.setex(`refresh:${user.id}`, 604800, tokens.refreshToken); // 7 days
            
            // Track login event
            logger.info(`User ${user.id} logged in successfully`);
            
            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role
                },
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken
            });
        } else {
            res.status(loginResponse.status).json(loginResponse.data);
        }
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: 'Authentication service unavailable' });
    }
});

app.post('/auth/refresh', async (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token required' });
        }
        
        const decoded = jwt.verify(refreshToken, config.jwt.secret);
        
        if (decoded.type !== 'refresh') {
            return res.status(400).json({ error: 'Invalid token type' });
        }
        
        // Check if refresh token exists in Redis
        const storedToken = await redisClient.get(`refresh:${decoded.userId}`);
        if (!storedToken || storedToken !== refreshToken) {
            return res.status(401).json({ error: 'Invalid refresh token' });
        }
        
        // Get user details for new token
        const userResponse = await proxyToService('userService', `/api/users/${decoded.userId}`, 'GET', 
            null, { 'X-Internal-Service-Token': process.env.INTERNAL_SERVICE_TOKEN }, null);
        
        if (userResponse.status === 200) {
            const user = userResponse.data;
            const tokens = generateTokens(user);
            
            // Update refresh token in Redis
            await redisClient.setex(`refresh:${user.id}`, 604800, tokens.refreshToken);
            
            res.json({
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken
            });
        } else {
            res.status(401).json({ error: 'User not found' });
        }
    } catch (error) {
        logger.error('Token refresh error:', error);
        res.status(401).json({ error: 'Invalid refresh token' });
    }
});

app.post('/auth/logout', authenticateToken, async (req, res) => {
    try {
        const token = req.headers['authorization'].split(' ')[1];
        
        // Blacklist the current access token
        const decoded = jwt.decode(token);
        const expiryTime = decoded.exp - Math.floor(Date.now() / 1000);
        if (expiryTime > 0) {
            await redisClient.setex(`blacklist:${token}`, expiryTime, 'true');
        }
        
        // Remove refresh token
        await redisClient.del(`refresh:${req.user.userId}`);
        
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        logger.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// User management routes
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const response = await proxyToService('userService', `/api/users/${req.user.userId}`, 'GET',
            null, req.headers, req.query);
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'User service unavailable' });
    }
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const response = await proxyToService('userService', `/api/users/${req.user.userId}`, 'PUT',
            req.body, req.headers, req.query);
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'User service unavailable' });
    }
});

app.get('/api/users', authenticateToken, requirePermission('read:users'), async (req, res) => {
    try {
        const response = await proxyToService('userService', '/api/users', 'GET',
            null, req.headers, req.query);
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'User service unavailable' });
    }
});

// Order management routes
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        // Add user context to the request
        const modifiedQuery = { ...req.query };
        
        // Non-admin users can only see their own orders
        if (req.user.role !== 'admin') {
            modifiedQuery.userId = req.user.userId;
        }
        
        const response = await proxyToService('orderService', '/api/orders', 'GET',
            null, req.headers, modifiedQuery);
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Order service unavailable' });
    }
});

app.post('/api/orders', authenticateToken, requirePermission('write:orders'), async (req, res) => {
    try {
        // Add user context to the order
        const orderData = {
            ...req.body,
            userId: req.user.userId,
            createdBy: req.user.userId
        };
        
        const response = await proxyToService('orderService', '/api/orders', 'POST',
            orderData, req.headers, req.query);
        
        // If order creation successful, trigger notification
        if (response.status === 201) {
            try {
                await proxyToService('notificationService', '/api/notifications/order-created', 'POST',
                    { orderId: response.data.id, userId: req.user.userId }, req.headers, null);
            } catch (notifError) {
                logger.warn('Failed to send order notification:', notifError.message);
            }
        }
        
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Order service unavailable' });
    }
});

app.get('/api/orders/:orderId', authenticateToken, async (req, res) => {
    try {
        const { orderId } = req.params;
        
        const response = await proxyToService('orderService', `/api/orders/${orderId}`, 'GET',
            null, req.headers, req.query);
        
        // Authorization check - users can only access their own orders
        if (response.status === 200 && req.user.role !== 'admin') {
            const order = response.data;
            if (order.userId !== req.user.userId) {
                return res.status(403).json({ error: 'Access denied' });
            }
        }
        
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Order service unavailable' });
    }
});

// Payment routes
app.post('/api/payments/process', authenticateToken, requirePermission('write:payments'), async (req, res) => {
    try {
        const paymentData = {
            ...req.body,
            userId: req.user.userId,
            requestId: req.requestId
        };
        
        const response = await proxyToService('paymentService', '/api/payments/process', 'POST',
            paymentData, req.headers, req.query);
        
        // Log payment attempts
        logger.info({
            action: 'payment_processed',
            userId: req.user.userId,
            amount: paymentData.amount,
            status: response.status,
            requestId: req.requestId
        });
        
        res.status(response.status).json(response.data);
    } catch (error) {
        logger.error('Payment processing error:', error);
        res.status(500).json({ error: 'Payment service unavailable' });
    }
});

// Analytics routes
app.post('/api/analytics/events', authenticateToken, async (req, res) => {
    try {
        const eventData = {
            ...req.body,
            userId: req.user.userId,
            timestamp: new Date().toISOString(),
            userAgent: req.get('User-Agent'),
            ip: req.ip
        };
        
        const response = await proxyToService('analyticsService', '/api/events', 'POST',
            eventData, req.headers, req.query);
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Analytics service unavailable' });
    }
});

app.get('/api/analytics/dashboard', authenticateToken, requirePermission('read:analytics'), async (req, res) => {
    try {
        const response = await proxyToService('analyticsService', '/api/dashboard', 'GET',
            null, req.headers, req.query);
        res.status(response.status).json(response.data);
    } catch (error) {
        res.status(500).json({ error: 'Analytics service unavailable' });
    }
});

// Admin routes
app.get('/api/admin/services/status', authenticateToken, requirePermission('admin:services'), (req, res) => {
    const servicesStatus = {};
    
    for (const [serviceName, service] of serviceRegistry.entries()) {
        servicesStatus[serviceName] = {
            url: service.url,
            isHealthy: service.isHealthy,
            lastHealthCheck: service.lastHealthCheck
        };
    }
    
    res.json(servicesStatus);
});

app.post('/api/admin/cache/clear', authenticateToken, requirePermission('admin:cache'), async (req, res) => {
    try {
        const pattern = req.body.pattern || '*';
        const keys = await redisClient.keys(pattern);
        
        if (keys.length > 0) {
            await redisClient.del(...keys);
        }
        
        res.json({ message: `Cleared ${keys.length} cache entries` });
    } catch (error) {
        logger.error('Cache clear error:', error);
        res.status(500).json({ error: 'Cache clear failed' });
    }
});

// Internal service communication endpoint
app.post('/internal/auth/validate', async (req, res) => {
    const internalToken = req.headers['x-internal-service-token'];
    
    if (internalToken !== process.env.INTERNAL_SERVICE_TOKEN) {
        return res.status(401).json({ error: 'Invalid internal service token' });
    }
    
    const { token } = req.body;
    
    try {
        const decoded = jwt.verify(token, config.jwt.secret);
        
        // Check blacklist
        const isBlacklisted = await redisClient.get(`blacklist:${token}`);
        if (isBlacklisted) {
            return res.status(401).json({ error: 'Token revoked' });
        }
        
        res.json({
            valid: true,
            user: decoded
        });
    } catch (error) {
        res.json({ valid: false, error: error.message });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {}
    };
    
    for (const [serviceName, service] of serviceRegistry.entries()) {
        health.services[serviceName] = service.isHealthy ? 'healthy' : 'unhealthy';
    }
    
    const overallHealthy = Object.values(health.services).every(status => status === 'healthy');
    health.status = overallHealthy ? 'healthy' : 'degraded';
    
    res.json(health);
});

// Error handling middleware
app.use((error, req, res, next) => {
    logger.error({
        requestId: req.requestId,
        error: error.message,
        stack: error.stack
    });
    
    res.status(error.status || 500).json({
        error: 'Internal server error',
        requestId: req.requestId
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    
    try {
        await redisClient.quit();
        console.log('Redis connection closed');
    } catch (error) {
        console.error('Error closing Redis connection:', error);
    }
    
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`API Gateway running on port ${PORT}`);
    logger.info(`API Gateway started on port ${PORT}`);
});

module.exports = app; 