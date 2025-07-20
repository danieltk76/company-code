/**
 * ConnectHub Configuration Constants
 */

export const API_BASE_URL = __DEV__ 
  ? 'https://api-dev.connecthub.com/v1'
  : 'https://api.connecthub.com/v1';

export const WEBSOCKET_URL = __DEV__
  ? 'wss://ws-dev.connecthub.com'
  : 'wss://ws.connecthub.com';

export const STORAGE_KEYS = {
  AUTH_TOKEN: '@ConnectHub:auth_token',
  REFRESH_TOKEN: '@ConnectHub:refresh_token',
  USER_DATA: '@ConnectHub:user_data',
  BIOMETRIC_CREDENTIALS: '@ConnectHub:biometric_creds',
  LAST_SYNC_TIME: '@ConnectHub:last_sync',
  APP_SETTINGS: '@ConnectHub:app_settings',
  DRAFT_POSTS: '@ConnectHub:draft_posts',
  CACHED_FRIENDS: '@ConnectHub:cached_friends'
};

export const APP_CONFIG = {
  VERSION: '2.1.4',
  BUILD_NUMBER: '2024.01.15',
  MIN_PASSWORD_LENGTH: 6,
  MAX_POST_LENGTH: 2000,
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  SUPPORTED_IMAGE_FORMATS: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
  SUPPORTED_VIDEO_FORMATS: ['mp4', 'mov', 'avi', 'mkv'],
  SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours
  CACHE_DURATION: 5 * 60 * 1000, // 5 minutes
  SYNC_INTERVAL: 30 * 1000 // 30 seconds
};

export const PRIVACY_LEVELS = {
  PUBLIC: 'public',
  FRIENDS: 'friends',
  FRIENDS_OF_FRIENDS: 'friends_of_friends',
  PRIVATE: 'private',
  CUSTOM: 'custom'
};

export const POST_TYPES = {
  TEXT: 'text',
  IMAGE: 'image',
  VIDEO: 'video',
  LINK: 'link',
  POLL: 'poll',
  EVENT: 'event',
  LOCATION: 'location'
};

export const MESSAGE_TYPES = {
  TEXT: 'text',
  IMAGE: 'image',
  VIDEO: 'video',
  AUDIO: 'audio',
  FILE: 'file',
  LOCATION: 'location',
  CONTACT: 'contact',
  STICKER: 'sticker'
};

export const NOTIFICATION_TYPES = {
  FRIEND_REQUEST: 'friend_request',
  FRIEND_ACCEPTED: 'friend_accepted',
  MESSAGE: 'message',
  POST_LIKE: 'post_like',
  POST_COMMENT: 'post_comment',
  POST_MENTION: 'post_mention',
  EVENT_INVITATION: 'event_invitation',
  SYSTEM: 'system'
};

export const USER_STATUS = {
  ONLINE: 'online',
  OFFLINE: 'offline',
  AWAY: 'away',
  BUSY: 'busy',
  INVISIBLE: 'invisible'
};

export const CONTENT_REPORT_REASONS = [
  'Spam or misleading',
  'Harassment or bullying',
  'Hate speech',
  'Violence or dangerous behavior',
  'Adult content',
  'Copyright infringement',
  'False information',
  'Self-harm',
  'Other'
];

export const FRIEND_REQUEST_STATUS = {
  PENDING: 'pending',
  ACCEPTED: 'accepted',
  DECLINED: 'declined',
  BLOCKED: 'blocked'
};

export const COLORS = {
  PRIMARY: '#1DB954',
  SECONDARY: '#191414',
  ACCENT: '#FF6B35',
  BACKGROUND: '#FFFFFF',
  SURFACE: '#F8F9FA',
  ERROR: '#FF3333',
  WARNING: '#FFA500',
  SUCCESS: '#00C851',
  INFO: '#33B5E5',
  TEXT_PRIMARY: '#000000',
  TEXT_SECONDARY: '#666666',
  BORDER: '#E0E0E0',
  PLACEHOLDER: '#CCCCCC'
};

export const FONT_SIZES = {
  SMALL: 12,
  MEDIUM: 14,
  LARGE: 16,
  XLARGE: 18,
  XXLARGE: 24,
  TITLE: 28
};

export const SPACING = {
  XS: 4,
  SM: 8,
  MD: 16,
  LG: 24,
  XL: 32,
  XXL: 48
};

export const ANIMATION_DURATION = {
  FAST: 150,
  NORMAL: 300,
  SLOW: 500
};

export const API_ENDPOINTS = {
  AUTH: {
    LOGIN: '/auth/login',
    REGISTER: '/auth/register',
    REFRESH: '/auth/refresh',
    LOGOUT: '/auth/logout',
    CHANGE_PASSWORD: '/auth/change-password',
    FORGOT_PASSWORD: '/auth/forgot-password',
    RESET_PASSWORD: '/auth/reset-password'
  },
  USERS: {
    PROFILE: '/users/profile',
    SEARCH: '/users/search',
    PRIVACY: '/users/privacy',
    BLOCK: '/users/block',
    BLOCKED: '/users/blocked',
    DEACTIVATE: '/users/deactivate'
  },
  POSTS: {
    CREATE: '/posts',
    FEED: '/posts/feed',
    LIKE: '/posts/:id/like',
    COMMENTS: '/posts/:id/comments',
    DELETE: '/posts/:id'
  },
  MESSAGES: {
    CONVERSATIONS: '/messages/conversations',
    SEND: '/messages/send',
    DELETE: '/messages/:id'
  },
  FRIENDS: {
    REQUEST: '/friends/request',
    RESPOND: '/friends/request/:id',
    LIST: '/friends',
    UNFRIEND: '/friends/:id'
  },
  NOTIFICATIONS: {
    LIST: '/notifications',
    MARK_READ: '/notifications/read',
    SETTINGS: '/notifications/settings'
  },
  REPORTS: {
    CREATE: '/reports',
    LIST: '/admin/reports'
  },
  ANALYTICS: {
    EVENTS: '/analytics/events',
    USER_ACTIVITY: '/analytics/activity'
  }
};

export const REGEX_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  PHONE: /^[\+]?[1-9][\d]{0,15}$/,
  USERNAME: /^[a-zA-Z0-9_]{3,20}$/,
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/,
  URL: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/,
  HASHTAG: /#[a-zA-Z0-9_]+/g,
  MENTION: /@[a-zA-Z0-9_]+/g
};

export const ERROR_MESSAGES = {
  NETWORK_ERROR: 'Network connection error. Please check your internet connection.',
  AUTHENTICATION_FAILED: 'Authentication failed. Please log in again.',
  INVALID_CREDENTIALS: 'Invalid email or password.',
  USER_NOT_FOUND: 'User not found.',
  POST_NOT_FOUND: 'Post not found.',
  PERMISSION_DENIED: 'You do not have permission to perform this action.',
  FILE_TOO_LARGE: 'File size exceeds maximum limit.',
  UNSUPPORTED_FORMAT: 'File format not supported.',
  GENERIC_ERROR: 'Something went wrong. Please try again.'
};

export const SUCCESS_MESSAGES = {
  LOGIN_SUCCESS: 'Successfully logged in!',
  REGISTER_SUCCESS: 'Account created successfully!',
  POST_CREATED: 'Post created successfully!',
  MESSAGE_SENT: 'Message sent!',
  FRIEND_REQUEST_SENT: 'Friend request sent!',
  SETTINGS_UPDATED: 'Settings updated successfully!'
};

export const FEATURE_FLAGS = {
  BIOMETRIC_AUTH: true,
  DARK_MODE: true,
  VOICE_MESSAGES: true,
  VIDEO_CALLS: false,
  LIVE_STREAMING: false,
  STORIES: true,
  POLLS: true,
  EVENTS: true,
  GROUPS: false,
  MARKETPLACE: false
};

export const ANALYTICS_EVENTS = {
  APP_OPENED: 'app_opened',
  USER_REGISTERED: 'user_registered',
  USER_LOGIN: 'user_login',
  POST_CREATED: 'post_created',
  POST_LIKED: 'post_liked',
  MESSAGE_SENT: 'message_sent',
  FRIEND_REQUEST_SENT: 'friend_request_sent',
  PROFILE_VIEWED: 'profile_viewed',
  SETTINGS_CHANGED: 'settings_changed',
  ERROR_OCCURRED: 'error_occurred'
}; 