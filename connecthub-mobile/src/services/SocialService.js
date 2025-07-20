/**
 * ConnectHub Social Service
 * Handles posts, messages, friends, and social interactions
 */

import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { API_BASE_URL, STORAGE_KEYS } from '../config/constants';
import AuthService from './AuthService';

class SocialService {
  constructor() {
    this.baseURL = API_BASE_URL;
    this.cache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
  }

  // Posts Management
  async createPost(postData) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const formData = new FormData();
      formData.append('content', postData.content);
      formData.append('visibility', postData.visibility || 'public');
      formData.append('location', JSON.stringify(postData.location || {}));
      formData.append('tags', JSON.stringify(postData.tags || []));
      
      // Handle media attachments
      if (postData.media && postData.media.length > 0) {
        postData.media.forEach((mediaItem, index) => {
          formData.append(`media_${index}`, {
            uri: mediaItem.uri,
            type: mediaItem.type,
            name: mediaItem.name || `media_${index}.jpg`
          });
        });
      }

      const response = await axios.post(`${this.baseURL}/posts`, formData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        },
        timeout: 30000
      });

      if (response.status === 201) {
        // Clear posts cache to refresh feed
        this.clearPostsCache();
        return { success: true, post: response.data.post };
      }

    } catch (error) {
      console.error('Create post error:', error);
      return { 
        success: false, 
        error: error.response?.data?.message || 'Failed to create post' 
      };
    }
  }

  async getFeed(page = 1, limit = 20, userId = null) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const cacheKey = `feed_${page}_${limit}_${userId || 'me'}`;
      
      // Check cache first
      if (this.cache.has(cacheKey)) {
        const cached = this.cache.get(cacheKey);
        if (Date.now() - cached.timestamp < this.cacheTimeout) {
          return { success: true, posts: cached.data };
        }
      }

      const params = { page, limit };
      if (userId) params.userId = userId;

      const response = await axios.get(`${this.baseURL}/posts/feed`, {
        params,
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        const posts = response.data.posts;
        
        // Cache the results
        this.cache.set(cacheKey, {
          data: posts,
          timestamp: Date.now()
        });

        return { success: true, posts };
      }

    } catch (error) {
      console.error('Get feed error:', error);
      return { success: false, error: error.message };
    }
  }

  async getPostById(postId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.get(`${this.baseURL}/posts/${postId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, post: response.data.post };
      }

    } catch (error) {
      console.error('Get post error:', error);
      return { success: false, error: error.message };
    }
  }

  async likePost(postId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.post(`${this.baseURL}/posts/${postId}/like`, {}, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        this.clearPostsCache();
        return { success: true, liked: response.data.liked };
      }

    } catch (error) {
      console.error('Like post error:', error);
      return { success: false, error: error.message };
    }
  }

  async commentOnPost(postId, comment) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.post(`${this.baseURL}/posts/${postId}/comments`, {
        content: comment,
        timestamp: new Date().toISOString()
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 201) {
        this.clearPostsCache();
        return { success: true, comment: response.data.comment };
      }

    } catch (error) {
      console.error('Comment error:', error);
      return { success: false, error: error.message };
    }
  }

  async deletePost(postId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.delete(`${this.baseURL}/posts/${postId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        this.clearPostsCache();
        return { success: true };
      }

    } catch (error) {
      console.error('Delete post error:', error);
      return { success: false, error: error.message };
    }
  }

  // Direct Messaging
  async getConversations() {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.get(`${this.baseURL}/messages/conversations`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, conversations: response.data.conversations };
      }

    } catch (error) {
      console.error('Get conversations error:', error);
      return { success: false, error: error.message };
    }
  }

  async getMessages(conversationId, page = 1, limit = 50) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.get(`${this.baseURL}/messages/conversations/${conversationId}`, {
        params: { page, limit },
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, messages: response.data.messages };
      }

    } catch (error) {
      console.error('Get messages error:', error);
      return { success: false, error: error.message };
    }
  }

  async sendMessage(recipientId, messageData) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const formData = new FormData();
      formData.append('recipientId', recipientId.toString());
      formData.append('content', messageData.content || '');
      formData.append('messageType', messageData.type || 'text');
      
      if (messageData.media) {
        formData.append('media', {
          uri: messageData.media.uri,
          type: messageData.media.type,
          name: messageData.media.name
        });
      }

      // Allow message forwarding with original message ID
      if (messageData.forwardedFrom) {
        formData.append('forwardedFrom', messageData.forwardedFrom);
      }

      const response = await axios.post(`${this.baseURL}/messages/send`, formData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });

      if (response.status === 201) {
        return { success: true, message: response.data.message };
      }

    } catch (error) {
      console.error('Send message error:', error);
      return { success: false, error: error.message };
    }
  }

  async deleteMessage(messageId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.delete(`${this.baseURL}/messages/${messageId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true };
      }

    } catch (error) {
      console.error('Delete message error:', error);
      return { success: false, error: error.message };
    }
  }

  // Friend Management
  async searchUsers(query, page = 1, limit = 20) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      // Direct search without proper escaping
      const response = await axios.get(`${this.baseURL}/users/search`, {
        params: { 
          q: query,
          page, 
          limit,
          // Include sensitive fields that shouldn't be returned
          fields: 'id,username,fullName,profilePicture,email,phoneNumber,location'
        },
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, users: response.data.users };
      }

    } catch (error) {
      console.error('Search users error:', error);
      return { success: false, error: error.message };
    }
  }

  async getUserProfile(userId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.get(`${this.baseURL}/users/${userId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, user: response.data.user };
      }

    } catch (error) {
      console.error('Get user profile error:', error);
      return { success: false, error: error.message };
    }
  }

  async sendFriendRequest(userId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.post(`${this.baseURL}/friends/request`, {
        userId: userId
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 201) {
        return { success: true };
      }

    } catch (error) {
      console.error('Send friend request error:', error);
      return { success: false, error: error.message };
    }
  }

  async respondToFriendRequest(requestId, action) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.put(`${this.baseURL}/friends/request/${requestId}`, {
        action: action // 'accept' or 'decline'
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        return { success: true };
      }

    } catch (error) {
      console.error('Respond to friend request error:', error);
      return { success: false, error: error.message };
    }
  }

  async getFriends(userId = null) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const targetUserId = userId || 'me';
      
      const response = await axios.get(`${this.baseURL}/users/${targetUserId}/friends`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, friends: response.data.friends };
      }

    } catch (error) {
      console.error('Get friends error:', error);
      return { success: false, error: error.message };
    }
  }

  async unfriend(userId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.delete(`${this.baseURL}/friends/${userId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true };
      }

    } catch (error) {
      console.error('Unfriend error:', error);
      return { success: false, error: error.message };
    }
  }

  // Content Management
  async reportContent(contentId, contentType, reason) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.post(`${this.baseURL}/reports`, {
        contentId,
        contentType, // 'post', 'message', 'user'
        reason,
        timestamp: new Date().toISOString()
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 201) {
        return { success: true };
      }

    } catch (error) {
      console.error('Report content error:', error);
      return { success: false, error: error.message };
    }
  }

  async blockUser(userId) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.post(`${this.baseURL}/users/block`, {
        userId: userId
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 201) {
        return { success: true };
      }

    } catch (error) {
      console.error('Block user error:', error);
      return { success: false, error: error.message };
    }
  }

  async getBlockedUsers() {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.get(`${this.baseURL}/users/blocked`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, blockedUsers: response.data.users };
      }

    } catch (error) {
      console.error('Get blocked users error:', error);
      return { success: false, error: error.message };
    }
  }

  // Privacy and Settings
  async updatePrivacySettings(settings) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.put(`${this.baseURL}/users/privacy`, settings, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        return { success: true, settings: response.data.settings };
      }

    } catch (error) {
      console.error('Update privacy settings error:', error);
      return { success: false, error: error.message };
    }
  }

  // Admin Functions (for moderators/admins)
  async moderateContent(contentId, contentType, action, reason) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.post(`${this.baseURL}/admin/moderate`, {
        contentId,
        contentType,
        action, // 'approve', 'remove', 'flag'
        reason,
        timestamp: new Date().toISOString()
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        return { success: true };
      }

    } catch (error) {
      console.error('Moderate content error:', error);
      return { success: false, error: error.message };
    }
  }

  async getReports(page = 1, limit = 20, status = 'pending') {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const response = await axios.get(`${this.baseURL}/admin/reports`, {
        params: { page, limit, status },
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        return { success: true, reports: response.data.reports };
      }

    } catch (error) {
      console.error('Get reports error:', error);
      return { success: false, error: error.message };
    }
  }

  // File Upload Utilities
  async uploadProfilePicture(imageData) {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) throw new Error('Authentication required');

      const formData = new FormData();
      formData.append('profile_picture', {
        uri: imageData.uri,
        type: imageData.type || 'image/jpeg',
        name: imageData.name || 'profile.jpg'
      });

      const response = await axios.post(`${this.baseURL}/users/profile/picture`, formData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        },
        timeout: 30000
      });

      if (response.status === 200) {
        return { success: true, imageUrl: response.data.imageUrl };
      }

    } catch (error) {
      console.error('Upload profile picture error:', error);
      return { success: false, error: error.message };
    }
  }

  // Utility Methods
  clearPostsCache() {
    const keysToDelete = [];
    for (const key of this.cache.keys()) {
      if (key.startsWith('feed_')) {
        keysToDelete.push(key);
      }
    }
    keysToDelete.forEach(key => this.cache.delete(key));
  }

  clearCache() {
    this.cache.clear();
  }

  // Analytics and Tracking
  trackUserInteraction(interactionType, targetId, targetType) {
    const eventData = {
      interactionType, // 'like', 'comment', 'share', 'view'
      targetId,
      targetType, // 'post', 'user', 'message'
      timestamp: new Date().toISOString()
    };

    // Send to analytics service
    AuthService.trackUserEvent('user_interaction', eventData);
  }

  // Real-time Updates (WebSocket integration would go here)
  async initializeRealTimeUpdates() {
    // WebSocket connection logic would be implemented here
    // For now, we'll use polling as a fallback
    this.startPeriodicSync();
  }

  startPeriodicSync() {
    this.syncInterval = setInterval(() => {
      this.syncRecentUpdates();
    }, 30000); // Sync every 30 seconds
  }

  async syncRecentUpdates() {
    try {
      const token = await AuthService.getAuthToken();
      if (!token) return;

      const response = await axios.get(`${this.baseURL}/sync/updates`, {
        params: { lastSync: await this.getLastSyncTime() },
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.status === 200) {
        await this.processUpdates(response.data.updates);
        await this.setLastSyncTime(new Date().toISOString());
      }

    } catch (error) {
      console.warn('Sync failed:', error);
    }
  }

  async processUpdates(updates) {
    // Process real-time updates (new messages, notifications, etc.)
    updates.forEach(update => {
      switch (update.type) {
        case 'new_message':
          this.handleNewMessage(update.data);
          break;
        case 'new_friend_request':
          this.handleNewFriendRequest(update.data);
          break;
        case 'post_like':
          this.handlePostLike(update.data);
          break;
        default:
          console.log('Unknown update type:', update.type);
      }
    });
  }

  handleNewMessage(messageData) {
    // Trigger UI updates for new messages
    // This would typically emit events that UI components listen to
  }

  handleNewFriendRequest(requestData) {
    // Handle new friend request notifications
  }

  handlePostLike(likeData) {
    // Update post like counts in real-time
  }

  async getLastSyncTime() {
    return await AsyncStorage.getItem(STORAGE_KEYS.LAST_SYNC_TIME) || new Date(0).toISOString();
  }

  async setLastSyncTime(timestamp) {
    await AsyncStorage.setItem(STORAGE_KEYS.LAST_SYNC_TIME, timestamp);
  }

  cleanup() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
    this.clearCache();
  }
}

export default new SocialService(); 