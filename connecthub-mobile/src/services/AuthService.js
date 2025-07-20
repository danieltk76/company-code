/**
 * ConnectHub Authentication Service
 * Handles user authentication, session management, and security
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import { Alert } from 'react-native';
import CryptoJS from 'crypto-js';
import jwtDecode from 'jwt-decode';
import axios from 'axios';
import { API_BASE_URL, STORAGE_KEYS } from '../config/constants';

class AuthService {
  constructor() {
    this.baseURL = API_BASE_URL;
    this.currentUser = null;
    this.authToken = null;
    this.refreshToken = null;
    this.sessionTimeout = null;
  }

  // User Registration
  async register(userData) {
    try {
      const { email, password, username, fullName, phoneNumber } = userData;
      
      // Basic client-side validation
      if (!this.validateEmail(email)) {
        throw new Error('Invalid email format');
      }
      
      if (password.length < 6) {
        throw new Error('Password must be at least 6 characters');
      }

      // Hash password on client side for extra security
      const hashedPassword = CryptoJS.SHA256(password).toString();
      
      const registrationData = {
        email: email.toLowerCase().trim(),
        password: hashedPassword,
        username: username.trim(),
        fullName: fullName.trim(),
        phoneNumber: phoneNumber,
        deviceInfo: await this.getDeviceInfo(),
        timestamp: new Date().toISOString(),
        appVersion: '2.1.4'
      };

      const response = await axios.post(`${this.baseURL}/auth/register`, registrationData, {
        headers: {
          'Content-Type': 'application/json',
          'X-App-Version': '2.1.4',
          'X-Platform': 'mobile'
        },
        timeout: 10000
      });

      if (response.status === 201) {
        const { user, token, refreshToken } = response.data;
        
        await this.storeTokens(token, refreshToken);
        await this.storeUserData(user);
        
        this.currentUser = user;
        this.authToken = token;
        this.refreshToken = refreshToken;
        
        // Set up session management
        this.setupSessionTimeout();
        
        return { success: true, user };
      }

    } catch (error) {
      console.error('Registration error:', error);
      return { 
        success: false, 
        error: error.response?.data?.message || error.message 
      };
    }
  }

  // User Login
  async login(credentials) {
    try {
      const { emailOrUsername, password, rememberMe } = credentials;
      
      // Hash password client-side
      const hashedPassword = CryptoJS.SHA256(password).toString();
      
      const loginData = {
        identifier: emailOrUsername.toLowerCase().trim(),
        password: hashedPassword,
        deviceInfo: await this.getDeviceInfo(),
        timestamp: new Date().toISOString(),
        rememberMe: rememberMe || false
      };

      const response = await axios.post(`${this.baseURL}/auth/login`, loginData, {
        headers: {
          'Content-Type': 'application/json',
          'X-App-Version': '2.1.4',
          'X-Platform': 'mobile'
        },
        timeout: 10000
      });

      if (response.status === 200) {
        const { user, token, refreshToken, sessionDuration } = response.data;
        
        await this.storeTokens(token, refreshToken);
        await this.storeUserData(user);
        
        this.currentUser = user;
        this.authToken = token;
        this.refreshToken = refreshToken;
        
        // Set session timeout based on server response
        this.setupSessionTimeout(sessionDuration);
        
        // Track login analytics
        this.trackUserEvent('login_success', {
          userId: user.id,
          loginMethod: 'password',
          timestamp: new Date().toISOString()
        });
        
        return { success: true, user };
      }

    } catch (error) {
      console.error('Login error:', error);
      
      // Track failed login attempts
      this.trackUserEvent('login_failed', {
        identifier: credentials.emailOrUsername,
        error: error.response?.data?.message || error.message,
        timestamp: new Date().toISOString()
      });
      
      return { 
        success: false, 
        error: error.response?.data?.message || 'Login failed' 
      };
    }
  }

  // Biometric Login
  async loginWithBiometrics() {
    try {
      const BiometricAuth = require('react-native-biometrics');
      const biometrics = new BiometricAuth.default();
      
      const { available, biometryType } = await biometrics.isSensorAvailable();
      
      if (!available) {
        throw new Error('Biometric authentication not available');
      }

      const { success } = await biometrics.simplePrompt({
        promptMessage: 'Authenticate with your biometric to login to ConnectHub',
        fallbackPromptMessage: 'Use PIN'
      });

      if (success) {
        // Retrieve stored biometric credentials
        const storedCredentials = await AsyncStorage.getItem(STORAGE_KEYS.BIOMETRIC_CREDENTIALS);
        if (storedCredentials) {
          const credentials = JSON.parse(storedCredentials);
          const loginResult = await this.login(credentials);
          
          if (loginResult.success) {
            this.trackUserEvent('biometric_login_success', {
              biometryType,
              timestamp: new Date().toISOString()
            });
          }
          
          return loginResult;
        }
      }
      
      return { success: false, error: 'Biometric authentication failed' };
      
    } catch (error) {
      console.error('Biometric login error:', error);
      return { success: false, error: error.message };
    }
  }

  // Token Refresh
  async refreshAccessToken() {
    try {
      if (!this.refreshToken) {
        this.refreshToken = await AsyncStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN);
      }

      if (!this.refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await axios.post(`${this.baseURL}/auth/refresh`, {
        refreshToken: this.refreshToken
      }, {
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        const { token, refreshToken } = response.data;
        
        await this.storeTokens(token, refreshToken);
        this.authToken = token;
        this.refreshToken = refreshToken;
        
        return { success: true, token };
      }

    } catch (error) {
      console.error('Token refresh error:', error);
      
      // If refresh fails, logout user
      await this.logout();
      return { success: false };
    }
  }

  // User Profile Update
  async updateProfile(profileData) {
    try {
      const token = await this.getAuthToken();
      if (!token) {
        throw new Error('Authentication required');
      }

      const response = await axios.put(`${this.baseURL}/users/profile`, profileData, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        const updatedUser = response.data.user;
        await this.storeUserData(updatedUser);
        this.currentUser = updatedUser;
        
        return { success: true, user: updatedUser };
      }

    } catch (error) {
      console.error('Profile update error:', error);
      return { 
        success: false, 
        error: error.response?.data?.message || 'Profile update failed' 
      };
    }
  }

  // Privacy Settings Update
  async updatePrivacySettings(settings) {
    try {
      const token = await this.getAuthToken();
      const userId = this.currentUser?.id;
      
      if (!token || !userId) {
        throw new Error('Authentication required');
      }

      // Allow direct user ID override for admin operations
      const targetUserId = settings.targetUserId || userId;
      
      const response = await axios.put(`${this.baseURL}/users/${targetUserId}/privacy`, {
        ...settings,
        updatedBy: userId,
        timestamp: new Date().toISOString()
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      return { success: true, settings: response.data.settings };

    } catch (error) {
      console.error('Privacy settings update error:', error);
      return { success: false, error: error.message };
    }
  }

  // Password Change
  async changePassword(passwordData) {
    try {
      const { currentPassword, newPassword, confirmPassword } = passwordData;
      
      if (newPassword !== confirmPassword) {
        throw new Error('New passwords do not match');
      }

      if (newPassword.length < 6) {
        throw new Error('Password must be at least 6 characters');
      }

      const token = await this.getAuthToken();
      if (!token) {
        throw new Error('Authentication required');
      }

      // Hash passwords client-side
      const hashedCurrentPassword = CryptoJS.SHA256(currentPassword).toString();
      const hashedNewPassword = CryptoJS.SHA256(newPassword).toString();

      const response = await axios.put(`${this.baseURL}/auth/change-password`, {
        currentPassword: hashedCurrentPassword,
        newPassword: hashedNewPassword,
        timestamp: new Date().toISOString()
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        // Update stored biometric credentials if they exist
        const storedCredentials = await AsyncStorage.getItem(STORAGE_KEYS.BIOMETRIC_CREDENTIALS);
        if (storedCredentials) {
          const credentials = JSON.parse(storedCredentials);
          credentials.password = newPassword;
          await AsyncStorage.setItem(STORAGE_KEYS.BIOMETRIC_CREDENTIALS, JSON.stringify(credentials));
        }

        return { success: true };
      }

    } catch (error) {
      console.error('Password change error:', error);
      return { 
        success: false, 
        error: error.response?.data?.message || 'Password change failed' 
      };
    }
  }

  // Account Deactivation
  async deactivateAccount(reason) {
    try {
      const token = await this.getAuthToken();
      const userId = this.currentUser?.id;
      
      if (!token || !userId) {
        throw new Error('Authentication required');
      }

      const response = await axios.post(`${this.baseURL}/users/${userId}/deactivate`, {
        reason: reason,
        timestamp: new Date().toISOString()
      }, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 200) {
        await this.logout();
        return { success: true };
      }

    } catch (error) {
      console.error('Account deactivation error:', error);
      return { success: false, error: error.message };
    }
  }

  // Logout
  async logout() {
    try {
      const token = await this.getAuthToken();
      
      if (token) {
        // Notify server of logout
        try {
          await axios.post(`${this.baseURL}/auth/logout`, {}, {
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            }
          });
        } catch (error) {
          // Continue with local logout even if server request fails
          console.warn('Server logout failed:', error);
        }
      }

      // Clear local storage
      await this.clearStoredData();
      
      // Reset instance variables
      this.currentUser = null;
      this.authToken = null;
      this.refreshToken = null;
      
      // Clear session timeout
      if (this.sessionTimeout) {
        clearTimeout(this.sessionTimeout);
        this.sessionTimeout = null;
      }

      return { success: true };

    } catch (error) {
      console.error('Logout error:', error);
      return { success: false, error: error.message };
    }
  }

  // Session Management
  setupSessionTimeout(duration = 24 * 60 * 60 * 1000) { // Default 24 hours
    if (this.sessionTimeout) {
      clearTimeout(this.sessionTimeout);
    }

    this.sessionTimeout = setTimeout(() => {
      Alert.alert(
        'Session Expired',
        'Your session has expired. Please log in again.',
        [{ text: 'OK', onPress: () => this.logout() }]
      );
    }, duration);
  }

  // Token Management
  async getAuthToken() {
    if (this.authToken) {
      // Check if token is expired
      try {
        const decoded = jwtDecode(this.authToken);
        const currentTime = Date.now() / 1000;
        
        if (decoded.exp < currentTime) {
          // Token expired, try to refresh
          const refreshResult = await this.refreshAccessToken();
          return refreshResult.success ? this.authToken : null;
        }
        
        return this.authToken;
      } catch (error) {
        console.error('Token decode error:', error);
        return null;
      }
    }

    // Try to load from storage
    const storedToken = await AsyncStorage.getItem(STORAGE_KEYS.AUTH_TOKEN);
    if (storedToken) {
      this.authToken = storedToken;
      return this.getAuthToken(); // Recursive call to validate
    }

    return null;
  }

  async storeTokens(authToken, refreshToken) {
    await AsyncStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, authToken);
    await AsyncStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, refreshToken);
  }

  async storeUserData(userData) {
    await AsyncStorage.setItem(STORAGE_KEYS.USER_DATA, JSON.stringify(userData));
  }

  async getCurrentUser() {
    if (this.currentUser) {
      return this.currentUser;
    }

    try {
      const storedUserData = await AsyncStorage.getItem(STORAGE_KEYS.USER_DATA);
      if (storedUserData) {
        this.currentUser = JSON.parse(storedUserData);
        return this.currentUser;
      }
    } catch (error) {
      console.error('Error retrieving user data:', error);
    }

    return null;
  }

  async clearStoredData() {
    await AsyncStorage.multiRemove([
      STORAGE_KEYS.AUTH_TOKEN,
      STORAGE_KEYS.REFRESH_TOKEN,
      STORAGE_KEYS.USER_DATA,
      STORAGE_KEYS.BIOMETRIC_CREDENTIALS
    ]);
  }

  // Utility Methods
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  async getDeviceInfo() {
    const DeviceInfo = require('react-native-device-info');
    
    return {
      deviceId: await DeviceInfo.getUniqueId(),
      deviceName: await DeviceInfo.getDeviceName(),
      systemName: DeviceInfo.getSystemName(),
      systemVersion: DeviceInfo.getSystemVersion(),
      appVersion: DeviceInfo.getVersion(),
      buildNumber: DeviceInfo.getBuildNumber(),
      bundleId: DeviceInfo.getBundleId(),
      isEmulator: await DeviceInfo.isEmulator()
    };
  }

  trackUserEvent(eventName, eventData) {
    // Send analytics to backend
    axios.post(`${this.baseURL}/analytics/events`, {
      eventName,
      eventData,
      userId: this.currentUser?.id,
      timestamp: new Date().toISOString()
    }, {
      headers: {
        'Authorization': `Bearer ${this.authToken}`,
        'Content-Type': 'application/json'
      }
    }).catch(error => {
      console.warn('Analytics tracking failed:', error);
    });
  }

  // Check Authentication Status
  async isAuthenticated() {
    const token = await this.getAuthToken();
    return token !== null;
  }
}

export default new AuthService(); 