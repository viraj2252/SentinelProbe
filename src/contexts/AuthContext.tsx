import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import apiService from '../services/api';

// Define the User type
interface User {
  id: string;
  username: string;
  email: string;
  role: string;
}

// Define the AuthContextType
interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  error: string | null;
}

// Create the AuthContext
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Define the AuthProvider props
interface AuthProviderProps {
  children: ReactNode;
}

// Create the AuthProvider component
export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Check if the user is already authenticated on component mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          // Fetch the current user data
          const userData = await apiService.get<User>('/auth/me');
          setUser(userData);
        } catch (error) {
          // If there's an error, clear the token
          localStorage.removeItem('token');
          setError('Session expired. Please login again.');
        }
      }
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  // Login function
  const login = async (email: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      // Call the login API
      const response = await apiService.post<{ token: string; user: User }>('/auth/login', {
        email,
        password,
      });

      // Save the token to localStorage
      localStorage.setItem('token', response.token);

      // Set the user data
      setUser(response.user);
    } catch (error: any) {
      setError(error.response?.data?.message || 'Login failed. Please try again.');
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  // Logout function
  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  // Create the auth context value
  const value = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    error,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Create a hook to use the auth context
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
