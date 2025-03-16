import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

// Create a base API instance
const apiClient: AxiosInstance = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000/api',
    headers: {
        'Content-Type': 'application/json',
    },
});

// Add a request interceptor for authentication
apiClient.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token && config.headers) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Add a response interceptor for error handling
apiClient.interceptors.response.use(
    (response) => response,
    (error) => {
        // Handle authentication errors
        if (error.response && error.response.status === 401) {
            localStorage.removeItem('token');
            window.location.href = '/login';
        }
        return Promise.reject(error);
    }
);

// Generic API request function
const apiRequest = async <T>(config: AxiosRequestConfig): Promise<T> => {
    try {
        const response: AxiosResponse<T> = await apiClient(config);
        return response.data;
    } catch (error) {
        console.error('API request error:', error);
        throw error;
    }
};

// API service with common CRUD operations
const apiService = {
    get: <T>(url: string, params?: any): Promise<T> => {
        return apiRequest<T>({ method: 'get', url, params });
    },

    post: <T>(url: string, data?: any): Promise<T> => {
        return apiRequest<T>({ method: 'post', url, data });
    },

    put: <T>(url: string, data?: any): Promise<T> => {
        return apiRequest<T>({ method: 'put', url, data });
    },

    delete: <T>(url: string): Promise<T> => {
        return apiRequest<T>({ method: 'delete', url });
    },
};

export default apiService;
