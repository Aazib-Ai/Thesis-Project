class AuthManager {
    constructor() {
        this.tokenKey = 'auth_token';
        this.userKey = 'auth_user';
        this.listeners = [];
    }

    login(token, username) {
        localStorage.setItem(this.tokenKey, token);
        localStorage.setItem(this.userKey, username);
        this.notifyListeners(true);
    }

    logout() {
        // Clear auth
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.userKey);
        // Clear all SecureHealth data
        this.clearAllData();
        this.notifyListeners(false);
        window.location.href = '/login';
    }

    clearAllData() {
        // Clear upload page state
        localStorage.removeItem('securehealth_last_dataset');
        localStorage.removeItem('securehealth_manual_records');
        // Clear any other app-specific keys
        Object.keys(localStorage).filter(k => k.startsWith('securehealth_')).forEach(k => {
            localStorage.removeItem(k);
        });
    }

    getToken() {
        return localStorage.getItem(this.tokenKey);
    }

    getUser() {
        return localStorage.getItem(this.userKey);
    }

    isAuthenticated() {
        return !!this.getToken();
    }

    // Attach token to fetch requests
    async fetchWithAuth(url, options = {}) {
        const token = this.getToken();
        const headers = options.headers || {};

        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        // Ensure JSON content type if body is present and not FormData
        if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        const config = {
            ...options,
            headers: headers
        };

        const response = await fetch(url, config);

        if (response.status === 401) {
            this.logout();
            throw new Error('Session expired');
        }

        return response;
    }

    subscribe(callback) {
        this.listeners.push(callback);
    }

    notifyListeners(isAuth) {
        this.listeners.forEach(cb => cb(isAuth));
    }
}

const auth = new AuthManager();
window.auth = auth;
