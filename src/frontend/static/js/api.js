class ApiClient {
    async request(endpoint, options = {}) {
        // Ensure auth.js is loaded
        if (!window.auth) {
            console.error('Auth module not loaded');
            throw new Error('Internal Error');
        }

        try {
            const response = await window.auth.fetchWithAuth(endpoint, options);

            // Handle 204 No Content
            if (response.status === 204) return null;

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `Request failed with status ${response.status}`);
            }

            return data;
        } catch (error) {
            // Global error handling notification
            if (window.notify) {
                window.notify.error('API Error', error.message);
            }
            throw error;
        }
    }

    get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    post(endpoint, body) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    put(endpoint, body) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}

window.api = new ApiClient();
