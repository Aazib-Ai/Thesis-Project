class StateManager {
    constructor() {
        this.state = {};
        this.listeners = {};
    }

    setState(key, value) {
        const oldValue = this.state[key];
        this.state[key] = value;

        if (this.listeners[key]) {
            this.listeners[key].forEach(callback => callback(value, oldValue));
        }
    }

    getState(key) {
        return this.state[key];
    }

    subscribe(key, callback) {
        if (!this.listeners[key]) {
            this.listeners[key] = [];
        }
        this.listeners[key].push(callback);

        // Return unsubscribe function
        return () => {
            this.listeners[key] = this.listeners[key].filter(cb => cb !== callback);
        };
    }
}

window.store = new StateManager();
