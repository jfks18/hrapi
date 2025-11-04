// Custom fetch utility for Node.js backend
const fetch = require('node-fetch');

class CustomFetch {
  constructor(baseURL = 'http://localhost:5000') {
    this.baseURL = baseURL;
  }

  // Default headers for all requests
  getHeaders(customHeaders = {}) {
    return {
      'Content-Type': 'application/json',
      ...customHeaders
    };
  }

  // Generic request method
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: this.getHeaders(options.headers),
      ...options
    };

    try {
      const response = await fetch(url, config);
      
      // Handle different response types
      const contentType = response.headers.get('content-type');
      let data;
      
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      if (!response.ok) {
        throw new Error(data.message || data.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      return data;
    } catch (error) {
      console.error(`API Error (${endpoint}):`, error);
      throw error;
    }
  }

  // GET request
  async get(endpoint, headers = {}) {
    return this.request(endpoint, {
      method: 'GET',
      headers
    });
  }

  // POST request
  async post(endpoint, data = null, headers = {}) {
    return this.request(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : null,
      headers
    });
  }

  // PUT request
  async put(endpoint, data = null, headers = {}) {
    return this.request(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : null,
      headers
    });
  }

  // DELETE request
  async delete(endpoint, headers = {}) {
    return this.request(endpoint, {
      method: 'DELETE',
      headers
    });
  }

  // PATCH request
  async patch(endpoint, data = null, headers = {}) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : null,
      headers
    });
  }
}

// Create singleton instance
const customFetch = new CustomFetch();

// Export both the class and instance
module.exports = customFetch;
module.exports.CustomFetch = CustomFetch;