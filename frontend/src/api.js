// Central backend URL — all API calls go through the Vite dev proxy.
// The proxy forwards /api, /perform_login, /perform_logout to Spring Boot on :8080.
// Using an empty string means fetch('/api/...') uses the proxy automatically,
// avoiding CORS issues in development and production builds.
export const API = '';
