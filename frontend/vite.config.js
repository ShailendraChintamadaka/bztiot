import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
    plugins: [react()],
    server: {
        host: "0.0.0.0",
        port: 5173,
        proxy: {
            "/api": {
                target: "http://127.0.0.1:8080",
                changeOrigin: true
            },
            "/perform_login": {
                target: "http://127.0.0.1:8080",
                changeOrigin: true
            },
            "/perform_logout": {
                target: "http://127.0.0.1:8080",
                changeOrigin: true
            }
        }
    }
});
