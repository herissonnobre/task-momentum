import axios from "axios";

const getToken = () => localStorage.getItem("token");

const api = axios.create({
    baseURL: "http://localhost:5000",
    timeout: 10000,
    headers: {
        "Content-Type": "application/json",
    },
});

api.interceptors.request.use(
    (config) => {
        const token = getToken();
        if (token) {
            config.headers.Authorization = token;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            console.log("Invalid token or expired.");
        }
        return Promise.reject(error);
    }
);

export default api;
