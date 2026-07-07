import axios from "axios";

const baseURL = import.meta.env.VITE_API_URL;
const api = axios.create({ baseURL });

// Attach the access token to every request.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

function logoutAndRedirect() {
  localStorage.clear();
  if (window.location.pathname !== "/login") {
    window.location.href = "/login";
  }
}

// On a 401, try to refresh the access token once, then replay the request.
// If refresh fails (or there is no refresh token), log the user out cleanly
// instead of hammering the API with a token the server keeps rejecting.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    const status = error.response?.status;

    if (status !== 401 || original?._retry) {
      return Promise.reject(error);
    }
    // Don't try to refresh the refresh call itself.
    if (original?.url?.includes("/auth/refresh")) {
      logoutAndRedirect();
      return Promise.reject(error);
    }

    const refreshToken = localStorage.getItem("refresh_token");
    if (!refreshToken) {
      logoutAndRedirect();
      return Promise.reject(error);
    }

    original._retry = true;
    try {
      // Bare axios (no interceptors) so a failing refresh can't recurse.
      const res = await axios.post(`${baseURL}/auth/refresh`, {
        refresh_token: refreshToken,
      });
      localStorage.setItem("access_token", res.data.access_token);
      localStorage.setItem("refresh_token", res.data.refresh_token);
      original.headers.Authorization = `Bearer ${res.data.access_token}`;
      return api(original);
    } catch (refreshErr) {
      logoutAndRedirect();
      return Promise.reject(refreshErr);
    }
  }
);

export default api;
