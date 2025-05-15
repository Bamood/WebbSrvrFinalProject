document.addEventListener("DOMContentLoaded", async () => {
    // Load the CSRF token when the page loads
        const getCsrfToken = async () => {
    try {
        const response = await fetch('http://localhost:8000/api/csrf-token', {
            method: 'GET',
            credentials: 'include',
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch CSRF token');
        }
        
        const data = await response.json();
        return data.csrfToken;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        throw error;
    }
};

const fetchWithCsrf = async (url, options = {}) => {
    try {
        const csrfToken = await getCsrfToken();
        
        const headers = options.headers || {};
        
        return fetch(url, {
            ...options,
            credentials: 'include',
            headers: {
                ...headers,
                'CSRF-Token': csrfToken
            }
        });
    } catch (error) {
        console.error('Error in fetchWithCsrf:', error);
        throw error;
    }
};
    try {
        await getCsrfToken();
    } catch (error) {
        console.error("Failed to get initial CSRF token:", error);
    }

    const decodeJWT = (token) => {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload));
    };

    const isTokenExpired = (token) => {
        const payload = decodeJWT(token);
        return payload.exp * 1000 <= Date.now();
    };
    
    async function refreshToken() {
        try {
            const response = await fetch("http://localhost:8000/api/accounts/refresh-token", {
                method: "POST",
                credentials: "include",
            });

            if (response.ok) {
                const data = await response.json();
                sessionStorage.setItem("access_token", data.access_token);
                console.log("Access token refreshed successfully.");
                return true;
            } else {
                sessionStorage.removeItem("access_token");
                alert("Session expired. Redirecting to login page...");
                window.location.href = "login.html";
                return false;
            }
        } catch (error) {
            alert("Please log in again.");
            window.location.href = "login.html";
            return false;
        }
    }
    
    function startAccessTokenRefreshTimer() {
        if (window.refreshTimer) return;

        const token = sessionStorage.getItem("access_token");
        if (!token) return;

        const decodeJWT = (token) => {
            const payload = token.split('.')[1];
            return JSON.parse(atob(payload));
        };

        const payload = decodeJWT(token);
        const refreshTime = payload.exp * 1000 - Date.now() - 60000;

        if (refreshTime > 0) {
            window.refreshTimer = setTimeout(async () => {
                if (await refreshToken()) {
                    window.refreshTimer = null;
                    startAccessTokenRefreshTimer();
                    console.log("Timer restarted.");
                }
            }, refreshTime);
        }
    }

    startAccessTokenRefreshTimer();

    document.getElementById("showInfoButton")?.addEventListener("click", async () => {
        const userInfoDiv = document.getElementById("userInfo");
        if (!userInfoDiv.classList.contains("hidden")) {
            userInfoDiv.classList.add("hidden");
            return;
        }

        const token = sessionStorage.getItem("access_token");
        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        try {
            const response = await fetch("http://localhost:8000/api/accounts/info", {
                method: "GET",
                headers: {
                    "Authorization": "Bearer " + token,
                },
            });

            if (response.ok) {
                const data = await response.json();
                document.getElementById("infoUsername").textContent = data.username;
                document.getElementById("infoEmail").textContent = data.email;
                userInfoDiv.classList.remove("hidden");
            } else {
                const errorData = await response.json();
                alert("Error: " + (errorData.error || "Unknown error"));
            }
        } catch (error) {
            console.error("Error fetching user info:", error);
            alert("An error occurred while fetching user information.");
        }
    });

    document.getElementById("changePasswordForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const currentPassword = document.getElementById("currentPassword").value.trim();
        const newPassword = document.getElementById("newPassword").value.trim();
        const token = sessionStorage.getItem("access_token");

        if (!currentPassword || !newPassword) {
            alert("Both current and new passwords are required.");
            return;
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        if (!confirm("Are you sure you want to change your password? This action cannot be undone.")) {
            return;
        }

        try {
            // Use CSRF-protected fetch
            const response = await fetchWithCsrf("http://localhost:8000/api/accounts/change-password", {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + token,
                },
                body: JSON.stringify({ currentPassword, newPassword }),
            });

            const data = await response.json();
            alert(response.ok ? "Password changed successfully! Please log in again." : "Error: " + (data.error || "Unknown error"));

            if (response.ok) {
                sessionStorage.removeItem("access_token");
                window.location.href = "login.html";
            }
        } catch (error) {
            console.error("Error changing password:", error);
            alert("An error occurred while changing your password.");
        }
    });

    document.getElementById("deleteUserButton")?.addEventListener("click", async () => {
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        if (!confirm("Are you sure you want to delete your account? This action cannot be undone.")) {
            return;
        }

        try {
            // Use CSRF-protected fetch
            const response = await fetchWithCsrf("http://localhost:8000/api/accounts/delete", {
                method: "DELETE",
                headers: {
                    "Authorization": "Bearer " + token,
                },
            });

            const data = await response.json();
            alert(response.ok ? "User deleted successfully!" : "Error: " + (data.error || "Unknown error"));

            if (response.ok) {
                sessionStorage.removeItem("access_token");
                window.location.href = "login.html";
            }
        } catch (error) {
            console.error("Error deleting user:", error);
            alert("An error occurred while deleting your account.");
        }
    });

    document.getElementById("backToDashboardButton")?.addEventListener("click", () => {
        window.location.href = "main.html";
    });
});
