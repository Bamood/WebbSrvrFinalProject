document.addEventListener("DOMContentLoaded", async () => {
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

    document.getElementById("loginForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = document.getElementById("loginUsername").value;
        const password = document.getElementById("loginPassword").value;

        try {
         
            const response = await fetchWithCsrf("http://localhost:8000/api/accounts/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error("Login failed:", errorText);
                alert("Login failed. Please check your credentials or try again later.");
                return;
            }

            const data = await response.json();
            sessionStorage.setItem("access_token", data.access_token);
            window.location.href = "main.html";
        } catch (error) {
            console.error("Error during login:", error);
            alert("An error occurred during login. Please try again later.");
        }
    });

    if (window.location.pathname.endsWith("login.html")) {
        const accessToken = sessionStorage.getItem("access_token");
        if (accessToken) {
            try {
                const payload = JSON.parse(atob(accessToken.split('.')[1]));
                if (payload.exp * 1000 > Date.now()) {
                    window.location.href = "main.html";
                } else {
                    sessionStorage.removeItem("access_token");
                }
            } catch (error) {
                console.error("Failed to decode token:", error);
                sessionStorage.removeItem("access_token");
            }
        }

        const autoLogin = async () => {
            try {
                const response = await fetch("http://localhost:8000/api/accounts/auto-login", {
                    method: "POST",
                    credentials: "include",
                });

                if (response.ok) {
                    const data = await response.json();
                    sessionStorage.setItem("access_token", data.access_token);
                    window.location.href = "main.html";
                }
            } catch (error) {
                console.error("Auto-login failed:", error);
            }
        };

        autoLogin();
    }

    document.getElementById("registerRedirectButton")?.addEventListener("click", () => {
        window.location.href = "register.html";
    });
});