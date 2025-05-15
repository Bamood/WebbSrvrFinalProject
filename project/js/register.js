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
    // Load the CSRF token when the page loads
    try {
        await getCsrfToken();
    } catch (error) {
        console.error("Failed to get initial CSRF token:", error);
    }

    document.getElementById("registerForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = document.getElementById("regUsername").value;
        const email = document.getElementById("regEmail").value;
        const password = document.getElementById("regPassword").value;

        try {
            // Use CSRF-protected fetch
            const response = await fetchWithCsrf("http://localhost:8000/api/accounts/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, email, password }),
            });

            if (response.ok) {
                alert("User registered successfully! Redirecting to login page...");
                window.location.href = "login.html";
            } else {
                const data = await response.json();
                alert("Error: " + (data.error || "Unknown error"));
            }
        } catch (error) {
            console.error("Registration error:", error);
            alert("An error occurred during registration. Please try again later.");
        }
    });

    document.getElementById("loginRedirectButton")?.addEventListener("click", () => {
        window.location.href = "login.html";
    });
});
