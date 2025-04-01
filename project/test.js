document.addEventListener("DOMContentLoaded", () => {
    const API_BASE_URL = "http://localhost:8000"; // Your server URL

    const encodeHTML = (str) => {
        return str.replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;")
                  .replace(/'/g, "&#039;");
    };

    // Decode JWT to extract payload
    const decodeJWT = (token) => {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload));
    };

    // Function to check if the token is expired
    const isTokenExpired = (token) => {
        const payload = decodeJWT(token);
        return payload.exp * 1000 <= Date.now(); // Check if the expiration time has passed
    };

    // Function to refresh the access token
    async function refreshToken() {
        const response = await fetch(`${API_BASE_URL}/api/accounts/refresh-token`, {
            method: "POST",
            credentials: "include", // Ensure cookies are sent with the request
        });

        const data = await response.json();
        if (response.ok) {
            sessionStorage.setItem("access_token", data.access_token); // Update the access token
            return true;
        } else {
            alert("Failed to refresh token. Please log in again.");
            window.location.href = "login.html"; // Redirect to login
            return false;
        }
    }

    // Automatically refresh the access token before expiration
    function startAccessTokenRefreshTimer() {
        const token = sessionStorage.getItem("access_token");
        if (!token) return;

        const payload = decodeJWT(token);
        const expirationTime = payload.exp * 1000; // Convert to milliseconds
        const refreshTime = expirationTime - Date.now() - 60000; // Refresh 1 minute before expiration

        if (refreshTime > 0) {
            setTimeout(async () => {
                console.log("Refreshing access token before expiration...");
                const refreshed = await refreshToken();
                if (refreshed) {
                    startAccessTokenRefreshTimer(); // Restart the timer with the new token
                }
            }, refreshTime);
        }
    }

    // Start the access token refresh timer on page load
    startAccessTokenRefreshTimer();

    // Ensure error messages in alerts are encoded
    async function handleError(response) {
        const data = await response.json();
        alert("Error: " + encodeHTML(data.error || "Unknown error"));
    }

    // Fetch CSRF token before making POST/PUT/DELETE requests
    async function fetchCsrfToken() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/csrf-token`, {
                credentials: "include" // Include cookies
            });
            if (!response.ok) throw new Error("Failed to fetch CSRF token");
            const data = await response.json();
            return data.csrfToken;
        } catch (error) {
            console.error("Error fetching CSRF token:", error);
            return null;
        }
    }

    document.getElementById("registerForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const username = encodeHTML(document.getElementById("regUsername").value);
        const email = encodeHTML(document.getElementById("regEmail").value);
        const password = encodeHTML(document.getElementById("regPassword").value);

        const response = await fetch(`${API_BASE_URL}/api/accounts/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, email, password })
        });

        if (response.ok) {
            alert("User registered successfully! Redirecting to login page...");
            window.location.href = "login.html"; // Redirect to the login page
        } else {
            await handleError(response);
        }
    });

    document.getElementById("loginForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const username = encodeHTML(document.getElementById("loginUsername").value);
        const password = encodeHTML(document.getElementById("loginPassword").value);

        try {
            const response = await fetch(`${API_BASE_URL}/api/accounts/login`, {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (response.ok) {
                sessionStorage.setItem("access_token", data.access_token);
                alert("Login successful!");
                window.location.href = "test.html";
            } else {
                alert("Error: " + encodeHTML(data.error));
            }
        } catch (error) {
            console.error("Error during login request:", error); // Debugging log
            alert("An unexpected error occurred. Please try again.");
        }
    });

    // Ensure CSRF token is included only for routes that require it
    document.getElementById("postForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const title = encodeHTML(document.getElementById("postTitle").value);
        const content = encodeHTML(document.getElementById("postContent").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const csrfToken = await fetchCsrfToken();
        if (!csrfToken) {
            alert("Security error: Could not get CSRF token");
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/posts`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`,
                    "X-CSRF-Token": csrfToken
                },
                credentials: "include",
                body: JSON.stringify({ title, content })
            });

            const data = await response.json();
            alert(response.ok ? "Post created successfully!" : "Error: " + encodeHTML(data.error));
        } catch (error) {
            console.error("Error creating post:", error);
        }
    });

    document.getElementById("deleteForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const postId = encodeHTML(document.getElementById("deletePostId").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const csrfToken = await fetchCsrfToken();
        if (!csrfToken) {
            alert("Security error: Could not get CSRF token");
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/posts/${postId}`, {
                method: "DELETE",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "X-CSRF-Token": csrfToken
                }
            });

            const data = await response.json();
            alert(response.ok ? "Post deleted successfully!" : "Error: " + encodeHTML(data.error));
        } catch (error) {
            console.error("Error deleting post:", error);
        }
    });

    document.getElementById("deleteUserForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const token = sessionStorage.getItem("access_token");

        if (!token) {
            alert("You must be logged in to delete your account.");
            return;
        }

        const csrfToken = await fetchCsrfToken();
        if (!csrfToken) {
            alert("Security error: Could not get CSRF token");
            return;
        }

        const response = await fetch(`${API_BASE_URL}/api/accounts/delete`, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + token,
                "X-CSRF-Token": csrfToken
            }
        });

        const data = await response.json();
        if (response.ok) {
            sessionStorage.removeItem("access_token");
            localStorage.removeItem("refresh_token");
            alert("User deleted successfully!");
            window.location.href = "login.html";
        } else {
            await handleError(response);
        }
    });

    document.getElementById("commentForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const postId = encodeHTML(document.getElementById("commentPostId").value);
        const comment = encodeHTML(document.getElementById("commentContent").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const csrfToken = await fetchCsrfToken();
        if (!csrfToken) {
            alert("Security error: Could not get CSRF token");
            return;
        }

        const response = await fetch(`${API_BASE_URL}/api/comments`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({ postId, comment })
        });

        const data = await response.json();
        alert(response.ok ? "Comment created successfully!" : "Error: " + encodeHTML(data.error));
    });

    document.getElementById("deleteCommentForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const commentId = encodeHTML(document.getElementById("deleteCommentId").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const csrfToken = await fetchCsrfToken();
        if (!csrfToken) {
            alert("Security error: Could not get CSRF token");
            return;
        }

        const response = await fetch(`${API_BASE_URL}/api/comments/${commentId}`, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + token,
                "X-CSRF-Token": csrfToken
            }
        });

        const data = await response.json();
        alert(response.ok ? "Comment deleted successfully!" : "Error: " + encodeHTML(data.error));
    });

    document.getElementById("changePasswordForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const currentPassword = encodeHTML(document.getElementById("currentPassword").value);
        const newPassword = encodeHTML(document.getElementById("newPassword").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const csrfToken = await fetchCsrfToken();
        if (!csrfToken) {
            alert("Security error: Could not get CSRF token");
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/accounts/change-password`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${token}`,
                    "X-CSRF-Token": csrfToken
                },
                body: JSON.stringify({ currentPassword, newPassword })
            });

            if (!response.ok) {
                const errorData = await response.json();
                alert("Error: " + encodeHTML(errorData.error || "Unknown error"));
                return;
            }

            const data = await response.json();
            sessionStorage.removeItem("access_token");
            alert("Password changed successfully. You have been logged out. Please log in again.");
            window.location.href = "login.html";
        } catch (error) {
            console.error("Error changing password:", error);
            alert("An unexpected error occurred. Please try again.");
        }
    });

    document.getElementById("logoutButton")?.addEventListener("click", async function () {
        const response = await fetch(`${API_BASE_URL}/api/accounts/logout`, {
            method: "POST",
            credentials: "include"
        });

        if (response.ok) {
            sessionStorage.removeItem("access_token");
            localStorage.removeItem("refresh_token");
            alert("Logged out successfully!");
            window.location.href = "login.html";
        } else {
            alert("Failed to log out. Please try again.");
        }
    });

    document.getElementById("showInfoButton")?.addEventListener("click", async function () {
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        // Fetch user information
        const response = await fetch(`${API_BASE_URL}/api/accounts/info`, {
            method: "GET",
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        const data = await response.json();
        if (response.ok) {
            document.getElementById("infoUsername").textContent = encodeHTML(data.username);
            document.getElementById("infoEmail").textContent = encodeHTML(data.email);
            document.getElementById("userInfo").style.display = "block";
        } else {
            alert("Error: " + encodeHTML(data.error));
        }
    });
});
