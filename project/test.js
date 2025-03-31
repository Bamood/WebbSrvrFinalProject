document.addEventListener("DOMContentLoaded", async () => {
    let csrfToken;

    // Fetch CSRF token from the server
    async function fetchCsrfToken() {
        if (csrfToken) {
            console.log("Using existing CSRF token:", csrfToken); // Debugging log
            return;
        }
        const response = await fetch("http://localhost:8000/csrf-token", {
            method: "GET",
            credentials: "include" // Ensure cookies are sent with the request
        });
        if (!response.ok) {
            console.error("Failed to fetch CSRF token:", response.statusText); // Debugging log
            throw new Error("Failed to fetch CSRF token");
        }
        const data = await response.json();
        csrfToken = data.csrfToken;
        console.log("Fetched CSRF token:", csrfToken); // Debugging log
    }

    // Ensure CSRF token is included in all requests
    async function makeRequest(url, options) {
        if (!csrfToken) {
            await fetchCsrfToken(); // Ensure CSRF token is available
        }
        options.headers = {
            ...options.headers,
            "X-CSRF-Token": csrfToken // Include CSRF token
        };
        return fetch(url, options);
    }

    await fetchCsrfToken(); // Fetch the CSRF token on page load

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
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const response = await makeRequest("http://localhost:8000/api/accounts/refresh-token", {
            method: "POST",
            credentials: "include"
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
        try {
            const data = await response.json();
            alert("Error: " + encodeHTML(data.error || "Unknown error"));
        } catch (e) {
            alert("Error: An unexpected error occurred.");
        }
    }

    document.getElementById("registerForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const username = encodeHTML(document.getElementById("regUsername").value);
        const email = encodeHTML(document.getElementById("regEmail").value);
        const password = encodeHTML(document.getElementById("regPassword").value);

        const response = await makeRequest("http://localhost:8000/api/accounts/register", {
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
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const username = encodeHTML(document.getElementById("loginUsername").value);
        const password = encodeHTML(document.getElementById("loginPassword").value);

        try {
            const response = await makeRequest("http://localhost:8000/api/accounts/login", {
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

    document.getElementById("postForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const title = encodeHTML(document.getElementById("postTitle").value);
        const content = encodeHTML(document.getElementById("postContent").value);
        let token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        let response = await makeRequest("http://localhost:8000/api/posts", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({ title, content })
        });
        console.log("Request headers:", {
            "Authorization": "Bearer " + token,
            "X-CSRF-Token": csrfToken
        }); // Debugging log
        console.log("Response status:", response.status); // Debugging log

        if (response.status === 401 || response.status === 403) {
            const refreshed = await refreshToken();
            if (refreshed) {
                token = sessionStorage.getItem("access_token");
                response = await makeRequest("http://localhost:8000/api/posts", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + token
                    },
                    body: JSON.stringify({ title, content })
                });
                console.log("Request headers:", {
                    "Authorization": "Bearer " + token,
                    "X-CSRF-Token": csrfToken
                }); // Debugging log
                console.log("Response status:", response.status); // Debugging log
            }
        }

        const data = await response.json();
        alert(response.ok ? "Post created successfully!" : "Error: " + encodeHTML(data.error));
    });

    document.getElementById("deleteForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const postId = encodeHTML(document.getElementById("deletePostId").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await makeRequest(`http://localhost:8000/api/posts/${postId}`, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        const data = await response.json();
        alert(response.ok ? "Post deleted successfully!" : "Error: " + encodeHTML(data.error));
    });

    document.getElementById("deleteUserForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const token = sessionStorage.getItem("access_token");

        if (!token) {
            alert("You must be logged in to delete your account.");
            return;
        }

        const response = await makeRequest("http://localhost:8000/api/accounts/delete", {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + token
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
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const postId = encodeHTML(document.getElementById("commentPostId").value);
        const comment = encodeHTML(document.getElementById("commentContent").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await makeRequest("http://localhost:8000/api/comments", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({ postId, comment })
        });

        const data = await response.json();
        alert(response.ok ? "Comment created successfully!" : "Error: " + encodeHTML(data.error));
    });

    document.getElementById("deleteCommentForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const commentId = encodeHTML(document.getElementById("deleteCommentId").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await makeRequest(`http://localhost:8000/api/comments/${commentId}`, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        const data = await response.json();
        alert(response.ok ? "Comment deleted successfully!" : "Error: " + encodeHTML(data.error));
    });

    document.getElementById("changePasswordForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const currentPassword = encodeHTML(document.getElementById("currentPassword").value);
        const newPassword = encodeHTML(document.getElementById("newPassword").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await makeRequest("http://localhost:8000/api/accounts/change-password", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });

        const data = await response.json();
        if (response.ok) {
            sessionStorage.removeItem("access_token");
            localStorage.removeItem("refresh_token");
            alert("Password changed successfully. You have been logged out. Please log in again.");
            window.location.href = "login.html"; // Redirect to the login page
        } else {
            alert("Error: " + encodeHTML(data.error));
        }
    });

    document.getElementById("logoutButton")?.addEventListener("click", async function () {
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const response = await makeRequest("http://localhost:8000/api/accounts/logout", {
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
        if (!csrfToken) {
            await fetchCsrfToken(); // Fetch CSRF token if not available
        }

        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        // Fetch user information
        const response = await makeRequest("http://localhost:8000/api/accounts/info", {
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
