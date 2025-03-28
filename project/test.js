document.addEventListener("DOMContentLoaded", () => {
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
        const refreshToken = localStorage.getItem("refresh_token");
        console.log("Refresh token accessed in refreshToken:", refreshToken); // Debugging log
        if (!refreshToken) {
            alert("No refresh token available. Please log in again.");
            window.location.href = "login.html"; // Redirect to login
            return false;
        }

        const response = await fetch("http://localhost:8000/api/accounts/refresh-token", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ refreshToken })
        });

        console.log("Refresh token response status:", response.status); // Debugging log
        const data = await response.json();
        console.log("Refresh token response data:", data); // Debugging log

        if (response.ok) {
            sessionStorage.setItem("access_token", data.access_token); // Update the access token
            console.log("Access token refreshed:", sessionStorage.getItem("access_token")); // Debugging log
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

    document.getElementById("registerForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const username = encodeHTML(document.getElementById("regUsername").value);
        const email = encodeHTML(document.getElementById("regEmail").value);
        const password = encodeHTML(document.getElementById("regPassword").value);

        const response = await fetch("http://localhost:8000/api/accounts/register", {
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

        const response = await fetch("http://localhost:8000/api/accounts/login", {
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
            localStorage.setItem("refresh_token", data.refresh_token); // Store the refresh token
            console.log("Refresh token stored:", localStorage.getItem("refresh_token")); // Debugging log
            alert("Login successful!");
            // Redirect to another page after login
            window.location.href = "test.html";
        } else {
            alert("Error: " + encodeHTML(data.error));
        }
    });

    document.getElementById("postForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const title = encodeHTML(document.getElementById("postTitle").value);
        const content = encodeHTML(document.getElementById("postContent").value);
        let token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        let response = await fetch("http://localhost:8000/api/posts", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({ title, content })
        });

        if (response.status === 401 || response.status === 403) {
            const refreshed = await refreshToken();
            if (refreshed) {
                token = sessionStorage.getItem("access_token");
                response = await fetch("http://localhost:8000/api/posts", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + token
                    },
                    body: JSON.stringify({ title, content })
                });
            }
        }

        const data = await response.json();
        alert(response.ok ? "Post created successfully!" : "Error: " + encodeHTML(data.error));
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

        const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
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
        const token = sessionStorage.getItem("access_token");

        if (!token) {
            alert("You must be logged in to delete your account.");
            return;
        }

        const response = await fetch("http://localhost:8000/api/accounts/delete", {
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
        const postId = encodeHTML(document.getElementById("commentPostId").value);
        const comment = encodeHTML(document.getElementById("commentContent").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await fetch("http://localhost:8000/api/comments", {
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
        const commentId = encodeHTML(document.getElementById("deleteCommentId").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await fetch(`http://localhost:8000/api/comments/${commentId}`, {
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
        const currentPassword = encodeHTML(document.getElementById("currentPassword").value);
        const newPassword = encodeHTML(document.getElementById("newPassword").value);
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await fetch("http://localhost:8000/api/accounts/change-password", {
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
        const response = await fetch("http://localhost:8000/api/accounts/logout", {
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
        const response = await fetch("http://localhost:8000/api/accounts/info", {
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
