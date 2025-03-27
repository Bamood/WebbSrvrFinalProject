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

    // Function to refresh the access token
    async function refreshToken() {
        const refreshToken = localStorage.getItem("refresh_token");
        if (!refreshToken) {
            alert("No refresh token available. Please log in again.");
            window.location.href = "landing.html"; // Redirect to login
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

        const data = await response.json();
        if (response.ok) {
            sessionStorage.setItem("access_token", data.access_token); // Update the access token
            localStorage.setItem("refresh_token", data.refresh_token); // Update the refresh token
            return true;
        } else {
            alert("Failed to refresh token. Please log in again.");
            window.location.href = "landing.html"; // Redirect to login
            return false;
        }
    }

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
            window.location.href = "landing.html"; // Redirect to the login page
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

        if (!token) {
            alert("You must be logged in to create a post.");
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

        const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + sessionStorage.getItem("access_token")
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
            window.location.href = "landing.html";
        } else {
            await handleError(response);
        }
    });

    document.getElementById("commentForm")?.addEventListener("submit", async function (event) {
        event.preventDefault();
        const postId = encodeHTML(document.getElementById("commentPostId").value);
        const comment = encodeHTML(document.getElementById("commentContent").value);
        const token = sessionStorage.getItem("access_token");

        if (!token) {
            alert("You must be logged in to create a comment.");
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

        const response = await fetch(`http://localhost:8000/api/comments/${commentId}`, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + sessionStorage.getItem("access_token")
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

        if (!token) {
            alert("You must be logged in to change your password.");
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
            window.location.href = "landing.html"; // Redirect to the login page
        } else {
            alert("Error: " + encodeHTML(data.error));
        }
    });

    document.getElementById("logoutButton")?.addEventListener("click", function () {
        const token = sessionStorage.getItem("access_token");
        if (!token) {
            alert("You are not logged in.");
            return;
        }

        sessionStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        alert("Logged out successfully!");
        // Redirect to the landing page
        window.location.href = "landing.html";
    });

    document.getElementById("showInfoButton")?.addEventListener("click", async function () {
        let token = sessionStorage.getItem("access_token");

        if (!token) {
            alert("You must be logged in to view your information.");
            return;
        }

        const refreshed = await refreshToken();
        if (refreshed) {
            token = sessionStorage.getItem("access_token");
        }

        const response = await fetch("http://localhost:8000/api/accounts/info", {
            method: "GET",
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        const data = await response.json();
        if (response.ok) {
            alert(`Username: ${encodeHTML(data.username)}\nEmail: ${encodeHTML(data.email)}`);
        } else {
            alert("Error: " + encodeHTML(data.error));
        }
    });
});
