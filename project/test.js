document.addEventListener("DOMContentLoaded", () => {
    const decodeJWT = (token) => {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload));
    };

    const isTokenExpired = (token) => {
        const payload = decodeJWT(token);
        return payload.exp * 1000 <= Date.now();
    };

    async function refreshToken() {
        const response = await fetch("http://localhost:8000/api/accounts/refresh-token", {
            method: "POST",
            credentials: "include",
        });

        if (response.ok) {
            const data = await response.json();
            sessionStorage.setItem("access_token", data.access_token);
            return true;
        } else {
            alert("Session expired. Please log in again.");
            window.location.href = "login.html";
            return false;
        }
    }

    function startAccessTokenRefreshTimer() {
        const token = sessionStorage.getItem("access_token");
        if (!token) return;

        const payload = decodeJWT(token);
        const refreshTime = payload.exp * 1000 - Date.now() - 60000;

        if (refreshTime > 0) {
            setTimeout(async () => {
                if (await refreshToken()) startAccessTokenRefreshTimer();
            }, refreshTime);
        }
    }

    startAccessTokenRefreshTimer();

    async function handleError(response) {
        const data = await response.json();
        alert("Error: " + (data.error || "Unknown error"));
    }

    document.getElementById("registerForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = document.getElementById("regUsername").value;
        const email = document.getElementById("regEmail").value;
        const password = document.getElementById("regPassword").value;

        const response = await fetch("http://localhost:8000/api/accounts/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password }),
        });

        if (response.ok) {
            alert("User registered successfully! Redirecting to login page...");
            window.location.href = "login.html";
        } else {
            await handleError(response);
        }
    });

    document.getElementById("loginForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = document.getElementById("loginUsername").value;
        const password = document.getElementById("loginPassword").value;

        const response = await fetch("http://localhost:8000/api/accounts/login", {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            const data = await response.json();
            sessionStorage.setItem("access_token", data.access_token);
            alert("Login successful!");
            window.location.href = "test.html";
        } else {
            await handleError(response);
        }
    });

    document.getElementById("postForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const title = document.getElementById("postTitle").value;
        const content = document.getElementById("postContent").value;
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
                "Authorization": "Bearer " + token,
            },
            body: JSON.stringify({ title, content }),
        });

        if (response.status === 401 || response.status === 403) {
            if (await refreshToken()) {
                response = await fetch("http://localhost:8000/api/posts", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + sessionStorage.getItem("access_token"),
                    },
                    body: JSON.stringify({ title, content }),
                });
            }
        }

        const data = await response.json();
        alert(response.ok ? "Post created successfully!" : "Error: " + (data.error || "Unknown error"));
    });

    document.getElementById("deleteForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const postId = document.getElementById("deletePostId").value;
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
return;
}

        const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
            method: "DELETE",
            headers: { "Authorization": "Bearer " + token },
        });

        const data = await response.json();
        alert(response.ok ? "Post deleted successfully!" : "Error: " + (data.error || "Unknown error"));
    });

    document.getElementById("logoutButton")?.addEventListener("click", async () => {
        const response = await fetch("http://localhost:8000/api/accounts/logout", {
            method: "POST",
            credentials: "include",
        });

        if (response.ok) {
            sessionStorage.removeItem("access_token");
            alert("Logged out successfully!");
            window.location.href = "login.html";
        } else {
            alert("Failed to log out. Please try again.");
        }
    });

    document.getElementById("commentForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const postId = document.getElementById("commentPostId").value.trim();
        const comment = document.getElementById("commentContent").value.trim();
        const token = sessionStorage.getItem("access_token");

        if (!postId || isNaN(postId)) {
            alert("Invalid Post ID. Please enter a valid number.");
            return;
        }

        if (!comment) {
            alert("Comment cannot be empty.");
            return;
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await fetch("http://localhost:8000/api/comments", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
            },
            body: JSON.stringify({ postId: parseInt(postId, 10), comment }),
        });

        const data = await response.json();
        alert(response.ok ? "Comment created successfully!" : "Error: " + (data.error || "Unknown error"));
    });

    document.getElementById("deleteCommentForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const commentId = document.getElementById("deleteCommentId").value.trim();
        const token = sessionStorage.getItem("access_token");

        if (!commentId || isNaN(commentId)) {
            alert("Invalid Comment ID. Please enter a valid number.");
            return;
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await fetch(`http://localhost:8000/api/comments/${commentId}`, {
            method: "DELETE",
            headers: { "Authorization": "Bearer " + token },
        });

        const data = await response.json();
        alert(response.ok ? "Comment deleted successfully!" : "Error: " + (data.error || "Unknown error"));
    });

    document.getElementById("showInfoButton")?.addEventListener("click", async () => {
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

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
            document.getElementById("userInfo").style.display = "block";
        } else {
            const errorData = await response.json();
            alert("Error: " + (errorData.error || "Unknown error"));
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

        const response = await fetch("http://localhost:8000/api/accounts/change-password", {
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
    });

    document.getElementById("deleteUserButton")?.addEventListener("click", async () => {
        const token = sessionStorage.getItem("access_token");

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        const response = await fetch("http://localhost:8000/api/accounts/delete", {
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
    });
});
