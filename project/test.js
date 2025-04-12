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
        try {
            console.log("Sending refresh token request...");
            const response = await fetch("http://localhost:8000/api/accounts/refresh-token", {
                method: "POST",
                credentials: "include",
            });

            return response.ok;
        } catch (error) {
            console.error("Error refreshing token:", error);
            window.location.href = "login.html";
            return false;
        }
    }

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

        let response = await fetch("http://localhost:8000/api/posts", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ title, content }),
        });

        if (response.status === 401) {
            if (await refreshToken()) {
                response = await fetch("http://localhost:8000/api/posts", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ title, content }),
                });
            }
        }

        const data = await response.json();
        alert(response.ok ? "Post created successfully!" : "Error: " + (data.error || "Unknown error"));

        if (response.ok) {
            loadPosts();
        }
    });

    document.getElementById("deleteForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const postId = document.getElementById("deletePostId").value;

        const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
            method: "DELETE",
            credentials: "include",
        });

        const data = await response.json();
        alert(response.ok ? "Post deleted successfully!" : "Error: " + (data.error || "Unknown error"));

        if (response.ok) {
            loadPosts();
        }
    });

    document.getElementById("logoutButton")?.addEventListener("click", async () => {
        const response = await fetch("http://localhost:8000/api/accounts/logout", {
            method: "POST",
            credentials: "include",
        });

        if (response.ok) {
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

        if (!postId || isNaN(postId)) {
            alert("Invalid Post ID. Please enter a valid number.");
            return;
        }

        if (!comment) {
            alert("Comment cannot be empty.");
            return;
        }

        const response = await fetch("http://localhost:8000/api/comments", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ postId: parseInt(postId, 10), comment }),
        });

        const data = await response.json();
        alert(response.ok ? "Comment created successfully!" : "Error: " + (data.error || "Unknown error"));
    });

    document.getElementById("deleteCommentForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const commentId = document.getElementById("deleteCommentId").value.trim();

        if (!commentId || isNaN(commentId)) {
            alert("Invalid Comment ID. Please enter a valid number.");
            return;
        }

        const response = await fetch(`http://localhost:8000/api/comments/${commentId}`, {
            method: "DELETE",
            credentials: "include",
        });

        const data = await response.json();
        alert(response.ok ? "Comment deleted successfully!" : "Error: " + (data.error || "Unknown error"));
    });

    document.getElementById("showInfoButton")?.addEventListener("click", async () => {
        const response = await fetch("http://localhost:8000/api/accounts/info", {
            method: "GET",
            credentials: "include",
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

        if (!currentPassword || !newPassword) {
            alert("Both current and new passwords are required.");
            return;
        }

        const response = await fetch("http://localhost:8000/api/accounts/change-password", {
            method: "PUT",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ currentPassword, newPassword }),
        });

        const data = await response.json();
        alert(response.ok ? "Password changed successfully! Please log in again." : "Error: " + (data.error || "Unknown error"));

        if (response.ok) {
            window.location.href = "login.html";
        }
    });

    document.getElementById("deleteUserButton")?.addEventListener("click", async () => {
        const response = await fetch("http://localhost:8000/api/accounts/delete", {
            method: "DELETE",
            credentials: "include",
        });

        const data = await response.json();
        alert(response.ok ? "User deleted successfully!" : "Error: " + (data.error || "Unknown error"));

        if (response.ok) {
            window.location.href = "login.html";
        }
    });

    async function checkAuth() {
        try {
            const response = await fetch("http://localhost:8000/api/accounts/check-auth", {
                method: "GET",
                credentials: "include"
            });
            const data = await response.json();
            return data.authenticated;
        } catch (error) {
            console.error("Auth check failed:", error);
            return false;
        }
    }

    // Initialize the page
    (async () => {
        const isAuthenticated = await checkAuth();
        if (isAuthenticated) {
            const postsList = document.getElementById("postsList");
            if (postsList) {
                await loadPosts();
            }
        } else {
            window.location.href = "login.html";
        }
    })();

    async function loadPosts() {
        const postsList = document.getElementById("postsList");
        if (!postsList) return;

        try {
            const response = await fetch("http://localhost:8000/api/posts", {
                method: "GET",
                credentials: "include",
            });

            if (!response.ok) {
                document.getElementById("postsList").innerHTML = '<p>Could not load posts.</p>';
                return;
            }

            const posts = await response.json();
            const postsListDiv = document.getElementById("postsList");
            postsListDiv.innerHTML = '';

            if (posts.length === 0) {
                postsListDiv.innerHTML = '<p>No posts yet.</p>';
                return;
            }

            posts.forEach(post => {
                const postElement = document.createElement('div');
                postElement.classList.add('post-item');
                const createdDate = new Date(post.created).toLocaleString();
                postElement.innerHTML = `
                    <strong>${post.title}</strong> (by ${post.user})
                    <br>
                    <small>Created on: ${createdDate}</small>
                `;
                postElement.style.cursor = 'pointer';
                postElement.dataset.postId = post.id;

                postElement.addEventListener('click', () => {
                    window.location.href = `post.html?id=${post.id}`;
                });
                postsListDiv.appendChild(postElement);
            });
        } catch (error) {
            document.getElementById("postsList").innerHTML = '<p>Error loading posts.</p>';
        }
    }

    document.getElementById('closePostDetail')?.addEventListener('click', () => {
        document.getElementById("postDetailView").style.display = 'none';
    });
});

