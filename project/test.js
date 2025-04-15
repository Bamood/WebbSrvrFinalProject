document.addEventListener("DOMContentLoaded", () => {
    const decodeJWT = (token) => {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload));
    };

    const isTokenExpired = (token) => {
        const payload = decodeJWT(token);
        return payload.exp * 1000 <= Date.now();
    };

    async function autoLogin(req, res) {
        const refreshToken = req.cookies?.refresh_token; // Retrieve the refresh token from the cookie
        if (!refreshToken) {
            return res.status(401).json({ error: "No refresh token provided" });
        }
    
        try {
            const payload = validateRefreshToken(refreshToken);
            if (!payload) {
                return res.status(401).json({ error: "Invalid refresh token" });
            }
    
            const newAccessToken = jwt.sign(
                { username: payload.username },
                ACCESS_TOKEN_SECRET,
                { expiresIn: "2m" }
            );
    
            res.json({ access_token: newAccessToken });
        } catch (error) {
            console.error("Error during auto-login:", error);
            res.status(500).json({ error: "Internal server error" });
        }
    }

    async function refreshToken() {
        try {
            const response = await fetch("http://localhost:8000/api/accounts/refresh-token", {
                method: "POST",
                credentials: "include", // Include the refresh token cookie
            });

            if (response.ok) {
                const data = await response.json();
                sessionStorage.setItem("access_token", data.access_token); // Store the new access token
                return true;
            } else {
                sessionStorage.removeItem("access_token");
                alert("Session expired. Redirecting to login page...");
                window.location.href = "login.html";
                return false;
            }
        } catch (error) {
            alert("An error occurred while refreshing the token. Please log in again.");
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

        try {
            const response = await fetch("http://localhost:8000/api/accounts/login", {
                method: "POST",
                credentials: "include",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                const errorText = await response.text(); // Read the raw response text
                console.error("Login failed:", errorText); // Log the error response
                alert("Login failed. Please check your credentials or try again later.");
                return;
            }

            const data = await response.json();
            sessionStorage.setItem("access_token", data.access_token);
            alert("Login successful!");
            window.location.href = "test.html";
        } catch (error) {
            console.error("Error during login:", error); // Log any unexpected errors
            alert("An error occurred during login. Please try again later.");
        }
    });

    document.getElementById("postForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const title = document.getElementById("postTitle").value.trim();
        const content = document.getElementById("postContent").value.trim();
        let token = sessionStorage.getItem("access_token");

        // Validate input before sending the request
        if (title.length === 0 || title.length > 100) {
            alert("Title must be between 1 and 100 characters.");
            return;
        }
        if (content.length === 0) {
            alert("Content cannot be empty.");
            return;
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        try {
            let response = await fetch("http://localhost:8000/api/posts", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + token,
                },
                body: JSON.stringify({ title, content }),
            });

            if (response.status === 400) {
                const errorData = await response.json();
                console.error("Error:", errorData.error); // Log the error message
                alert("Error: " + errorData.error);
                return;
            }

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

            if (response.ok) {
                loadPosts();
            }
        } catch (error) {
            console.error("Fetch error:", error); // Log unexpected errors
            alert("An error occurred while creating the post. Please try again.");
        }
    });

    document.getElementById("deleteForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const postId = document.getElementById("deletePostId").value.trim();
        const token = sessionStorage.getItem("access_token");

        if (!postId || isNaN(postId)) {
            alert("Invalid Post ID. Please enter a valid number.");
            return;
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        console.log(`Attempting to delete post with ID: ${postId}`); // Debugging log

        try {
            const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
                method: "DELETE",
                headers: { "Authorization": "Bearer " + token },
            });

            const data = await response.json();
            console.log("Delete post response:", data); // Debugging log

            alert(response.ok ? "Post deleted successfully!" : "Error: " + (data.error || "Unknown error"));

            if (response.ok) {
                loadPosts();
            }
        } catch (error) {
            console.error("Error deleting post:", error); // Debugging log
            alert("An error occurred while deleting the post.");
        }
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

        console.log(`Attempting to delete comment with ID: ${commentId}`); // Debugging log

        try {
            const response = await fetch(`http://localhost:8000/api/comments/${commentId}`, {
                method: "DELETE",
                headers: { "Authorization": "Bearer " + token },
            });

            const data = await response.json();
            console.log("Delete comment response:", data); // Debugging log

            alert(response.ok ? "Comment deleted successfully!" : "Error: " + (data.error || "Unknown error"));

            if (response.ok) {
                const postId = new URLSearchParams(window.location.search).get("id");
                loadComments(postId, token);
            }
        } catch (error) {
            console.error("Error deleting comment:", error); // Debugging log
            alert("An error occurred while deleting the comment.");
        }
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

        console.log(`Attempting to delete comment with ID: ${commentId}`); // Debugging log

        try {
            const response = await fetch(`http://localhost:8000/api/comments/${commentId}`, {
                method: "DELETE",
                headers: { "Authorization": "Bearer " + token },
            });

            const data = await response.json();
            console.log("Delete comment response:", data); // Debugging log

            alert(response.ok ? "Comment deleted successfully!" : "Error: " + (data.error || "Unknown error"));

            if (response.ok) {
                const postId = new URLSearchParams(window.location.search).get("id");
                loadComments(postId, token);
            }
        } catch (error) {
            console.error("Error deleting comment:", error); // Debugging log
            alert("An error occurred while deleting the comment.");
        }
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
            document.getElementById("userInfo").classList.remove("hidden"); // Use CSS class instead of inline style
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

    if (sessionStorage.getItem("access_token")) {
        loadPosts();
    }

    // Add event listener for the "Manage Account" button
    document.getElementById("accManagementButton")?.addEventListener("click", () => {
        window.location.href = "accManagement.html";
    });

    // Add event listener for the "Register" redirect button
    document.getElementById("registerRedirectButton")?.addEventListener("click", () => {
        window.location.href = "register.html";
    });

    // Add event listener for the "Login" redirect button
    document.getElementById("loginRedirectButton")?.addEventListener("click", () => {
        window.location.href = "login.html";
    });

    async function loadPosts() {
        console.log("Loading posts..."); // Debugging log
        const token = sessionStorage.getItem("access_token");
        const postsListDiv = document.getElementById("postsList");

        // Check if postsListDiv exists
        if (!postsListDiv) {
            console.warn("postsList element not found. Skipping loadPosts."); // Debugging log
            return; // Exit if the element is missing
        }

        if (!token || isTokenExpired(token)) {
            postsListDiv.innerHTML = '<p>Please log in to see posts.</p>';
            return;
        }

        try {
            const response = await fetch("http://localhost:8000/api/posts", {
                method: "GET",
                headers: { "Authorization": "Bearer " + token },
            });

            if (!response.ok) {
                postsListDiv.innerHTML = '<p>Could not load posts.</p>';
                return;
            }

            const posts = await response.json();
            console.log("API response:", posts); // Debugging log

            postsListDiv.innerHTML = '';

            if (posts.length === 0) {
                postsListDiv.innerHTML = '<p>No posts yet.</p>';
                return;
            }

            posts.forEach(post => {
                const postElement = document.createElement('div');
                postElement.classList.add('post-item');
                postElement.style.cursor = "pointer"; // Ensure the post is visually clickable
                const createdDate = new Date(post.created).toLocaleString(); // Format the creation date
                postElement.innerHTML = `
                    <strong>${post.title}</strong> (by ${post.user})
                    <br>
                    <small>Created on: ${createdDate}</small>
                `;

                // Add click event listener to redirect to post.html with the post ID
                postElement.addEventListener('click', () => {
                    console.log(`Post clicked: ${post.title}`); // Debugging log
                    console.log(`Post content: ${post.content}`); // Debugging log

                    // Redirect to post.html with the post ID as a query parameter
                    window.location.href = `post.html?id=${post.id}`;
                });

                postsListDiv.appendChild(postElement);
            });
        } catch (error) {
            console.error("Error loading posts:", error); // Debugging log
            postsListDiv.innerHTML = '<p>Error loading posts.</p>';
        }
    }

    // Ensure loadPosts is only called on test.html
    if (window.location.pathname.endsWith("test.html")) {
        loadPosts();
    }
    
    // Close post detail view when the "Close" button is clicked
    document.getElementById('closePostDetail')?.addEventListener('click', () => {
        document.getElementById("postDetailView").classList.add("hidden"); // Hide the post detail view
    });
    
    // Ensure comments and other dynamic elements use CSS classes
    async function loadComments(postId, token) {
        const commentsListDiv = document.getElementById("commentsList");
        commentsListDiv.innerHTML = '<p>Loading comments...</p>';

        try {
            const response = await fetch(`http://localhost:8000/api/comments/${postId}`, {
                method: "GET",
                headers: { "Authorization": "Bearer " + token },
            });

            if (response.status === 404) {
                commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
                return;
            }

            if (!response.ok) {
                commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
                return;
            }

            const comments = await response.json();
            const payload = decodeJWT(token); // Decode the token to get the username
            const currentUser = payload.username;

            commentsListDiv.innerHTML = '';

            if (comments.length === 0) {
                commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
            } else {
                comments.forEach(comment => {
                    const commentElement = document.createElement('div');
                    commentElement.classList.add('comment-item');
                    const commentDate = new Date(comment.created_at).toLocaleString();
                    commentElement.innerHTML = `
                        <p><strong>${comment.user}:</strong> ${comment.comment}</p>
                        <small>Posted on: ${commentDate}</small>
                    `;

                    // Add delete button if the current user is the owner
                    if (comment.user === currentUser) {
                        const deleteButton = document.createElement('button');
                        deleteButton.classList.add('delete-button');
                        deleteButton.textContent = 'Delete';
                        deleteButton.addEventListener('click', async () => {
                            if (confirm("Are you sure you want to delete this comment?")) {
                                try {
                                    const deleteResponse = await fetch(`http://localhost:8000/api/comments/${comment.id}`, {
                                        method: "DELETE",
                                        headers: { "Authorization": "Bearer " + token },
                                    });

                                    if (deleteResponse.ok) {
                                        alert("Comment deleted successfully.");
                                        loadComments(postId, token);
                                    } else {
                                        alert("Failed to delete comment.");
                                    }
                                } catch (error) {
                                    console.error("Error deleting comment:", error);
                                    alert("Error deleting comment.");
                                }
                            }
                        });
                        commentElement.appendChild(deleteButton);
                    }

                    commentsListDiv.appendChild(commentElement);
                });
            }
        } catch (error) {
            console.error("Error loading comments:", error);
            commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
        }
    }

    // Redirect to test.html if the user has a valid access token (for login.html)
    if (window.location.pathname.endsWith("login.html")) {
        const accessToken = sessionStorage.getItem("access_token");
        if (accessToken) {
            try {
                const payload = JSON.parse(atob(accessToken.split('.')[1]));
                if (payload.exp * 1000 > Date.now()) { // Check if token is expired
                    window.location.href = "test.html";
                } else {
                    sessionStorage.removeItem("access_token"); // Clear expired token
                }
            } catch (error) {
                console.error("Failed to decode token:", error);
                sessionStorage.removeItem("access_token"); // Clear invalid token
            }
        }

        const autoLogin = async () => {
            try {
                const response = await fetch("http://localhost:8000/api/accounts/auto-login", {
                    method: "POST",
                    credentials: "include", // Include cookies
                });

                if (response.ok) {
                    const data = await response.json();
                    sessionStorage.setItem("access_token", data.access_token); // Store the new access token
                    window.location.href = "test.html"; // Redirect to the dashboard
                }
            } catch (error) {
                console.error("Auto-login failed:", error); // Log any errors
            }
        };

        autoLogin(); // Attempt auto-login
    }

    // Handle welcome message and redirection for test.html
    if (window.location.pathname.endsWith("test.html")) {
        const accessToken = sessionStorage.getItem("access_token");
        console.log("Access token retrieved from sessionStorage:", accessToken); // Log the access token

        if (!accessToken) {
            console.log("No access token found. Redirecting to login page."); // Log missing token
            window.location.href = "login.html";
            return;
        }

        try {
            const payload = JSON.parse(atob(accessToken.split('.')[1]));
            console.log("Decoded access token payload:", payload); // Log the decoded payload
            const username = payload.username;
            document.getElementById("welcomeMessage").textContent = `Welcome, ${username}!`;
        } catch (error) {
            console.error("Failed to decode access token:", error); // Log decoding error
            sessionStorage.removeItem("access_token");
            window.location.href = "login.html";
        }
    }

    // Handle functionality for accManagement.html
    if (window.location.pathname.endsWith("accManagement.html")) {
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
                document.getElementById("userInfo").classList.remove("hidden");
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

        // Add event listener for the "Back to Dashboard" button
        document.getElementById("backToDashboardButton")?.addEventListener("click", () => {
            window.location.href = "test.html";
        });
    }

    // Handle functionality for post.html
    if (window.location.pathname.endsWith("post.html")) {
        const postId = new URLSearchParams(window.location.search).get("id");
        const token = sessionStorage.getItem("access_token");

        if (!postId) {
            alert("Invalid post ID. Redirecting to the dashboard...");
            window.location.href = "test.html";
            return;
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
            return;
        }

        // Load post details
        async function loadPostDetails() {
            const postId = new URLSearchParams(window.location.search).get("id");
            const token = sessionStorage.getItem("access_token");
        
            if (!postId) {
                alert("Invalid post ID. Redirecting to the dashboard...");
                window.location.href = "test.html";
                return;
            }
        
            if (!token || isTokenExpired(token)) {
                alert("Your session has expired. Please log in again.");
                window.location.href = "login.html";
                return;
            }
        
            try {
                const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
                    method: "GET",
                    headers: { "Authorization": "Bearer " + token },
                });
        
                if (!response.ok) {
                    alert("Failed to load post details. Redirecting to the dashboard...");
                    window.location.href = "test.html";
                    return;
                }
        
                const post = await response.json();
                const payload = decodeJWT(token); // Decode the token to get the username
                const currentUser = payload.username;
        
                document.getElementById("postTitle").textContent = post.title;
                document.getElementById("postContent").textContent = post.content;
        
                // Add delete button if the current user is the owner
                if (post.user === currentUser) {
                    const deleteButton = document.createElement("button");
                    deleteButton.textContent = "Delete Post";
                    deleteButton.classList.add("delete-button");
                    deleteButton.addEventListener("click", async () => {
                        if (confirm("Are you sure you want to delete this post?")) {
                            try {
                                const deleteResponse = await fetch(`http://localhost:8000/api/posts/${postId}`, {
                                    method: "DELETE",
                                    headers: { "Authorization": "Bearer " + token },
                                });
        
                                if (deleteResponse.ok) {
                                    alert("Post deleted successfully.");
                                    window.location.href = "test.html";
                                } else {
                                    alert("Failed to delete post.");
                                }
                            } catch (error) {
                                console.error("Error deleting post:", error);
                                alert("Error deleting post.");
                            }
                        }
                    });
        
                    document.querySelector(".post-container").appendChild(deleteButton);
                }
            } catch (error) {
                console.error("Error loading post details:", error);
                alert("An error occurred while loading the post. Redirecting to the dashboard...");
                window.location.href = "test.html";
            }
        }
        

        // Load comments for the post
        async function loadComments() {
            const commentsListDiv = document.getElementById("commentsList");
            commentsListDiv.innerHTML = '<p>Loading comments...</p>';

            try {
                const response = await fetch(`http://localhost:8000/api/comments/${postId}`, {
                    method: "GET",
                    headers: { "Authorization": "Bearer " + token },
                });

                if (!response.ok) {
                    commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
                    return;
                }

                const comments = await response.json();
                const payload = decodeJWT(token); // Decode the token to get the username
                const currentUser = payload.username;

                commentsListDiv.innerHTML = '';

                if (comments.length === 0) {
                    commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
                } else {
                    comments.forEach(comment => {
                        const commentElement = document.createElement('div');
                        commentElement.classList.add('comment-item');
                        const commentDate = new Date(comment.created_at).toLocaleString();
                        commentElement.innerHTML = `
                            <p><strong>${comment.user}:</strong> ${comment.comment}</p>
                            <small>Posted on: ${commentDate}</small>
                        `;

                        // Add delete button if the current user is the owner
                        if (comment.user === currentUser) {
                            const deleteButton = document.createElement('button');
                            deleteButton.classList.add('delete-button');
                            deleteButton.textContent = 'Delete';
                            deleteButton.addEventListener('click', async () => {
                                if (confirm("Are you sure you want to delete this comment?")) {
                                    try {
                                        const deleteResponse = await fetch(`http://localhost:8000/api/comments/${comment.id}`, {
                                            method: "DELETE",
                                            headers: { "Authorization": "Bearer " + token },
                                        });

                                        if (deleteResponse.ok) {
                                            alert("Comment deleted successfully.");
                                            loadComments(postId, token);
                                        } else {
                                            alert("Failed to delete comment.");
                                        }
                                    } catch (error) {
                                        console.error("Error deleting comment:", error);
                                        alert("Error deleting comment.");
                                    }
                                }
                            });
                            commentElement.appendChild(deleteButton);
                        }

                        commentsListDiv.appendChild(commentElement);
                    });
                }
            } catch (error) {
                console.error("Error loading comments:", error);
                commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
            }
        }

        // Add a new comment
        document.getElementById("addCommentForm")?.addEventListener("submit", async (event) => {
            event.preventDefault();
            const commentContent = document.getElementById("commentContent").value.trim();

            if (!commentContent) {
                alert("Comment cannot be empty.");
                return;
            }

            try {
                const response = await fetch("http://localhost:8000/api/comments", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + token,
                    },
                    body: JSON.stringify({ postId: parseInt(postId, 10), comment: commentContent }),
                });

                if (!response.ok) {
                    alert("Failed to add comment.");
                    return;
                }

                alert("Comment added successfully!");
                document.getElementById("commentContent").value = ""; // Clear the input
                loadComments(); // Reload comments
            } catch (error) {
                console.error("Error adding comment:", error);
                alert("An error occurred while adding the comment.");
            }
        });

        // Back button functionality
        document.getElementById("backButton")?.addEventListener("click", () => {
            window.location.href = "test.html";
        });

        // Initial load
        loadPostDetails();
        loadComments();
    }
});

