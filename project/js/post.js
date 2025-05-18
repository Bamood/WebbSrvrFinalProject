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

    const postId = new URLSearchParams(window.location.search).get("id");
    const token = sessionStorage.getItem("access_token");

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
            const response = await fetchWithCsrf("http://localhost:8000/api/accounts/refresh-token", {
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

    if (!postId) {
        alert("Invalid post ID. Redirecting to the dashboard...");
        window.location.href = "main.html";
    }

    if (!token || isTokenExpired(token)) {
        alert("Your session has expired. Please log in again.");
        window.location.href = "login.html";
    }

    async function loadPostDetails() {
        const token = sessionStorage.getItem("access_token");

        if (!postId) {
            alert("Invalid post ID. Redirecting to the dashboard...");
            window.location.href = "main.html";
        }

        if (!token || isTokenExpired(token)) {
            alert("Your session has expired. Please log in again.");
            window.location.href = "login.html";
        }

        try {
            const response = await fetchWithCsrf(`http://localhost:8000/api/posts/${postId}`, {
                method: "GET",
                headers: { "Authorization": "Bearer " + token },
            });

            if (!response.ok) {
                alert("Failed to load post details. Redirecting to the dashboard...");
                window.location.href = "main.html";
            }

            const post = await response.json();
            const payload = decodeJWT(token); 
            const currentUser = payload.username;

            document.getElementById("postTitle").textContent = post.title;
            document.getElementById("postContent").textContent = post.content;

            if (post.user === currentUser) {
                const deleteButton = document.createElement("button");
                deleteButton.textContent = "Delete Post";
                deleteButton.classList.add("delete-button");
                deleteButton.addEventListener("click", async () => {
                    if (confirm("Are you sure you want to delete this post?")) {
                        try {
                            const deleteResponse = await fetchWithCsrf(`http://localhost:8000/api/posts/${postId}`, {
                                method: "DELETE",
                                headers: { 
                                    "Authorization": "Bearer " + token,
                                },
                            });

                            if (deleteResponse.ok) {
                                window.location.href = "main.html";
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
            window.location.href = "main.html";
        }
    }

    async function loadComments() {
        const commentsListDiv = document.getElementById("commentsList");
        commentsListDiv.innerHTML = '<p>Loading comments...</p>';

        try {
            const response = await fetchWithCsrf(`http://localhost:8000/api/comments/${postId}`, {
                method: "GET",
                headers: { "Authorization": "Bearer " + token },
            });

            if (!response.ok) {
                commentsListDiv.innerHTML = '<p>No comments yet. Be the first!</p>';
            }

            const comments = await response.json();
            const payload = decodeJWT(token);
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

                    if (comment.user === currentUser) {
                        const deleteButton = document.createElement('button');
                        deleteButton.classList.add('delete-button');
                        deleteButton.textContent = 'Delete';
                        deleteButton.addEventListener('click', async () => {
                            if (confirm("Are you sure you want to delete this comment?")) {
                                try {
                                    const deleteResponse = await fetchWithCsrf(`http://localhost:8000/api/comments/${comment.id}`, {
                                        method: "DELETE",
                                        headers: {
                                            "Authorization": "Bearer " + token,
                                        },
                                    });

                                    if (deleteResponse.ok) {
                                        loadComments();
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

    document.getElementById("addCommentForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const commentContent = document.getElementById("commentContent").value.trim();

        if (!commentContent) {
            alert("Comment cannot be empty.");
            return;
        }

        try {
            const response = await fetchWithCsrf("http://localhost:8000/api/comments", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + token,
                },
                body: JSON.stringify({ postId: parseInt(postId, 10), comment: commentContent }),
            });

            if (!response.ok) {
                alert("Failed to add comment.");
            }
            document.getElementById("commentContent").value = "";
            loadComments();
        } catch (error) {
            console.error("Error adding comment:", error);
            alert("An error occurred while adding the comment.");
        }
    });

    document.getElementById("backButton")?.addEventListener("click", () => {
        window.location.href = "main.html";
    });

    loadPostDetails();
    loadComments();
});