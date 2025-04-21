
    const postId = new URLSearchParams(window.location.search).get("id");
    const token = sessionStorage.getItem("access_token");
    const isTokenExpired = (token) => {
        const payload = decodeJWT(token);
        return payload.exp * 1000 <= Date.now();
    };
    const decodeJWT = (token) => {
        const payload = token.split('.')[1];
        return JSON.parse(atob(payload));
    };

    if (!postId) {
        alert("Invalid post ID. Redirecting to the dashboard...");
        window.location.href = "main.html";
    }

    if (!token || isTokenExpired(token)) {
        alert("Your session has expired. Please log in again.");
        window.location.href = "login.html";
         
    }

    // Load post details
    async function loadPostDetails() {
        const postId = new URLSearchParams(window.location.search).get("id");
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
            const response = await fetch(`http://localhost:8000/api/posts/${postId}`, {
                method: "GET",
                headers: { "Authorization": "Bearer " + token },
            });
    
            if (!response.ok) {
                alert("Failed to load post details. Redirecting to the dashboard...");
                window.location.href = "main.html";
                 
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
        window.location.href = "main.html";
    });

    // Initial load
    loadPostDetails();
    loadComments();
