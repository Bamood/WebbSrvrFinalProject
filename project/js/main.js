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
            const response = await fetch("http://localhost:8000/api/accounts/refresh-token", {
                method: "POST",
                credentials: "include",  //Include the refresh token cookie
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

    // Add event listener for the "Manage Account" button
    document.getElementById("accManagementButton")?.addEventListener("click", () => {
        window.location.href = "accManagement.html";
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

    // Ensure loadPosts is only called on main.html
    if (window.location.pathname.endsWith("main.html")) {
        loadPosts();
    }
    
    // Handle welcome message and redirection for main.html
    if (window.location.pathname.endsWith("main.html")) {
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
});

