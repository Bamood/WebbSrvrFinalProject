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
                credentials: "include",
            });

            if (response.ok) {
                const data = await response.json();
                sessionStorage.setItem("access_token", data.access_token);
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
    
        const decodeJWT = (token) => {
            const payload = token.split('.')[1];
            return JSON.parse(atob(payload));
        };
    
        const payload = decodeJWT(token);
        const refreshTime = payload.exp * 1000 - Date.now() - 60000;
    
        if (refreshTime > 0) {
            window.refreshTimer = setTimeout(async () => {
                if (await refreshToken()) {
                    window.refreshTimer = null;
                    startAccessTokenRefreshTimer();
                }
            }, refreshTime);
        };
    };

    startAccessTokenRefreshTimer();

    document.getElementById("postForm")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const title = document.getElementById("postTitle").value.trim();
        const content = document.getElementById("postContent").value.trim();
        let token = sessionStorage.getItem("access_token");

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
            
            let response = await fetchWithCsrf("http://localhost:8000/api/posts", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + token,
                },
                body: JSON.stringify({ title, content }),
            });

            if (response.status === 400) {
                const errorData = await response.json();
                alert("Error: " + errorData.error);
                return;
            }

            if (response.status === 401 || response.status === 403) {
                if (await refreshToken()) {
                    token = sessionStorage.getItem("access_token");
                    response = await fetchWithCsrf("http://localhost:8000/api/posts", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + token,
                        },
                        body: JSON.stringify({ title, content }),
                    });
                }
            }

            if (response.ok) {
                document.getElementById("postTitle").value = "";
                document.getElementById("postContent").value = "";
                loadPosts();
            }
        } catch (error) {
            console.error("Error creating post:", error);
            alert("An error occurred while creating the post. Please try again.");
        }
    });

    document.getElementById("logoutButton")?.addEventListener("click", async () => {
        try {
       
            const response = await fetchWithCsrf("http://localhost:8000/api/accounts/logout", {
                method: "POST",
                credentials: "include",
            });

            if (response.ok) {
                sessionStorage.removeItem("access_token");
                window.location.href = "login.html";
            } else {
                alert("Failed to log out. Please try again.");
            }
        } catch (error) {
            console.error("Error during logout:", error);
            alert("An error occurred during logout. Please try again.");
        }
    });

    document.getElementById("accManagementButton")?.addEventListener("click", () => {
        window.location.href = "accManagement.html";
    });

    async function loadPosts() {
        const token = sessionStorage.getItem("access_token");
        const postsListDiv = document.getElementById("postsList");

        if (!postsListDiv) {
            return;
        }

        if (!token || isTokenExpired(token)) {
            postsListDiv.innerHTML = '<p>Please log in to see posts.</p>';
            return;
        }

        try {
            const response = await fetch("http://localhost:8000/api/posts", {
                method: "GET",
                headers: { "Authorization": "Bearer " + token },
                credentials: "include"
            });

            if (!response.ok) {
                postsListDiv.innerHTML = '<p>Could not load posts.</p>';
                return;
            }

            const posts = await response.json();

            postsListDiv.innerHTML = '';

            if (posts.length === 0) {
                postsListDiv.innerHTML = '<p>No posts yet.</p>';
                return;
            }

            posts.forEach(post => {
                const postElement = document.createElement('div');
                postElement.classList.add('post-item');
                postElement.style.cursor = "pointer";
                const createdDate = new Date(post.created).toLocaleString();
                postElement.innerHTML = `
                    <strong>${post.title}</strong> (by ${post.user})
                    <br>
                    <small>Created on: ${createdDate}</small>
                `;

                postElement.addEventListener('click', () => {
                    window.location.href = `post.html?id=${post.id}`;
                });

                postsListDiv.appendChild(postElement);
            });
        } catch (error) {
            console.error("Error loading posts:", error);
            postsListDiv.innerHTML = '<p>Error loading posts.</p>';
        }
    }

    if (window.location.pathname.endsWith("main.html")) {
        loadPosts();
    }

    if (window.location.pathname.endsWith("main.html")) {
        const accessToken = sessionStorage.getItem("access_token");

        if (!accessToken) {
            window.location.href = "login.html";
            return;
        }

        try {
            const payload = JSON.parse(atob(accessToken.split('.')[1]));
            const username = payload.username;
            document.getElementById("welcomeMessage").textContent = `Welcome, ${username}!`;
        } catch (error) {
            sessionStorage.removeItem("access_token");
            window.location.href = "login.html";
        }
    }
});
