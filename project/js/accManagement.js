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
                console.log("Timer restarted.");
            }
        }, refreshTime);
    }
}

startAccessTokenRefreshTimer();

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

document.getElementById("backToDashboardButton")?.addEventListener("click", () => {
    window.location.href = "main.html";
});

});
