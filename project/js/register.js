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
        const data = await response.json();
        alert("Error: " + (data.error || "Unknown error"));
    }
});

document.getElementById("loginRedirectButton")?.addEventListener("click", () => {
    window.location.href = "login.html";
});