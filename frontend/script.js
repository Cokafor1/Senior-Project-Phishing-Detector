function checkURL() {

    const url = document.getElementById("urlInput").value;

    if (url === "") {
        document.getElementById("result").innerText = "Please enter a URL.";
        return;
    }

    if (url.includes("login") || url.includes("verify") || url.includes("secure")) {
        document.getElementById("result").innerText = "⚠️ Warning: This URL might be suspicious.";
    } else {
        document.getElementById("result").innerText = "✅ This URL appears safe.";
    }
}
