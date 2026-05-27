console.log("Extension loaded successfully");

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        const currentUrl = changeInfo.url;

        fetch("http://127.0.0.1:5000/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: currentUrl })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Backend Result:", data);

            if (data.risk_score > 40) {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png",
                    title: "⚠️ Phishing Alert",
                    message: "Risk Score: " + data.risk_score + "%\n" + data.url
                });
            }
        })
        .catch(error => {
            console.error("Fetch Error:", error);
        });
    }
});