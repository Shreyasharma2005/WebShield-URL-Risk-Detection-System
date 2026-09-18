const tabAnalysis = {};
const tabResults = {};

console.log("WebShield extension loaded successfully");


// ======================================================
// INTERNAL PAGE CHECK
// ======================================================

function isInternalPage(url) {

    if (!url) {
        return true;
    }

    return (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("devtools://")
    );
}


// ======================================================
// PAGE LOAD
// ======================================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete") {
        return;
    }

    const url = tab.url;

    console.log("======================================");
    console.log("TAB LOADED:", url);
    console.log("TAB ID:", tabId);
    console.log("======================================");


    if (isInternalPage(url)) {

        console.log(
            "Skipping internal page:",
            url
        );

        return;
    }


    // --------------------------------------------------
    // IMPORTANT
    // Clear previous website's data
    // --------------------------------------------------

    delete tabAnalysis[tabId];
    delete tabResults[tabId];


    console.log(
        "Cleared previous analysis for tab:",
        tabId
    );


    // --------------------------------------------------
    // Ask content.js to analyze the current page
    // --------------------------------------------------

    requestPageAnalysis(tabId);


    // --------------------------------------------------
    // Retry because content.js may not be ready yet
    // --------------------------------------------------

    setTimeout(() => {

        requestPageAnalysis(tabId);

    }, 500);


    setTimeout(() => {

        requestPageAnalysis(tabId);

    }, 1500);

});


// ======================================================
// REQUEST PAGE ANALYSIS FROM CONTENT SCRIPT
// ======================================================

function requestPageAnalysis(tabId) {

    chrome.tabs.sendMessage(
        tabId,
        {
            type: "REQUEST_PAGE_ANALYSIS"
        },
        response => {

            if (chrome.runtime.lastError) {

                console.log(
                    "Content script not ready for tab",
                    tabId,
                    ":",
                    chrome.runtime.lastError.message
                );

                return;
            }

            console.log(
                "Content script responded:",
                response
            );
        }
    );

}


// ======================================================
// RECEIVE MESSAGES
// ======================================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {


        // ==================================================
        // PAGE ANALYSIS
        // ==================================================

        if (message.type === "PAGE_ANALYSIS") {

            if (!sender.tab || !sender.tab.id) {

                console.log(
                    "PAGE_ANALYSIS has no valid tab"
                );

                return;
            }


            const tabId = sender.tab.id;

            const pageData = message.data;


            console.log(
                "======================================"
            );

            console.log(
                "PAGE ANALYSIS RECEIVED:"
            );

            console.log(
                pageData
            );


            console.log(
                "TAB ID:",
                tabId
            );


            // ------------------------------------------------
            // Make sure this analysis belongs to this tab
            // ------------------------------------------------

            const actualTabUrl =
                sender.tab.url;


            console.log(
                "ACTUAL TAB URL:",
                actualTabUrl
            );


            console.log(
                "PAGE DATA URL:",
                pageData.url
            );


            if (isInternalPage(actualTabUrl)) {

                console.log(
                    "Ignoring analysis from internal page:",
                    actualTabUrl
                );

                return;
            }


            // ------------------------------------------------
            // Store page analysis
            // ------------------------------------------------

            tabAnalysis[tabId] = pageData;


            console.log(
                "STORED ANALYSIS FOR TAB:",
                tabId
            );

            console.log(
                tabAnalysis[tabId]
            );


            // ------------------------------------------------
            // Send to Flask
            // ------------------------------------------------

            analyzeWithBackend(
                actualTabUrl,
                pageData,
                tabId
            );


            return;
        }


        // ==================================================
        // POPUP REQUEST
        // ==================================================

        if (message.type === "GET_TAB_DATA") {

            const tabId = message.tabId;


            console.log(
                "======================================"
            );

            console.log(
                "POPUP REQUESTED DATA"
            );

            console.log(
                "TAB ID:",
                tabId
            );


            const analysis =
                tabAnalysis[tabId] || null;


            const result =
                tabResults[tabId] || null;


            console.log(
                "ANALYSIS FOUND:",
                analysis
            );


            console.log(
                "RESULT FOUND:",
                result
            );


            sendResponse({

                page_analysis: analysis,

                backend_result: result

            });


            return true;
        }

    }
);


// ======================================================
// SEND DATA TO FLASK
// ======================================================

function analyzeWithBackend(
    url,
    pageData,
    tabId
) {

    const requestData = {

        url: url,

        page_analysis: pageData

    };


    console.log(
        "======================================"
    );

    console.log(
        "SENDING TO WEBSHIELD BACKEND:"
    );

    console.log(
        requestData
    );


    fetch(
        "http://127.0.0.1:5000/analyze",
        {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(requestData)

        }
    )

    .then(response => {

        console.log(
            "BACKEND HTTP STATUS:",
            response.status
        );


        if (!response.ok) {

            throw new Error(
                "Backend returned status " +
                response.status
            );

        }


        return response.json();

    })

    .then(data => {

        console.log(
            "======================================"
        );

        console.log(
            "WEBSHIELD BACKEND RESULT:"
        );

        console.log(
            data
        );


        console.log(
            "RISK SCORE:",
            data.risk_score
        );


        console.log(
            "RISK LEVEL:",
            data.risk_level
        );


        console.log(
            "RISK BREAKDOWN:",
            data.risk_breakdown
        );


        if (data.risk_breakdown) {

            console.log(
                "ML RISK:",
                data.risk_breakdown.ml_score
            );

            console.log(
                "URL RISK:",
                data.risk_breakdown.url_risk
            );

            console.log(
                "DOMAIN RISK:",
                data.risk_breakdown.domain_risk
            );

            console.log(
                "PAGE RISK:",
                data.risk_breakdown.page_risk
            );

        }


        console.log(
            "REASONS:",
            data.reasons
        );


        // --------------------------------------------------
        // Store backend result for THIS tab
        // --------------------------------------------------

        tabResults[tabId] = data;


        console.log(
            "STORED BACKEND RESULT FOR TAB:",
            tabId
        );


        // ==================================================
        // HIGH RISK
        // ==================================================

        if (data.risk_score >= 60) {

            console.log(
                "HIGH RISK! Creating notification"
            );


            chrome.notifications.create(
                "webshield-high-" + Date.now(),

                {
                    type: "basic",

                    iconUrl: "icon.png",

                    title:
                        "WebShield HIGH RISK",

                    message:
                        "Phishing website detected!\n" +
                        "Risk Score: " +
                        data.risk_score +
                        "%",

                    priority: 2
                },

                notificationId => {

                    if (chrome.runtime.lastError) {

                        console.error(
                            "NOTIFICATION ERROR:",
                            chrome.runtime.lastError.message
                        );

                    } else {

                        console.log(
                            "NOTIFICATION CREATED:",
                            notificationId
                        );

                    }

                }
            );

        }


        // ==================================================
        // SUSPICIOUS
        // ==================================================

        else if (data.risk_score >= 30) {

            console.log(
                "SUSPICIOUS! Creating warning"
            );


            chrome.notifications.create(
                "webshield-warning-" + Date.now(),

                {
                    type: "basic",

                    iconUrl: "icon.png",

                    title:
                        "WebShield Warning",

                    message:
                        "Suspicious website detected.\n" +
                        "Risk Score: " +
                        data.risk_score +
                        "%",

                    priority: 1
                },

                notificationId => {

                    if (chrome.runtime.lastError) {

                        console.error(
                            "NOTIFICATION ERROR:",
                            chrome.runtime.lastError.message
                        );

                    } else {

                        console.log(
                            "WARNING NOTIFICATION CREATED:",
                            notificationId
                        );

                    }

                }
            );

        }


        // ==================================================
        // SAFE
        // ==================================================

        else {

            console.log(
                "WEBSITE SAFE"
            );

        }

    })

    .catch(error => {

        console.error(
            "WEBSHIELD FETCH ERROR:",
            error
        );

    });

}


// ======================================================
// TAB CLOSED
// ======================================================

chrome.tabs.onRemoved.addListener(tabId => {

    delete tabAnalysis[tabId];

    delete tabResults[tabId];


    console.log(
        "Cleared WebShield data for tab:",
        tabId
    );

});