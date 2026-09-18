// ==================================================
// WebShield Content Script
// ==================================================

console.log(
    "WebShield content.js loaded on:",
    window.location.href
);


// ==================================================
// ANALYZE PAGE
// ==================================================

function analyzePage() {

    try {

        console.log(
            "======================================"
        );

        console.log(
            "WebShield: ANALYZING PAGE"
        );

        console.log(
            "URL:",
            window.location.href
        );


        const forms =
            document.querySelectorAll("form");


        const passwordFields =
            document.querySelectorAll(
                'input[type="password"]'
            );


        const iframes =
            document.querySelectorAll("iframe");


        const links =
            document.querySelectorAll("a[href]");


        // ==================================================
        // EXTERNAL LINKS
        // ==================================================

        let externalLinks = 0;


        links.forEach(link => {

            try {

                const linkUrl =
                    new URL(
                        link.href,
                        window.location.href
                    );


                if (
                    linkUrl.hostname &&
                    linkUrl.hostname !==
                    window.location.hostname
                ) {

                    externalLinks++;

                }

            }

            catch (error) {

                // Ignore invalid links

            }

        });


        // ==================================================
        // EXTERNAL FORM ACTIONS
        // ==================================================

        let externalFormActions = 0;


        forms.forEach(form => {

            try {

                const action =
                    form.getAttribute("action");


                // Empty action means same page.
                if (!action) {
                    return;
                }


                const actionUrl =
                    new URL(
                        action,
                        window.location.href
                    );


                if (
                    actionUrl.hostname &&
                    actionUrl.hostname !==
                    window.location.hostname
                ) {

                    externalFormActions++;

                }

            }

            catch (error) {

                // Ignore invalid actions

            }

        });


        // ==================================================
        // PAGE DATA
        // ==================================================

        const pageData = {

            url:
                window.location.href,

            title:
                document.title,

            forms:
                forms.length,

            password_fields:
                passwordFields.length,

            iframes:
                iframes.length,

            external_links:
                externalLinks,

            external_form_actions:
                externalFormActions,

            https:
                window.location.protocol ===
                "https:"

        };


        console.log(
            "WebShield PAGE ANALYSIS:",
            pageData
        );


        // ==================================================
        // SEND TO BACKGROUND
        // ==================================================

        chrome.runtime.sendMessage({

            type:
                "PAGE_ANALYSIS",

            data:
                pageData

        })

        .then(() => {

            console.log(
                "WebShield: PAGE_ANALYSIS sent successfully"
            );

        })

        .catch(error => {

            console.error(
                "WebShield: Failed to send PAGE_ANALYSIS:",
                error
            );

        });

    }

    catch (error) {

        console.error(
            "WebShield: Page analysis failed:",
            error
        );

    }

}


// ==================================================
// BACKGROUND CAN REQUEST A FRESH ANALYSIS
// ==================================================

chrome.runtime.onMessage.addListener(
    (message, sender, sendResponse) => {

        if (
            message.type ===
            "REQUEST_PAGE_ANALYSIS"
        ) {

            console.log(
                "WebShield: Background requested fresh page analysis"
            );


            analyzePage();


            sendResponse({
                success: true
            });

        }

    }
);


// ==================================================
// INITIAL ANALYSIS
// ==================================================

if (
    document.readyState ===
    "loading"
) {

    document.addEventListener(
        "DOMContentLoaded",
        analyzePage
    );

}

else {

    analyzePage();

}