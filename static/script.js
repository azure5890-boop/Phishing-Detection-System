document.addEventListener("DOMContentLoaded", () => {

    /* ================= DARK MODE ================= */
    const toggle = document.getElementById("darkModeToggle");
    const icon = document.getElementById("darkIcon");

    const savedDark = localStorage.getItem("dark") === "true";
    if (savedDark) {
        document.body.classList.add("dark");
        icon?.classList.replace("bi-moon", "bi-sun");
    }

    toggle?.addEventListener("click", () => {
        document.body.classList.toggle("dark");
        const isDark = document.body.classList.contains("dark");
        localStorage.setItem("dark", isDark);
        icon?.classList.toggle("bi-moon", !isDark);
        icon?.classList.toggle("bi-sun", isDark);
    });

    /* ================= ANALYZE BUTTON ================= */
    const scanForm = document.querySelector(".scanner form");
    const scanBtn = document.querySelector(".scanner button");

    scanForm?.addEventListener("submit", () => {
        scanBtn.textContent = "Analyzing...";
        scanBtn.classList.add("loading");
    });

    /* ================= TRUST SCORE ================= */
    const circle = document.querySelector(".progress");
    const scoreText = document.getElementById("scoreValue");

    if (circle && scoreText) {
        const score = Number(circle.dataset.score);
        const radius = 60;
        const circumference = 2 * Math.PI * radius;

        circle.style.strokeDasharray = circumference;
        circle.style.strokeDashoffset = circumference;

        let current = 0;
        const anim = setInterval(() => {
            current++;
            scoreText.textContent = current + "%";
            circle.style.strokeDashoffset =
                circumference - (current / 100) * circumference;
            if (current >= score) clearInterval(anim);
        }, 15);
    }

    /* ================= RISK METER ================= */
    const riskFill = document.getElementById("riskFill");
    const riskValue = document.getElementById("riskValue");

    if (circle && riskFill && riskValue) {
        const score = Number(circle.dataset.score);
        const finalRisk = Math.round((100 - score) / 10);

        let r = 0;
        const riskAnim = setInterval(() => {
            riskValue.textContent = r;
            riskFill.style.width = r * 10 + "%";

            if (r <= 3) riskFill.style.background = "#2e7d32";
            else if (r <= 6) riskFill.style.background = "#f9a825";
            else riskFill.style.background = "#c62828";

            if (r >= finalRisk) clearInterval(riskAnim);
            r++;
        }, 80);
    }

    /* ================= BAR GRAPHS ================= */
    document.querySelectorAll(".bar .fill").forEach((fill, i) => {
        const width = fill.style.getPropertyValue("--width");
        setTimeout(() => {
            fill.style.opacity = 1;
            fill.style.width = width;
        }, 300 + i * 200);
    });

    /* ================= CARD REVEAL ================= */
    document.querySelectorAll(".results-grid .card")
        .forEach((card, i) => {
            setTimeout(() => card.classList.add("show"), 300 + i * 200);
        });

});
