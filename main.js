/**
 * main.js — ThreatLens frontend  v5  (Premium Dark Cybersecurity SaaS)
 *
 * SECURITY RULES (never relax these):
 * - All user-supplied content is rendered via textContent, setAttribute,
 *   or createElement — never via innerHTML or insertAdjacentHTML.
 * - No eval(), no new Function(), no document.write().
 * - The URL from the result payload (url_display) is shown only as text.
 *
 * Sections:
 *  1. Constants & DOM refs
 *  2. Full-page background particle canvas
 *  3. Hero canvas grid animation
 *  4. Nav (mobile hamburger + scroll)
 *  5. Form handling
 *  6. API call
 *  7. State management
 *  8. Result rendering
 *  9. Score ring + progress bar animation
 * 10. Indicator cards (staggered)
 * 11. Recommendation list
 * 12. Loading-step cycling
 * 13. Scroll-in entrance animations (IntersectionObserver)
 * 14. Utility helpers
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// 1. CONSTANTS & DOM REFS
// ─────────────────────────────────────────────────────────────────────────────

const RING_R       = 50;
const RING_CIRCUMF = 2 * Math.PI * RING_R;  // ≈ 314.16

const RISK_COLOURS = {
  low:    "#10b981",
  medium: "#f59e0b",
  high:   "#ef4444",
};

// Resolved once after DOMContentLoaded
let $ = {};

// ─────────────────────────────────────────────────────────────────────────────
// 2. ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  resolveRefs();
  initAmbientBlobs();       // drifting soft-light blobs behind all content
  initCircuitOverlay();     // CSS circuit lines + traveling pulse dots
  initPageCanvas();         // full-page floating particles (background layer)
  initCanvas();             // hero section animated grid
  initNav();
  initNavScroll();
  initForm();
  initSampleButtons();
  initAnalyzeAnotherBtn();
  initRetryBtn();
  initResultActionBtns();   // Copy Result + Download Report buttons
  initEntranceObserver();
  initButtonRipple();       // press-ripple on all .btn elements
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. RESOLVE DOM REFERENCES
// ─────────────────────────────────────────────────────────────────────────────

function resolveRefs() {
  $ = {
    // Nav
    burger:           document.getElementById("burger"),
    mobileMenu:       document.getElementById("mobile-menu"),

    // Form
    form:             document.getElementById("analyze-form"),
    urlInput:         document.getElementById("url-input"),
    submitBtn:        document.getElementById("submit-btn"),
    clearBtn:         document.getElementById("clear-btn"),
    inputRow:         document.getElementById("input-row"),
    urlError:         document.getElementById("url-error"),

    // States
    resultsArea:      document.getElementById("results-area"),
    stateLoading:     document.getElementById("state-loading"),
    stateError:       document.getElementById("state-error"),
    stateResult:      document.getElementById("state-result"),
    errorMessage:     document.getElementById("error-message"),

    // Result elements
    resultScore:      document.getElementById("result-score"),
    ringWrap:         document.querySelector(".ring-wrap"),
    scoreRingFill:    document.getElementById("score-ring-fill"),
    resultRiskBadge:  document.getElementById("result-risk-badge"),
    resultHeading:    document.getElementById("result-heading"),
    resultSummary:    document.getElementById("result-summary"),
    resultBarFill:    document.getElementById("result-bar-fill"),
    resultBarLabel:   document.getElementById("result-bar-label"),
    indicatorsGrid:   document.getElementById("indicators-grid"),
    indSummaryBadge:  document.getElementById("ind-summary-badge"),
    recsList:         document.getElementById("recommendations-list"),
    resultDisclaimer: document.getElementById("result-disclaimer"),

    // Buttons
    analyzeAnotherBtn:  document.getElementById("analyze-another-btn"),
    retryBtn:           document.getElementById("retry-btn"),
    resultCopyBtn:      document.getElementById("result-copy-btn"),
    resultDownloadBtn:  document.getElementById("result-download-btn"),

    // Loading steps
    loadingSteps:     document.querySelectorAll(".loading__step"),
  };

  // Initialise ring dasharray
  if ($.scoreRingFill) {
    $.scoreRingFill.style.strokeDasharray  = RING_CIRCUMF;
    $.scoreRingFill.style.strokeDashoffset = RING_CIRCUMF;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. FULL-PAGE BACKGROUND PARTICLE CANVAS
//    Renders soft floating particles + connecting lines behind all content.
//    Responds subtly to mouse movement for depth.
// ─────────────────────────────────────────────────────────────────────────────

function initPageCanvas() {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  // Create and insert the canvas as the first body child
  const canvas = document.createElement("canvas");
  canvas.id = "page-canvas";
  canvas.setAttribute("aria-hidden", "true");
  document.body.insertBefore(canvas, document.body.firstChild);

  const ctx = canvas.getContext("2d");
  let w, h, animId;

  // Mouse tracking for subtle parallax
  let mouseX = -9999, mouseY = -9999;
  document.addEventListener("mousemove", (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  }, { passive: true });

  const PARTICLE_COUNT = 75;
  const CONNECT_DIST   = 130;
  const particles      = [];

  function resize() {
    w = canvas.width  = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }

  function spawnParticle() {
    // Pick a random colour from the palette
    const palette = [
      { r: 0,   g: 229, b: 255 },   // cyan
      { r: 124, g: 58,  b: 237 },   // violet
      { r: 41,  g: 121, b: 255 },   // electric blue
    ];
    const c = palette[Math.floor(Math.random() * palette.length)];
    return {
      x:    Math.random() * w,
      y:    Math.random() * h,
      vx:   (Math.random() - .5) * .18,
      vy:   (Math.random() - .5) * .18,
      r:    Math.random() * 1.6 + .5,
      a:    Math.random() * .55 + .08,
      cr:   c.r, cg: c.g, cb: c.b,
      life: 1,
    };
  }

  function initParticles() {
    particles.length = 0;
    for (let i = 0; i < PARTICLE_COUNT; i++) particles.push(spawnParticle());
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);

    // Faint digital grid
    ctx.strokeStyle = "rgba(0,229,255,0.024)";
    ctx.lineWidth   = 1;
    ctx.beginPath();
    const GRID = 56;
    for (let x = 0; x < w; x += GRID) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
    for (let y = 0; y < h; y += GRID) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
    ctx.stroke();

    // Grid intersection dots
    ctx.fillStyle = "rgba(0,229,255,0.04)";
    for (let x = 0; x < w; x += GRID) {
      for (let y = 0; y < h; y += GRID) {
        ctx.beginPath();
        ctx.arc(x, y, 1, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // Move and draw particles
    for (const p of particles) {
      // Very slight attraction toward mouse
      const dx = mouseX - p.x;
      const dy = mouseY - p.y;
      const dist = Math.hypot(dx, dy);
      if (dist < 350 && dist > 1) {
        p.vx += (dx / dist) * 0.0008;
        p.vy += (dy / dist) * 0.0008;
      }

      // Speed cap
      const speed = Math.hypot(p.vx, p.vy);
      if (speed > 0.55) { p.vx *= 0.55 / speed; p.vy *= 0.55 / speed; }

      p.x += p.vx;
      p.y += p.vy;

      // Wrap around edges
      if (p.x < 0) p.x = w; if (p.x > w) p.x = 0;
      if (p.y < 0) p.y = h; if (p.y > h) p.y = 0;

      // Draw particle with glow
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${p.cr},${p.cg},${p.cb},${p.a})`;
      ctx.fill();
    }

    // Connect nearby particles
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const pi = particles[i], pj = particles[j];
        const ddx = pi.x - pj.x;
        const ddy = pi.y - pj.y;
        const d = Math.hypot(ddx, ddy);
        if (d < CONNECT_DIST) {
          const alpha = (1 - d / CONNECT_DIST) * 0.055;
          ctx.beginPath();
          ctx.moveTo(pi.x, pi.y);
          ctx.lineTo(pj.x, pj.y);
          // Blend colours of the two endpoints
          ctx.strokeStyle = `rgba(${Math.round((pi.cr + pj.cr) / 2)},${Math.round((pi.cg + pj.cg) / 2)},${Math.round((pi.cb + pj.cb) / 2)},${alpha})`;
          ctx.lineWidth = .5;
          ctx.stroke();
        }
      }
    }

    animId = requestAnimationFrame(draw);
  }

  window.addEventListener("resize", () => { resize(); initParticles(); }, { passive: true });
  resize();
  initParticles();
  animId = requestAnimationFrame(draw);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. HERO CANVAS GRID
//    Denser, brighter hero-specific animation layered above the page canvas.
// ─────────────────────────────────────────────────────────────────────────────

function initCanvas() {
  const canvas = document.getElementById("hero-canvas");
  if (!canvas) return;

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const ctx = canvas.getContext("2d");
  let w, h, animId;

  function resize() {
    w = canvas.width  = canvas.offsetWidth;
    h = canvas.height = canvas.offsetHeight;
  }

  const GRID = 56;
  const DOTS = [];
  const DOT_COUNT = 70;

  function initDots() {
    DOTS.length = 0;
    for (let i = 0; i < DOT_COUNT; i++) {
      DOTS.push({
        x:  Math.random() * w,
        y:  Math.random() * h,
        vx: (Math.random() - .5) * .28,
        vy: (Math.random() - .5) * .28,
        r:  Math.random() * 1.8 + .5,
        a:  Math.random() * .6 + .1,
        // Random cyan/violet/blue
        hue: [
          [0, 229, 255],
          [124, 58, 237],
          [82, 180, 255],
        ][Math.floor(Math.random() * 3)],
      });
    }
  }

  function draw(ts) {
    ctx.clearRect(0, 0, w, h);

    // Grid lines — slightly brighter than page canvas
    ctx.strokeStyle = "rgba(0,229,255,0.042)";
    ctx.lineWidth   = 1;
    ctx.beginPath();
    for (let x = 0; x < w; x += GRID) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
    for (let y = 0; y < h; y += GRID) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
    ctx.stroke();

    // Intersection crosshair hints
    for (let x = GRID; x < w; x += GRID) {
      for (let y = GRID; y < h; y += GRID) {
        ctx.strokeStyle = "rgba(0,229,255,0.06)";
        ctx.lineWidth   = .5;
        ctx.beginPath();
        ctx.moveTo(x - 3, y); ctx.lineTo(x + 3, y);
        ctx.moveTo(x, y - 3); ctx.lineTo(x, y + 3);
        ctx.stroke();
      }
    }

    // Moving dots
    for (const d of DOTS) {
      d.x += d.vx; d.y += d.vy;
      if (d.x < 0) d.x = w; if (d.x > w) d.x = 0;
      if (d.y < 0) d.y = h; if (d.y > h) d.y = 0;

      const [r, g, b] = d.hue;

      // Glow halo
      const grd = ctx.createRadialGradient(d.x, d.y, 0, d.x, d.y, d.r * 4);
      grd.addColorStop(0, `rgba(${r},${g},${b},${d.a * .35})`);
      grd.addColorStop(1, `rgba(${r},${g},${b},0)`);
      ctx.beginPath();
      ctx.arc(d.x, d.y, d.r * 4, 0, Math.PI * 2);
      ctx.fillStyle = grd;
      ctx.fill();

      // Core dot
      ctx.beginPath();
      ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${r},${g},${b},${d.a})`;
      ctx.fill();
    }

    // Connect nearby dots
    for (let i = 0; i < DOTS.length; i++) {
      for (let j = i + 1; j < DOTS.length; j++) {
        const ddx = DOTS[i].x - DOTS[j].x;
        const ddy = DOTS[i].y - DOTS[j].y;
        const dist = Math.hypot(ddx, ddy);
        if (dist < 100) {
          ctx.beginPath();
          ctx.moveTo(DOTS[i].x, DOTS[i].y);
          ctx.lineTo(DOTS[j].x, DOTS[j].y);
          ctx.strokeStyle = `rgba(0,229,255,${(1 - dist / 100) * .07})`;
          ctx.lineWidth = .7;
          ctx.stroke();
        }
      }
    }

    animId = requestAnimationFrame(draw);
  }

  const ro = new ResizeObserver(() => { resize(); initDots(); });
  ro.observe(canvas.parentElement || document.body);
  resize();
  initDots();
  animId = requestAnimationFrame(draw);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. NAV (mobile hamburger)
// ─────────────────────────────────────────────────────────────────────────────

function initNav() {
  const { burger, mobileMenu } = $;
  if (!burger || !mobileMenu) return;

  burger.addEventListener("click", () => {
    const expanded = burger.getAttribute("aria-expanded") === "true";
    burger.setAttribute("aria-expanded", String(!expanded));
    mobileMenu.hidden = expanded;
  });

  // Close when a nav link is tapped
  document.querySelectorAll("[data-close-nav]").forEach(link => {
    link.addEventListener("click", () => {
      burger.setAttribute("aria-expanded", "false");
      mobileMenu.hidden = true;
    });
  });

  // Close on outside click
  document.addEventListener("click", (e) => {
    if (!burger.contains(e.target) && !mobileMenu.contains(e.target)) {
      burger.setAttribute("aria-expanded", "false");
      mobileMenu.hidden = true;
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. NAV SCROLL — adds .nav--scrolled + highlights active link
// ─────────────────────────────────────────────────────────────────────────────

function initNavScroll() {
  const nav = document.querySelector(".nav");
  if (!nav) return;

  const links = document.querySelectorAll(".nav__link[href^='#']");

  function onScroll() {
    // Scrolled style
    nav.classList.toggle("nav--scrolled", window.scrollY > 20);

    // Active link: highlight the section whose top is nearest/above viewport mid
    const mid = window.scrollY + window.innerHeight * 0.35;
    let active = null;
    document.querySelectorAll("section[id], main[id]").forEach(sec => {
      if (sec.offsetTop <= mid) active = sec.id;
    });
    links.forEach(l => {
      const href = l.getAttribute("href").slice(1);
      l.classList.toggle("active", href === active);
    });
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. FORM HANDLING
// ─────────────────────────────────────────────────────────────────────────────

function initForm() {
  const { form, urlInput, clearBtn } = $;
  if (!form) return;

  form.addEventListener("submit", handleSubmit);

  // Show/hide clear button
  urlInput.addEventListener("input", () => {
    clearBtn.hidden = urlInput.value.length === 0;
    clearInputError();
  });

  clearBtn.addEventListener("click", () => {
    urlInput.value   = "";
    clearBtn.hidden  = true;
    clearInputError();
    urlInput.focus();
    hideAllResultStates();
  });
}

// Maximum time (ms) to wait for the server to respond before aborting.
const FETCH_TIMEOUT_MS = 15_000;

async function handleSubmit(e) {
  e.preventDefault();
  clearInputError();

  const raw = $.urlInput.value.trim();

  // Client-side pre-validation (server always validates too)
  if (!raw) {
    showInputError("Please enter a URL before submitting.");
    $.urlInput.focus();
    return;
  }
  if (raw.length < 4) {
    showInputError("URL is too short.");
    return;
  }
  if (raw.length > 2083) {
    showInputError("URL exceeds maximum length (2083 characters).");
    return;
  }
  const lower = raw.toLowerCase();
  if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
    showInputError("Only http:// and https:// URLs are supported.");
    return;
  }

  // Clean up any previous result state
  if ($.ringWrap) $.ringWrap.classList.remove("ring-breathing");
  if ($.stateResult) delete $.stateResult.dataset.risk;

  // Enter loading state
  setBtnLoading(true);
  showState("loading");
  const stepTimer = cycleLoadingSteps();

  // AbortController lets us cancel the fetch if the server takes too long.
  const controller = new AbortController();
  const timeoutId  = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch("/api/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: raw }),
      signal:  controller.signal,
    });

    clearInterval(stepTimer);
    clearTimeout(timeoutId);

    let data;
    try {
      data = await res.json();
    } catch {
      showState("error", "The server returned an unexpected response. Please try again.");
      return;
    }

    if (!res.ok) {
      const msg = (data && typeof data.error === "string")
        ? data.error
        : `Server error (${res.status}). Please try again.`;
      showState("error", msg);
      return;
    }

    renderResult(data);

  } catch (err) {
    clearInterval(stepTimer);
    clearTimeout(timeoutId);
    if (err && err.name === "AbortError") {
      showState("error", "The request timed out. The server may be busy — please try again.");
    } else {
      showState("error", "Network error — check your connection and try again.");
    }
  } finally {
    setBtnLoading(false);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. SAMPLE BUTTONS
// ─────────────────────────────────────────────────────────────────────────────

function initSampleButtons() {
  // Selects both old .sample class and new .db-sample class used by dashboard layout
  document.querySelectorAll(".sample[data-url], .db-sample[data-url]").forEach(btn => {
    btn.addEventListener("click", () => {
      const url = btn.getAttribute("data-url");
      if (!url) return;
      $.urlInput.value   = url;
      $.clearBtn.hidden  = false;
      clearInputError();
      // Scroll scanner into view and focus input
      document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "center" });
      $.urlInput.focus();
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. ANALYZE ANOTHER / RETRY
// ─────────────────────────────────────────────────────────────────────────────

function initAnalyzeAnotherBtn() {
  const btn = $.analyzeAnotherBtn;
  if (!btn) return;
  btn.addEventListener("click", () => {
    hideAllResultStates();
    $.urlInput.value  = "";
    $.clearBtn.hidden = true;
    clearInputError();
    $.urlInput.focus();
    document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth" });
  });
}

function initRetryBtn() {
  const btn = $.retryBtn;
  if (!btn) return;
  btn.addEventListener("click", () => {
    hideAllResultStates();
    $.urlInput.focus();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. STATE MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {"loading"|"error"|"result"} which
 * @param {string} [errorMsg]
 */
function showState(which, errorMsg = "") {
  $.stateLoading.hidden = which !== "loading";
  $.stateError.hidden   = which !== "error";
  $.stateResult.hidden  = which !== "result";

  if (which === "error" && errorMsg) {
    $.errorMessage.textContent = errorMsg;
  }

  if (which !== "loading") {
    resetLoadingSteps();
    removeSweepLine();
  }

  // Inject sweep line + readout while loading
  if (which === "loading") {
    injectSweepLine();
  }

  // Scroll the results area into view for keyboard/screen-reader users
  if (which !== "loading") {
    requestAnimationFrame(() => {
      $.resultsArea.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }
}

function hideAllResultStates() {
  $.stateLoading.hidden = true;
  $.stateError.hidden   = true;
  $.stateResult.hidden  = true;
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. RENDER RESULT
// ─────────────────────────────────────────────────────────────────────────────

function renderResult(data) {
  const score      = typeof data.score      === "number" ? data.score      : 0;
  const riskLevel  = (typeof data.risk_level === "string" && ["low","medium","high"].includes(data.risk_level))
                     ? data.risk_level : "low";
  const riskLabel  = typeof data.risk_label === "string" ? data.risk_label : "";
  const urlDisplay = typeof data.url_display=== "string" ? data.url_display: "";
  const summary    = typeof data.summary    === "string" ? data.summary    : "";
  const indicators = Array.isArray(data.indicators)      ? data.indicators  : [];
  const recs       = Array.isArray(data.recommendations) ? data.recommendations : [];
  const disclaimer = typeof data.disclaimer === "string" ? data.disclaimer : "";
  const triggered  = typeof data.triggered_count === "number" ? data.triggered_count : 0;

  // Risk badge
  $.resultRiskBadge.textContent = riskLabel;
  $.resultRiskBadge.className   = `risk-badge risk-badge--${riskLevel}`;

  // Ring wrap — swap color class so CSS glow + score color update
  if ($.ringWrap) {
    $.ringWrap.className = `ring-wrap ring-wrap--${riskLevel}`;
  }

  // URL (textContent — never innerHTML)
  $.resultHeading.textContent = urlDisplay;

  // Summary
  $.resultSummary.textContent = summary;

  // Disclaimer
  $.resultDisclaimer.textContent = disclaimer;

  // Indicators summary badge
  $.indSummaryBadge.textContent =
    `${triggered} of ${indicators.length} rules triggered`;

  const colour = RISK_COLOURS[riskLevel] || RISK_COLOURS.low;

  // Tag the result container with the risk level for CSS cascade colouring
  if ($.stateResult) $.stateResult.dataset.risk = riskLevel;

  // Show the result pane first so animation plays correctly
  showState("result");

  // Animate ring after paint
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      animateRing(score, colour);
      animateBar(score, colour, riskLabel);
    });
  });

  // Render sub-sections
  renderIndicators(indicators, riskLevel);
  renderRecommendations(recs);

  // Move keyboard focus to the result region
  $.stateResult.setAttribute("tabindex", "-1");
  $.stateResult.focus({ preventScroll: true });

  // Notify dashboard-ui.js so it can update stat cards, donut, sparkline, recent scans
  // Full payload is included so dashboard-ui can power report download & rich copy.
  document.dispatchEvent(new CustomEvent("threatlens:result", {
    detail: {
      score,
      risk_level:   riskLevel,
      risk_label:   riskLabel,
      url_display:  urlDisplay,
      summary,
      indicators,
      recommendations: recs,
      disclaimer,
    },
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. SCORE RING + PROGRESS BAR
// ─────────────────────────────────────────────────────────────────────────────

function animateRing(score, colour) {
  const fill  = $.scoreRingFill;
  const numEl = $.resultScore;
  if (!fill) return;

  const offset = RING_CIRCUMF - (score / 100) * RING_CIRCUMF;
  fill.style.stroke           = colour;
  fill.style.strokeDashoffset = offset;

  // Add breathing animation to the ring wrap (removed on next scan)
  if ($.ringWrap) {
    $.ringWrap.classList.add("ring-breathing");
  }

  // Counter animation — ease-out-cubic
  const duration = 1100;
  const start    = performance.now();
  function tick(now) {
    const t     = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    numEl.textContent = Math.round(score * eased);
    if (t < 1) requestAnimationFrame(tick);
    else numEl.textContent = score;
  }
  requestAnimationFrame(tick);
}

function animateBar(score, colour, label) {
  const fill = $.resultBarFill;
  const lbl  = $.resultBarLabel;
  if (!fill) return;
  requestAnimationFrame(() => {
    fill.style.width      = `${score}%`;
    fill.style.background = colour;
  });
  if (lbl) lbl.textContent = label;
}

// ─────────────────────────────────────────────────────────────────────────────
// 14. INDICATOR CARDS (staggered entrance)
// ─────────────────────────────────────────────────────────────────────────────

function renderIndicators(indicators, riskLevel) {
  const grid = $.indicatorsGrid;
  if (!grid) return;

  // Clear previous children
  while (grid.firstChild) grid.removeChild(grid.firstChild);

  // Sort: triggered first, then by weight descending
  const sorted = [...indicators].sort((a, b) => {
    if (a.triggered !== b.triggered) return a.triggered ? -1 : 1;
    return (b.weight || 0) - (a.weight || 0);
  });

  sorted.forEach((ind, i) => {
    const card = buildIndicatorCard(ind);
    card.style.animationDelay = `${i * 40}ms`;
    grid.appendChild(card);
  });
}

/**
 * Build a single indicator card using DOM API only — no innerHTML.
 */
function buildIndicatorCard(ind) {
  const triggered   = !!ind.triggered;
  const name        = safeStr(ind.name);
  const explanation = safeStr(ind.explanation);
  const weight      = ind.weight || 0;

  const card = el("div");
  card.className = "ind-card" + (triggered ? " ind-card--triggered" : "");
  card.setAttribute("role", "listitem");

  // Top row
  const top = el("div");
  top.className = "ind-card__top";

  const nameEl = el("span");
  nameEl.className   = "ind-card__name";
  nameEl.textContent = name;

  const right = el("div");
  right.className = "ind-card__right";

  const status = el("span");
  status.className   = "ind-card__status";
  status.textContent = triggered ? "Triggered" : "Clear";

  const wt = el("span");
  wt.className   = "ind-card__weight";
  wt.textContent = triggered ? `+${weight}` : "–";

  right.append(status, wt);
  top.append(nameEl, right);

  // Explanation
  const body = el("p");
  body.className   = "ind-card__body";
  body.textContent = explanation;

  card.append(top, body);
  return card;
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. RECOMMENDATIONS
// ─────────────────────────────────────────────────────────────────────────────

const REC_ICONS = ["🔎", "🛡️", "⚠️", "🔒", "📞", "💡"];

function renderRecommendations(recs) {
  const list = $.recsList;
  if (!list) return;
  while (list.firstChild) list.removeChild(list.firstChild);

  recs.forEach((text, i) => {
    const li = el("li");
    li.className = "recs__item";
    li.setAttribute("role", "listitem");

    const icon = el("span");
    icon.className         = "recs__icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent       = REC_ICONS[i % REC_ICONS.length];

    const span = el("span");
    span.textContent = safeStr(text);

    li.append(icon, span);
    list.appendChild(li);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// 16. LOADING STEP CYCLE
// ─────────────────────────────────────────────────────────────────────────────

function cycleLoadingSteps() {
  const steps = $.loadingSteps;
  if (!steps || steps.length === 0) return null;

  let current = 0;
  steps.forEach((s, i) => s.classList.toggle("active", i === 0));

  return setInterval(() => {
    if (current < steps.length - 1) {
      steps[current].classList.remove("active");
      current++;
      steps[current].classList.add("active");
    }
  }, 380);
}

function resetLoadingSteps() {
  $.loadingSteps.forEach((s, i) => s.classList.toggle("active", i === 0));
}

// ─────────────────────────────────────────────────────────────────────────────
// 17. SCROLL-IN ENTRANCE (IntersectionObserver)
// ─────────────────────────────────────────────────────────────────────────────

function initEntranceObserver() {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  if (!("IntersectionObserver" in window)) return;

  const targets = document.querySelectorAll(
    ".feature, .step, .priv-block, .db-stat-card, .db-info-card"
  );

  // Start invisible
  targets.forEach(t => {
    t.style.opacity    = "0";
    t.style.transform  = "translateY(18px)";
    t.style.transition = "opacity .5s ease, transform .5s ease";
  });

  const io = new IntersectionObserver((entries) => {
    entries.forEach((entry, i) => {
      if (entry.isIntersecting) {
        const el = entry.target;
        setTimeout(() => {
          el.style.opacity   = "1";
          el.style.transform = "translateY(0)";
        }, i * 65);
        io.unobserve(el);
      }
    });
  }, { threshold: 0.10 });

  targets.forEach(t => io.observe(t));
}

// ─────────────────────────────────────────────────────────────────────────────
// 18. BUTTON LOADING STATE
// ─────────────────────────────────────────────────────────────────────────────

function setBtnLoading(on) {
  const btn = $.submitBtn;
  if (!btn) return;
  btn.disabled = on;
  btn.classList.toggle("btn--loading", on);
  btn.setAttribute("aria-busy", String(on));

  const txt = btn.querySelector(".btn-text");
  if (txt) txt.textContent = on ? "Scanning…" : "Scan URL";
}

// ─────────────────────────────────────────────────────────────────────────────
// 19. INPUT ERROR HELPERS
// ─────────────────────────────────────────────────────────────────────────────

function showInputError(msg) {
  const errEl = $.urlError;
  if (!errEl) return;
  errEl.textContent = msg;
  errEl.hidden      = false;
  $.inputRow?.classList.add("error");
  $.urlInput.setAttribute("aria-invalid", "true");
}

function clearInputError() {
  const errEl = $.urlError;
  if (!errEl) return;
  errEl.textContent = "";
  errEl.hidden      = true;
  $.inputRow?.classList.remove("error");
  $.urlInput.removeAttribute("aria-invalid");
}

// ─────────────────────────────────────────────────────────────────────────────
// 20. RESULT ACTION BUTTONS — Copy Result + Download Report
//     These are wired to the dashboard-ui.js richCopyResult() and
//     downloadReport() functions via the shared window scope.
// ─────────────────────────────────────────────────────────────────────────────

function initResultActionBtns() {
  // Copy Result button (inside result pane)
  const copyBtn = $.resultCopyBtn;
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      // richCopyResult is defined in dashboard-ui.js (same page scope)
      if (typeof richCopyResult !== "function") return;
      const orig = copyBtn.textContent.trim();
      try {
        const ok = await richCopyResult();
        if (ok) {
          copyBtn.textContent = "Copied!";
          copyBtn.disabled    = true;
          setTimeout(() => { copyBtn.textContent = orig; copyBtn.disabled = false; }, 1800);
        }
      } catch {
        copyBtn.textContent = "Failed";
        setTimeout(() => { copyBtn.textContent = orig; }, 1800);
      }
    });
  }

  // Download Report button (inside result pane)
  const dlBtn = $.resultDownloadBtn;
  if (dlBtn) {
    dlBtn.addEventListener("click", () => {
      // downloadReport is defined in dashboard-ui.js (same page scope)
      if (typeof downloadReport !== "function") return;
      const orig = dlBtn.textContent.trim();
      const ok   = downloadReport();
      if (ok) {
        dlBtn.textContent = "Downloading…";
        dlBtn.disabled    = true;
        setTimeout(() => { dlBtn.textContent = orig; dlBtn.disabled = false; }, 1800);
      }
    });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 21. UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

/** Create a DOM element by tag name. */
function el(tag) {
  return document.createElement(tag);
}

/** Safely coerce a value to a string; return "" for non-strings. */
function safeStr(val) {
  return typeof val === "string" ? val : "";
}

// ─────────────────────────────────────────────────────────────────────────────
// 21. AMBIENT BLOBS — inject three soft glow blobs into the document
//     CSS handles their animation; JS only creates the DOM once.
// ─────────────────────────────────────────────────────────────────────────────

function initAmbientBlobs() {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const wrap = document.createElement("div");
  wrap.id = "ambient-blobs";
  wrap.setAttribute("aria-hidden", "true");

  ["a", "b", "c"].forEach(id => {
    const blob = document.createElement("div");
    blob.className = `amb-blob amb-blob--${id}`;
    wrap.appendChild(blob);
  });

  // Insert as first body child (behind everything)
  document.body.insertBefore(wrap, document.body.firstChild);
}

// ─────────────────────────────────────────────────────────────────────────────
// 22. CIRCUIT OVERLAY — glowing horizontal/vertical traces with
//     a traveling pulse dot on each one. Entirely cosmetic; aria-hidden.
// ─────────────────────────────────────────────────────────────────────────────

function initCircuitOverlay() {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const wrap = document.createElement("div");
  wrap.id = "circuit-overlay";
  wrap.setAttribute("aria-hidden", "true");
  document.body.insertBefore(wrap, document.body.firstChild);

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Define a handful of hand-placed circuit segments (% of viewport)
  // Each: { x, y, w, h, dir:"h"|"v", delay (ms), duration (ms) }
  const SEGMENTS = [
    { x:  5, y: 18, w: 18, h: 1, dir: "h", delay:    0, dur: 7000 },
    { x: 23, y: 18, w:  1, h: 12, dir: "v", delay:  800, dur: 8000 },
    { x: 23, y: 30, w: 14, h: 1, dir: "h", delay: 1600, dur: 7500 },
    { x: 70, y: 12, w: 22, h: 1, dir: "h", delay:  300, dur: 9000 },
    { x: 92, y: 12, w:  1, h: 18, dir: "v", delay: 1200, dur: 8500 },
    { x: 75, y: 30, w: 17, h: 1, dir: "h", delay: 2100, dur: 7000 },
    { x: 10, y: 65, w: 20, h: 1, dir: "h", delay:  500, dur: 8200 },
    { x: 30, y: 55, w:  1, h: 10, dir: "v", delay: 1400, dur: 7800 },
    { x: 30, y: 55, w: 12, h: 1, dir: "h", delay: 2300, dur: 6800 },
    { x: 60, y: 72, w: 28, h: 1, dir: "h", delay:  700, dur: 9200 },
    { x: 88, y: 60, w:  1, h: 12, dir: "v", delay: 1900, dur: 8000 },
    { x: 40, y: 85, w: 18, h: 1, dir: "h", delay: 1000, dur: 7600 },
  ];

  SEGMENTS.forEach((seg, idx) => {
    const line = document.createElement("div");
    line.className = `cline${seg.dir === "v" ? " cline--v" : ""}`;

    if (seg.dir === "h") {
      line.style.cssText = `
        left:${seg.x}vw; top:${seg.y}vh;
        width:${seg.w}vw; height:${seg.h}px;
      `;
    } else {
      line.style.cssText = `
        left:${seg.x}vw; top:${seg.y}vh;
        width:${seg.h}px; height:${seg.w}vh;
      `;
    }

    // Animate the line opacity (fade in, hold, fade out)
    animateCircuitLine(line, seg.delay, seg.dur);

    // Traveling pulse dot
    const pulse = document.createElement("div");
    pulse.className = "cline-pulse";
    line.appendChild(pulse);
    animateCircuitPulse(pulse, seg.dir, seg.delay + 400, seg.dur);

    wrap.appendChild(line);

    // Corner node at the end of each segment
    addCircuitNode(wrap, seg);
  });
}

function animateCircuitLine(line, delay, dur) {
  // Use Web Animations API if available for better compositing
  if (!line.animate) return;
  const kf = [
    { opacity: 0, offset: 0 },
    { opacity: 0, offset: 0.05 },
    { opacity: 0.65, offset: 0.2 },
    { opacity: 0.65, offset: 0.8 },
    { opacity: 0, offset: 0.95 },
    { opacity: 0, offset: 1 },
  ];
  line.animate(kf, {
    duration: dur,
    delay,
    iterations: Infinity,
    easing: "ease-in-out",
    fill: "both",
  });
}

function animateCircuitPulse(pulse, dir, delay, dur) {
  if (!pulse.animate) return;
  const prop = dir === "h" ? "left" : "top";
  const kf = [
    { [prop]: "-4px",   opacity: 0, offset: 0    },
    { [prop]: "5%",     opacity: 0, offset: 0.05 },
    { [prop]: "20%",    opacity: 1, offset: 0.25 },
    { [prop]: "80%",    opacity: 1, offset: 0.75 },
    { [prop]: "95%",    opacity: 0, offset: 0.95 },
    { [prop]: "calc(100% + 4px)", opacity: 0, offset: 1 },
  ];
  pulse.animate(kf, {
    duration: dur * 0.7,
    delay,
    iterations: Infinity,
    easing: "ease-in-out",
    fill: "both",
  });
}

function addCircuitNode(wrap, seg) {
  const node = document.createElement("div");
  node.className = "cnode";
  // Place node at the end of the segment
  const nx = seg.dir === "h" ? seg.x + seg.w : seg.x;
  const ny = seg.dir === "h" ? seg.y          : seg.y + seg.w;
  node.style.left = `calc(${nx}vw - 2.5px)`;
  node.style.top  = `calc(${ny}vh - 2.5px)`;
  node.style.animationDelay = `${seg.delay + 200}ms`;
  wrap.appendChild(node);
}

// ─────────────────────────────────────────────────────────────────────────────
// 23. LOADING SWEEP LINE + DATA READOUT
//     Injected into the loading state while scanning, removed after.
// ─────────────────────────────────────────────────────────────────────────────

const READOUT_STRINGS = [
  "PARSING STRUCTURE",
  "RESOLVING HOST",
  "CHECKING ENTROPY",
  "RUNNING 17 RULES",
  "SCORING HEURISTICS",
  "BUILDING REPORT",
];
let _sweepWrap   = null;
let _readoutEl   = null;
let _readoutTimer = null;
let _readoutIdx   = 0;

function injectSweepLine() {
  const loadingEl = document.getElementById("state-loading");
  if (!loadingEl) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  // Sweep bar
  _sweepWrap = document.createElement("div");
  _sweepWrap.className = "scan-sweep-wrap";
  const sweepLine = document.createElement("div");
  sweepLine.className = "scan-sweep-line";
  _sweepWrap.appendChild(sweepLine);
  loadingEl.appendChild(_sweepWrap);

  // Readout text
  _readoutEl = document.createElement("div");
  _readoutEl.className = "scan-readout";
  _readoutIdx = 0;
  _readoutEl.textContent = READOUT_STRINGS[0];
  loadingEl.appendChild(_readoutEl);

  _readoutTimer = setInterval(() => {
    _readoutIdx = (_readoutIdx + 1) % READOUT_STRINGS.length;
    if (_readoutEl) _readoutEl.textContent = READOUT_STRINGS[_readoutIdx];
  }, 900);
}

function removeSweepLine() {
  clearInterval(_readoutTimer);
  _readoutTimer = null;
  if (_sweepWrap)  { _sweepWrap.remove();  _sweepWrap  = null; }
  if (_readoutEl)  { _readoutEl.remove();  _readoutEl  = null; }
}

// ─────────────────────────────────────────────────────────────────────────────
// 24. BUTTON RIPPLE — attaches a transient .btn--ripple class on click
//     CSS handles the animation; class is removed after it completes.
// ─────────────────────────────────────────────────────────────────────────────

function initButtonRipple() {
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn");
    if (!btn) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    btn.classList.remove("btn--ripple");
    // Force reflow so re-adding the class re-triggers the animation
    void btn.offsetWidth;
    btn.classList.add("btn--ripple");

    const cleanup = () => btn.classList.remove("btn--ripple");
    btn.addEventListener("animationend", cleanup, { once: true });
    // Fallback removal
    setTimeout(cleanup, 450);
  }, { passive: true });
}
