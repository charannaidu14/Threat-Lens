/**
 * dashboard-ui.js — ThreatLens Dashboard UI Controller  v7
 *
 * Features:
 *  1.  Mobile sidebar open / close with Escape + overlay
 *  2.  Scroll-spy active nav highlighting
 *  3.  Session stat cards with animated counters
 *  4.  Security overview donut chart
 *  5.  Scan activity sparkline (hidden canvas, kept for compat)
 *  6.  Dual-line scan overview chart (canvas)
 *  7.  Per-card stat sparklines (canvas)
 *  8.  Recent scans table with full table-row layout
 *  9.  History search (live URL filter)
 * 10.  History risk filter (All / Safe / Suspicious / Dangerous)
 * 11.  Export scan history as CSV or JSON download
 * 12.  Quick action buttons (sidebar panel + result panel)
 * 13.  Download plain-text scan report
 * 14.  Rich clipboard copy of last result
 * 15.  Interactive risk analysis panel (expandable bar chart)
 * 16.  Sidebar scan-count badge
 * 17.  Keyboard shortcut: Ctrl+Enter / Cmd+Enter to scan
 * 18.  "Analyze Another" resets everything cleanly
 *
 * SECURITY RULES (never relax):
 *  - All dynamic content rendered via textContent / setAttribute only.
 *  - No innerHTML, insertAdjacentHTML, eval(), new Function(), document.write().
 */

"use strict";

/* ═══════════════════════════════════════════════════════════════════════════
   1. SESSION STORE  (in-memory — cleared on page refresh)
═══════════════════════════════════════════════════════════════════════════ */

const SESSION = {
  total:      0,
  safe:       0,
  suspicious: 0,
  dangerous:  0,
  history:    [],      // [{ url, score, risk, risk_label, summary, ts, indicators, recommendations }]
  lastResult: null,    // full API response from most recent scan
  _sparkData:  [],     // cumulative total per scan
  _sparkSafe:  [],     // cumulative safe per scan
  _sparkPhish: [],     // cumulative suspicious per scan
  _sparkHigh:  [],     // cumulative dangerous per scan
};

// Donut circumference for r=46
const DONUT_CIRCUMF = 2 * Math.PI * 46; // ≈ 289.03

/* ═══════════════════════════════════════════════════════════════════════════
   2. INIT
═══════════════════════════════════════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
  initSidebar();
  initScrollSpy();
  initNavLinks();
  initQuickActions();
  initHistorySearch();
  initHistoryFilter();
  initExportButtons();
  initKeyboardShortcut();
  renderStatCards();
  renderDonut();
  drawSparkline([]);
  drawStatSparklines();
  requestAnimationFrame(() => drawOverviewChart());
  listenForScanResults();

  // Security Toolkit
  initPasswordAnalyzer();
  init2FAChecker();
  initSessionMonitor();

  // Live Threat Intelligence
  initLiveThreatPanel();

  window.addEventListener("resize", () => {
    drawOverviewChart();
    drawStatSparklines();
  }, { passive: true });
});

/* ═══════════════════════════════════════════════════════════════════════════
   3. SIDEBAR — mobile open / close
═══════════════════════════════════════════════════════════════════════════ */

function initSidebar() {
  const burger   = document.getElementById("db-burger");
  const sidebar  = document.getElementById("db-sidebar");
  const overlay  = document.getElementById("db-overlay");
  const closeBtn = document.getElementById("db-sidebar-close");

  if (!burger || !sidebar) return;
  if (closeBtn) closeBtn.removeAttribute("hidden");

  function openSidebar() {
    sidebar.classList.add("db-sidebar--open");
    overlay?.classList.add("db-overlay--visible");
    burger.setAttribute("aria-expanded", "true");
  }

  function closeSidebar() {
    sidebar.classList.remove("db-sidebar--open");
    overlay?.classList.remove("db-overlay--visible");
    burger.setAttribute("aria-expanded", "false");
  }

  burger.addEventListener("click", () => {
    sidebar.classList.contains("db-sidebar--open") ? closeSidebar() : openSidebar();
  });

  closeBtn?.addEventListener("click", closeSidebar);
  overlay?.addEventListener("click",  closeSidebar);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && sidebar.classList.contains("db-sidebar--open")) {
      closeSidebar();
      burger.focus();
    }
  });

  // Auto-close on mobile nav click
  document.querySelectorAll(".db-nav-item").forEach(link => {
    link.addEventListener("click", () => {
      if (window.innerWidth < 768) closeSidebar();
    });
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   4. SCROLL SPY — highlight active nav item
═══════════════════════════════════════════════════════════════════════════ */

function initScrollSpy() {
  const scroll   = document.getElementById("dashboard");
  const navItems = document.querySelectorAll(".db-nav-item[data-section]");
  if (!scroll || !navItems.length) return;

  const sections = [];
  navItems.forEach(item => {
    const id  = item.dataset.section;
    const sec = document.getElementById(id);
    if (sec) sections.push({ id, el: sec, nav: item });
  });

  function onScroll() {
    const mid = scroll.scrollTop + scroll.clientHeight * 0.35;
    let activeId = null;
    sections.forEach(({ id, el }) => {
      if (el.offsetTop <= mid) activeId = id;
    });
    navItems.forEach(item => {
      const active = item.dataset.section === activeId;
      item.classList.toggle("db-nav-item--active", active);
      item.setAttribute("aria-current", active ? "page" : "false");
    });
  }

  scroll.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
}

/* ═══════════════════════════════════════════════════════════════════════════
   5. NAV LINK ROUTING — all sidebar links scroll to correct sections
═══════════════════════════════════════════════════════════════════════════ */

function initNavLinks() {
  const scroll = document.getElementById("dashboard");
  if (!scroll) return;

  document.querySelectorAll(".db-nav-item[data-section]").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const id  = link.dataset.section;
      const target = document.getElementById(id);
      if (target) {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   6. KEYBOARD SHORTCUT — Ctrl+Enter / Cmd+Enter submits the scan form
═══════════════════════════════════════════════════════════════════════════ */

function initKeyboardShortcut() {
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      const form = document.getElementById("analyze-form");
      if (form) {
        e.preventDefault();
        form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
      }
    }
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   7. STAT CARDS with animated counters
═══════════════════════════════════════════════════════════════════════════ */

function renderStatCards() {
  const total = SESSION.total;
  const safe  = SESSION.safe;
  const susp  = SESSION.suspicious;
  const dang  = SESSION.dangerous;

  setStatCardValue("stat-total",      total);
  setStatCardValue("stat-safe",       safe);
  setStatCardValue("stat-suspicious", susp);
  setStatCardValue("stat-dangerous",  dang);

  // Delta text (percentage of total)
  setStatDelta("stat-total-delta",      total === 0 ? "This session" : `${total} scan${total !== 1 ? "s" : ""}`);
  setStatDelta("stat-safe-delta",       total > 0 ? `${Math.round(safe / total * 100)}% of total` : "This session");
  setStatDelta("stat-suspicious-delta", total > 0 ? `${Math.round(susp / total * 100)}% of total` : "This session");
  setStatDelta("stat-dangerous-delta",  total > 0 ? `${Math.round(dang / total * 100)}% of total` : "This session");

  // Update sidebar scan count badge
  const badge = document.getElementById("nav-scan-count");
  if (badge) badge.textContent = total;
}

function setStatCardValue(id, value) {
  const el = document.getElementById(id);
  if (el) animateCounter(el, value);
}

function setStatDelta(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function animateCounter(el, target) {
  const duration = 700;
  const start    = performance.now();
  const from     = parseInt(el.textContent, 10) || 0;
  if (from === target) { el.textContent = target; return; }

  function tick(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    el.textContent = Math.round(from + (target - from) * eased);
    if (t < 1) requestAnimationFrame(tick);
    else el.textContent = target;
  }
  requestAnimationFrame(tick);
}

/* ═══════════════════════════════════════════════════════════════════════════
   8. SECURITY OVERVIEW DONUT CHART
═══════════════════════════════════════════════════════════════════════════ */

function renderDonut() {
  const total  = SESSION.total;
  const safe   = SESSION.safe;
  const medium = SESSION.suspicious;
  const high   = SESSION.dangerous;

  const safeEl    = document.getElementById("donut-safe");
  const medEl     = document.getElementById("donut-medium");
  const highEl    = document.getElementById("donut-high");
  const pctEl     = document.getElementById("donut-pct");
  const badgeEl   = document.getElementById("donut-badge");
  const lgSafe    = document.getElementById("legend-safe");
  const lgMed     = document.getElementById("legend-medium");
  const lgHigh    = document.getElementById("legend-high");
  const lgSafePct = document.getElementById("legend-safe-pct");
  const lgMedPct  = document.getElementById("legend-medium-pct");
  const lgHighPct = document.getElementById("legend-high-pct");

  if (!safeEl || !medEl || !highEl) return;

  if (total === 0) {
    [safeEl, medEl, highEl].forEach(c => {
      c.style.strokeDasharray  = `0 ${DONUT_CIRCUMF}`;
      c.style.strokeDashoffset = DONUT_CIRCUMF;
    });
    if (pctEl)   pctEl.textContent   = "0";
    if (badgeEl) { badgeEl.textContent = "—"; badgeEl.style.color = ""; }
    if (lgSafe)  lgSafe.textContent  = "0";
    if (lgMed)   lgMed.textContent   = "0";
    if (lgHigh)  lgHigh.textContent  = "0";
    if (lgSafePct)  lgSafePct.textContent  = "0%";
    if (lgMedPct)   lgMedPct.textContent   = "0%";
    if (lgHighPct)  lgHighPct.textContent  = "0%";
    return;
  }

  const safeLen  = (safe   / total) * DONUT_CIRCUMF;
  const medLen   = (medium / total) * DONUT_CIRCUMF;
  const highLen  = (high   / total) * DONUT_CIRCUMF;

  animateDonutSegment(safeEl, safeLen, DONUT_CIRCUMF, 0,                  0);
  animateDonutSegment(medEl,  medLen,  DONUT_CIRCUMF, safeLen,           100);
  animateDonutSegment(highEl, highLen, DONUT_CIRCUMF, safeLen + medLen,  200);

  // Center: show total threats (medium + high count)
  const threatCount = medium + high;
  if (pctEl)   animateCounter(pctEl, threatCount);
  if (badgeEl) {
    if (high > 0)        { badgeEl.textContent = "THREATS"; badgeEl.style.color = "#ef4444"; }
    else if (medium > 0) { badgeEl.textContent = "CAUTION"; badgeEl.style.color = "#f59e0b"; }
    else                 { badgeEl.textContent = "CLEAN";   badgeEl.style.color = "#10b981"; }
  }

  const fmt = n => (total ? Math.round(n / total * 100) : 0) + "%";
  if (lgSafe)     lgSafe.textContent     = safe;
  if (lgMed)      lgMed.textContent      = medium;
  if (lgHigh)     lgHigh.textContent     = high;
  if (lgSafePct)  lgSafePct.textContent  = fmt(safe);
  if (lgMedPct)   lgMedPct.textContent   = fmt(medium);
  if (lgHighPct)  lgHighPct.textContent  = fmt(high);
}

function animateDonutSegment(circle, segLen, circumf, startOffset, animDelay) {
  circle.style.strokeDasharray  = `${segLen} ${circumf - segLen}`;
  const finalOffset = circumf - startOffset;
  circle.style.strokeDashoffset = circumf;
  setTimeout(() => {
    circle.style.transition    = "stroke-dashoffset .7s cubic-bezier(.4,0,.2,1)";
    circle.style.strokeDashoffset = finalOffset;
  }, animDelay);
}

/* ═══════════════════════════════════════════════════════════════════════════
   9. SPARKLINE (hidden canvas — preserved for backward compatibility)
═══════════════════════════════════════════════════════════════════════════ */

function drawSparkline(dataPoints) {
  const canvas = document.getElementById("db-sparkline");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width;
  const H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const DATA = [...dataPoints];
  while (DATA.length < 8) DATA.push(0);
  const last8 = DATA.slice(-8);
  const max  = Math.max(...last8, 1);
  const step = W / (last8.length - 1);

  const pts = last8.map((v, i) => ({
    x: i * step,
    y: H - (v / max) * (H - 10) - 5,
  }));

  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, "rgba(0,229,255,0.28)");
  grad.addColorStop(1, "rgba(0,229,255,0.02)");

  ctx.beginPath();
  ctx.moveTo(pts[0].x, H);
  ctx.lineTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    const cpx = pts[i - 1].x + step * 0.4;
    const cpx2 = pts[i].x - step * 0.4;
    ctx.bezierCurveTo(cpx, pts[i - 1].y, cpx2, pts[i].y, pts[i].x, pts[i].y);
  }
  ctx.lineTo(pts[pts.length - 1].x, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    const cpx  = pts[i - 1].x + step * 0.4;
    const cpx2 = pts[i].x - step * 0.4;
    ctx.bezierCurveTo(cpx, pts[i - 1].y, cpx2, pts[i].y, pts[i].x, pts[i].y);
  }
  ctx.strokeStyle = "rgba(0,229,255,0.75)";
  ctx.lineWidth   = 1.8;
  ctx.stroke();

  const last = pts[pts.length - 1];
  ctx.beginPath();
  ctx.arc(last.x, last.y, 3.5, 0, Math.PI * 2);
  ctx.fillStyle = "#00e5ff";
  ctx.fill();
}

/* ═══════════════════════════════════════════════════════════════════════════
   10. SCAN OVERVIEW LINE CHART — dual-line bezier with glow
═══════════════════════════════════════════════════════════════════════════ */

function drawOverviewChart() {
  const canvas = document.getElementById("db-overview-chart");
  if (!canvas) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const dpr  = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const W    = Math.max(rect.width || 400, 200);
  const H    = 160;
  canvas.width  = W * dpr;
  canvas.height = H * dpr;
  canvas.style.width  = W + "px";
  canvas.style.height = H + "px";
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);

  // Build 7-slot data from history
  const history   = SESSION.history.slice(0, 7).reverse();
  const safeData  = [];
  const phishData = [];
  let runSafe = 0, runPhish = 0;
  for (let i = 0; i < 7; i++) {
    const e = history[i];
    if (e) {
      if (e.risk === "low") runSafe++;
      else runPhish++;
    }
    safeData.push(runSafe);
    phishData.push(runPhish);
  }

  const maxVal  = Math.max(...safeData, ...phishData, 5);
  const padX = 6, padY = 8;
  const usW = W - padX * 2;
  const usH = H - padY * 2;

  // Grid
  ctx.strokeStyle = "rgba(255,255,255,0.04)";
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padY + (i / 4) * usH;
    ctx.beginPath(); ctx.moveTo(padX, y); ctx.lineTo(W - padX, y); ctx.stroke();
  }
  for (let i = 0; i < 7; i++) {
    const x = padX + (i / 6) * usW;
    ctx.beginPath(); ctx.moveTo(x, padY); ctx.lineTo(x, H - padY); ctx.stroke();
  }

  function plotLine(data, color, glowColor) {
    if (data.length < 2) return;
    const pts = data.map((v, i) => ({
      x: padX + (i / (data.length - 1)) * usW,
      y: padY + usH - (v / maxVal) * usH,
    }));
    const step = usW / (data.length - 1);

    ctx.save();
    ctx.shadowColor = glowColor;
    ctx.shadowBlur  = 10;

    // Area
    const grad = ctx.createLinearGradient(0, padY, 0, H);
    grad.addColorStop(0, color.replace("1)", "0.22)"));
    grad.addColorStop(1, color.replace("1)", "0.01)"));
    ctx.beginPath();
    ctx.moveTo(pts[0].x, H);
    ctx.lineTo(pts[0].x, pts[0].y);
    for (let i = 1; i < pts.length; i++) {
      const c1x = pts[i - 1].x + step * 0.4;
      const c2x = pts[i].x - step * 0.4;
      ctx.bezierCurveTo(c1x, pts[i - 1].y, c2x, pts[i].y, pts[i].x, pts[i].y);
    }
    ctx.lineTo(pts[pts.length - 1].x, H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i = 1; i < pts.length; i++) {
      const c1x = pts[i - 1].x + step * 0.4;
      const c2x = pts[i].x - step * 0.4;
      ctx.bezierCurveTo(c1x, pts[i - 1].y, c2x, pts[i].y, pts[i].x, pts[i].y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth   = 2;
    ctx.stroke();

    // Dots
    pts.forEach(pt => {
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, 3.5, 0, Math.PI * 2);
      ctx.fillStyle   = color;
      ctx.shadowBlur  = 8;
      ctx.shadowColor = glowColor;
      ctx.fill();
    });
    ctx.restore();
  }

  plotLine(safeData,  "rgba(16,185,129,1)", "rgba(16,185,129,0.8)");
  plotLine(phishData, "rgba(239,68,68,1)",  "rgba(239,68,68,0.8)");
}

/* ═══════════════════════════════════════════════════════════════════════════
   11. STAT CARD SPARKLINES
═══════════════════════════════════════════════════════════════════════════ */

function drawStatSparklines() {
  const configs = [
    { id: "spark-total",      data: SESSION._sparkData,  color: "rgba(0,229,255,1)",   glow: "rgba(0,229,255,0.8)"   },
    { id: "spark-safe",       data: SESSION._sparkSafe,  color: "rgba(16,185,129,1)",  glow: "rgba(16,185,129,0.8)"  },
    { id: "spark-suspicious", data: SESSION._sparkPhish, color: "rgba(245,158,11,1)",  glow: "rgba(245,158,11,0.8)"  },
    { id: "spark-dangerous",  data: SESSION._sparkHigh,  color: "rgba(239,68,68,1)",   glow: "rgba(239,68,68,0.8)"   },
  ];

  configs.forEach(({ id, data, color, glow }) => {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const W = 90, H = 32;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);

    const raw = [...data];
    while (raw.length < 7) raw.unshift(0);
    const pts7 = raw.slice(-7);
    const max  = Math.max(...pts7, 1);
    const step = W / (pts7.length - 1);

    const pts = pts7.map((v, i) => ({
      x: i * step,
      y: H - 4 - (v / max) * (H - 8),
    }));

    ctx.save();
    ctx.shadowColor = glow;
    ctx.shadowBlur  = 6;
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i = 1; i < pts.length; i++) {
      const c1x = pts[i - 1].x + step * 0.45;
      const c2x = pts[i].x - step * 0.45;
      ctx.bezierCurveTo(c1x, pts[i - 1].y, c2x, pts[i].y, pts[i].x, pts[i].y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth   = 1.5;
    ctx.stroke();
    ctx.restore();

    const last = pts[pts.length - 1];
    ctx.beginPath();
    ctx.arc(last.x, last.y, 2.2, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   12. RECENT SCANS TABLE — full table-row layout
═══════════════════════════════════════════════════════════════════════════ */

let _scanRowCount = 0;

function appendRecentScan(entry) {
  const list = document.getElementById("db-recent-list");
  if (!list) return;

  // Remove empty placeholder
  const empty = list.querySelector(".db-recent-empty");
  if (empty) empty.remove();

  _scanRowCount++;
  const { url, score, risk, ts } = entry;

  const badgeCls = risk === "high" ? "db-result-badge--phish"
                 : risk === "medium" ? "db-result-badge--medium"
                 : "db-result-badge--safe";
  const badgeTxt = risk === "high"   ? "Phishing"
                 : risk === "medium" ? "Suspicious"
                 : "Safe";
  const threatTxt = risk === "high"   ? "URL Analysis"
                  : risk === "medium" ? "Suspicious Pattern"
                  : "—";

  const li = document.createElement("li");
  li.className = `db-recent-item db-recent-item--${risk}`;
  li.dataset.risk = risk;
  li.dataset.url  = url.toLowerCase();

  const numEl = document.createElement("span");
  numEl.className   = "db-recent-item__num";
  numEl.textContent = _scanRowCount;

  const urlEl = document.createElement("span");
  urlEl.className   = "db-recent-item__url db-recent-url";
  urlEl.textContent = url.length > 40 ? url.slice(0, 37) + "…" : url;
  urlEl.title       = url;

  const badgeWrap = document.createElement("span");
  const badge     = document.createElement("span");
  badge.className = `db-result-badge ${badgeCls}`;
  const bdot = document.createElement("span");
  bdot.className = "db-result-badge__dot";
  bdot.setAttribute("aria-hidden", "true");
  const btxt = document.createElement("span");
  btxt.textContent = badgeTxt;
  badge.append(bdot, btxt);
  badgeWrap.appendChild(badge);

  const typeEl = document.createElement("span");
  typeEl.className   = "db-recent-item__type";
  typeEl.textContent = threatTxt;

  const timeEl = document.createElement("span");
  timeEl.className   = "db-recent-item__time";
  timeEl.textContent = formatDateTime(ts);

  const actionWrap = document.createElement("span");
  actionWrap.className = "db-recent-item__action";
  const viewBtn = document.createElement("button");
  viewBtn.type      = "button";
  viewBtn.className = "db-view-btn";
  viewBtn.textContent = "View";
  viewBtn.setAttribute("aria-label", `View scan for ${url}`);
  viewBtn.addEventListener("click", () => {
    document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
  });
  actionWrap.appendChild(viewBtn);

  li.append(numEl, urlEl, badgeWrap, typeEl, timeEl, actionWrap);

  // Prepend newest first, keep max 20
  list.insertBefore(li, list.firstChild);
  const items = list.querySelectorAll(".db-recent-item");
  if (items.length > 20) items[items.length - 1].remove();

  // Re-apply current filter
  applyHistoryFilter();
}

function formatTime(date) {
  return String(date.getHours()).padStart(2, "0") + ":" + String(date.getMinutes()).padStart(2, "0");
}

function formatDateTime(date) {
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return `${months[date.getMonth()]} ${String(date.getDate()).padStart(2,"0")}  ${String(date.getHours()).padStart(2,"0")}:${String(date.getMinutes()).padStart(2,"0")}`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   13. HISTORY SEARCH — live URL filter
═══════════════════════════════════════════════════════════════════════════ */

// Track active filter state
let _filterRisk   = "all";  // "all" | "low" | "medium" | "high"
let _filterSearch = "";

function initHistorySearch() {
  const recentList = document.getElementById("db-recent-list");
  if (!recentList) return;

  const panel = recentList.closest(".db-panel, .db-panel--table");
  if (!panel) return;

  // Build search row (if not already injected)
  if (document.getElementById("db-history-filter")) return;

  const wrap  = document.createElement("div");
  wrap.className = "db-history-search";

  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("width", "14"); icon.setAttribute("height", "14");
  icon.setAttribute("viewBox", "0 0 24 24"); icon.setAttribute("fill", "none");
  icon.setAttribute("aria-hidden", "true");
  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  circle.setAttribute("cx","11"); circle.setAttribute("cy","11");
  circle.setAttribute("r","7"); circle.setAttribute("stroke","currentColor");
  circle.setAttribute("stroke-width","1.8");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d","M21 21l-4.35-4.35");
  path.setAttribute("stroke","currentColor"); path.setAttribute("stroke-width","1.8");
  path.setAttribute("stroke-linecap","round");
  icon.append(circle, path);

  const input = document.createElement("input");
  input.type        = "search";
  input.className   = "db-history-input";
  input.placeholder = "Filter scans by URL…";
  input.setAttribute("aria-label", "Filter scan history by URL");
  input.id = "db-history-filter";

  wrap.append(icon, input);
  panel.insertBefore(wrap, recentList);

  input.addEventListener("input", () => {
    _filterSearch = input.value.trim().toLowerCase();
    applyHistoryFilter();
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   14. HISTORY FILTER — by risk level
═══════════════════════════════════════════════════════════════════════════ */

function initHistoryFilter() {
  // Filter buttons are rendered in the HTML — find by data-filter attribute
  document.querySelectorAll("[data-filter-risk]").forEach(btn => {
    btn.addEventListener("click", () => {
      _filterRisk = btn.dataset.filterRisk || "all";
      document.querySelectorAll("[data-filter-risk]").forEach(b => {
        b.classList.toggle("active", b.dataset.filterRisk === _filterRisk);
      });
      applyHistoryFilter();
    });
  });
}

function applyHistoryFilter() {
  const list = document.getElementById("db-recent-list");
  if (!list) return;

  const items    = list.querySelectorAll(".db-recent-item");
  let anyVisible = false;

  items.forEach(item => {
    const riskMatch   = _filterRisk === "all" || item.dataset.risk === _filterRisk;
    const searchMatch = !_filterSearch || (item.dataset.url || "").includes(_filterSearch);
    const visible     = riskMatch && searchMatch;
    item.style.display = visible ? "" : "none";
    if (visible) anyVisible = true;
  });

  // Show/hide "no results" message
  let noMatch = list.querySelector(".db-recent-nomatch");
  const hasItems = items.length > 0;

  if (hasItems && !anyVisible) {
    if (!noMatch) {
      noMatch = document.createElement("li");
      noMatch.className   = "db-recent-empty db-recent-nomatch";
      noMatch.textContent = "No scans match your filter.";
      list.appendChild(noMatch);
    }
    noMatch.style.display = "";
  } else if (noMatch) {
    noMatch.style.display = "none";
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   15. EXPORT — CSV + JSON download
═══════════════════════════════════════════════════════════════════════════ */

function initExportButtons() {
  const btnCsv  = document.getElementById("export-csv");
  const btnJson = document.getElementById("export-json");

  if (btnCsv) {
    btnCsv.addEventListener("click", () => {
      if (!SESSION.history.length) { flashEl(btnCsv, "No data"); return; }
      const csv = buildCsv(SESSION.history);
      triggerDownload(csv, "text/csv;charset=utf-8", `threatlens-history-${datestamp()}.csv`);
      flashEl(btnCsv, "Downloaded!");
    });
  }

  if (btnJson) {
    btnJson.addEventListener("click", () => {
      if (!SESSION.history.length) { flashEl(btnJson, "No data"); return; }
      const json = JSON.stringify(SESSION.history.map(h => ({
        url:       h.url,
        score:     h.score,
        risk:      h.risk,
        risk_label: h.risk_label || h.risk,
        scanned_at: h.ts.toISOString(),
      })), null, 2);
      triggerDownload(json, "application/json", `threatlens-history-${datestamp()}.json`);
      flashEl(btnJson, "Downloaded!");
    });
  }
}

function buildCsv(history) {
  const header = ["#","URL","Score","Risk","Risk Label","Scanned At"];
  const rows   = history.map((h, i) => [
    i + 1,
    `"${h.url.replace(/"/g, '""')}"`,
    h.score,
    h.risk,
    h.risk_label || h.risk,
    h.ts.toISOString(),
  ]);
  return [header.join(","), ...rows.map(r => r.join(","))].join("\r\n");
}

function triggerDownload(content, mime, filename) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function datestamp() {
  const d = new Date();
  return `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,"0")}${String(d.getDate()).padStart(2,"0")}`;
}

/* ═══════════════════════════════════════════════════════════════════════════
   16. QUICK ACTIONS (sidebar + result panel buttons)
═══════════════════════════════════════════════════════════════════════════ */

function initQuickActions() {
  // ── Clear input
  document.querySelectorAll("#qa-clear").forEach(btn => {
    btn.addEventListener("click", () => {
      const input  = document.getElementById("url-input");
      const clearB = document.getElementById("clear-btn");
      if (input)  { input.value = ""; input.focus(); }
      if (clearB) clearB.hidden = true;
      ["state-loading","state-error","state-result"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.hidden = true;
      });
      const rp = document.getElementById("risk-analysis-panel");
      if (rp) rp.hidden = true;
      document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  // ── View scan history
  document.querySelectorAll("#qa-scan-history").forEach(btn => {
    btn.addEventListener("click", () => {
      const panel = document.getElementById("db-recent-list");
      if (panel) panel.closest(".db-panel, .db-panel--table")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  });

  // ── Copy last result (rich)
  document.querySelectorAll("#qa-copy").forEach(btn => {
    btn.addEventListener("click", async () => {
      if (!SESSION.lastResult) { flashEl(btn, "Nothing to copy"); return; }
      try {
        await richCopyResult();
        flashEl(btn, "Copied!");
      } catch {
        flashEl(btn, "Copy failed");
      }
    });
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   17. DOWNLOAD SCAN REPORT
═══════════════════════════════════════════════════════════════════════════ */

function downloadReport() {
  const r = SESSION.lastResult;
  if (!r) return false;

  const line = "─".repeat(60);
  const ts   = r.ts ? r.ts.toLocaleString() : new Date().toLocaleString();
  const triggered = (r.indicators || []).filter(i => i.triggered);
  const clear     = (r.indicators || []).filter(i => !i.triggered);

  let report = "";
  report += "╔══════════════════════════════════════════════════════════╗\n";
  report += "║            ThreatLens — URL Analysis Report             ║\n";
  report += "╚══════════════════════════════════════════════════════════╝\n\n";
  report += `Scanned At  : ${ts}\n`;
  report += `URL         : ${r.url_display}\n`;
  report += `Risk Level  : ${(r.risk_label || r.risk_level || "").toUpperCase()}\n`;
  report += `Score       : ${r.score} / 100\n`;
  report += `Summary     : ${r.summary}\n\n`;

  report += `${line}\nTRIGGERED INDICATORS (${triggered.length})\n${line}\n`;
  if (triggered.length === 0) {
    report += "  None — no suspicious signals detected.\n";
  } else {
    triggered.forEach(ind => {
      report += `  [+${String(ind.weight || 0).padStart(2)}]  ${ind.name}\n`;
      if (ind.explanation) report += `         ${ind.explanation}\n`;
    });
  }

  report += `\n${line}\nCLEAR INDICATORS (${clear.length})\n${line}\n`;
  clear.forEach(ind => { report += `  [ – ]  ${ind.name}\n`; });

  report += `\n${line}\nRECOMMENDATIONS\n${line}\n`;
  (r.recommendations || []).forEach((rec, i) => { report += `  ${i + 1}. ${rec}\n`; });

  report += `\n${line}\nDISCLAIMER\n${line}\n${r.disclaimer || ""}\n\n`;
  report += "Generated by ThreatLens\n";

  triggerDownload(report, "text/plain;charset=utf-8", `threatlens-report-${Date.now()}.txt`);
  return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
   18. RICH CLIPBOARD COPY
═══════════════════════════════════════════════════════════════════════════ */

async function richCopyResult() {
  const r = SESSION.lastResult;
  if (!r) return false;

  const triggered = (r.indicators || []).filter(i => i.triggered);
  let text  = `ThreatLens Result\n${"─".repeat(40)}\n`;
  text += `URL   : ${r.url_display}\n`;
  text += `Score : ${r.score}/100  |  Risk: ${(r.risk_label || r.risk_level || "").toUpperCase()}\n`;
  text += `\n${r.summary}\n`;
  if (triggered.length) {
    text += `\nTriggered (${triggered.length}):\n`;
    triggered.forEach(ind => { text += `  • ${ind.name}  (+${ind.weight || 0})\n`; });
  }
  if ((r.recommendations || []).length) {
    text += `\nRecommendations:\n`;
    r.recommendations.forEach((rec, i) => { text += `  ${i + 1}. ${rec}\n`; });
  }
  text += `\n${"─".repeat(40)}\nGenerated by ThreatLens`;

  await navigator.clipboard.writeText(text);
  return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
   19. INTERACTIVE RISK ANALYSIS PANEL — expandable triggered-rules bar chart
═══════════════════════════════════════════════════════════════════════════ */

function renderRiskPanel(result) {
  let panel = document.getElementById("risk-analysis-panel");

  if (!panel) {
    panel = buildRiskPanel();
    if (!panel) return;
  }

  panel.hidden = false;

  const triggered  = (result.indicators || []).filter(i => i.triggered);
  const maxWeight  = Math.max(...triggered.map(i => i.weight || 1), 1);

  const summaryEl = panel.querySelector(".rap__summary");
  if (summaryEl) {
    summaryEl.textContent = triggered.length === 0
      ? "No risk indicators triggered — URL appears clean."
      : `${triggered.length} indicator${triggered.length !== 1 ? "s" : ""} triggered — score: ${result.score}/100`;
  }

  const chart = panel.querySelector(".rap__chart");
  if (!chart) return;
  while (chart.firstChild) chart.removeChild(chart.firstChild);

  if (triggered.length === 0) {
    const empty = document.createElement("p");
    empty.className   = "rap__empty";
    empty.textContent = "All indicators are clear.";
    chart.appendChild(empty);
    return;
  }

  const sorted = [...triggered].sort((a, b) => (b.weight || 0) - (a.weight || 0));
  sorted.forEach(ind => {
    const row     = document.createElement("div");
    row.className = "rap__row";

    const label = document.createElement("span");
    label.className   = "rap__label";
    label.textContent = ind.name;

    const barWrap = document.createElement("div");
    barWrap.className = "rap__bar-wrap";

    const bar = document.createElement("div");
    bar.className  = "rap__bar";
    bar.style.width = "0%";

    const wt = document.createElement("span");
    wt.className   = "rap__wt";
    wt.textContent = `+${ind.weight || 0}`;

    barWrap.append(bar, wt);
    row.append(label, barWrap);
    chart.appendChild(row);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        bar.style.width = `${Math.round(((ind.weight || 0) / maxWeight) * 100)}%`;
      });
    });
  });
}

function buildRiskPanel() {
  const stateResult = document.getElementById("state-result");
  if (!stateResult) return null;

  const panel = document.createElement("div");
  panel.id        = "risk-analysis-panel";
  panel.className = "rap";
  panel.setAttribute("aria-label", "Risk analysis breakdown");
  panel.hidden = true;

  const hd = document.createElement("button");
  hd.type      = "button";
  hd.className = "rap__toggle";
  hd.setAttribute("aria-expanded", "true");
  hd.setAttribute("aria-controls",  "rap-body");

  const hdLeft = document.createElement("span");
  hdLeft.className = "rap__toggle-left";

  const shieldSvg  = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  shieldSvg.setAttribute("width","14"); shieldSvg.setAttribute("height","14");
  shieldSvg.setAttribute("viewBox","0 0 24 24"); shieldSvg.setAttribute("fill","none");
  shieldSvg.setAttribute("aria-hidden","true");
  const shieldPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
  shieldPath.setAttribute("d","M12 2L2 7v10c0 6 4.5 10 10 11 5.5-1 10-5 10-11V7L12 2Z");
  shieldPath.setAttribute("stroke","#00e5ff"); shieldPath.setAttribute("stroke-width","1.8");
  shieldSvg.appendChild(shieldPath);

  const titleSpan = document.createElement("span");
  titleSpan.textContent = "Risk Analysis Breakdown";
  hdLeft.append(shieldSvg, titleSpan);

  const chevron = document.createElement("span");
  chevron.className   = "rap__chevron";
  chevron.setAttribute("aria-hidden", "true");
  chevron.textContent = "▾";

  hd.append(hdLeft, chevron);

  const body = document.createElement("div");
  body.id        = "rap-body";
  body.className = "rap__body";

  const summaryP = document.createElement("p");
  summaryP.className = "rap__summary";

  const chart = document.createElement("div");
  chart.className = "rap__chart";

  body.append(summaryP, chart);
  panel.append(hd, body);

  hd.addEventListener("click", () => {
    const expanded = hd.getAttribute("aria-expanded") === "true";
    hd.setAttribute("aria-expanded", String(!expanded));
    body.classList.toggle("rap__body--collapsed", expanded);
    chevron.textContent = expanded ? "▸" : "▾";
  });

  stateResult.insertAdjacentElement("afterend", panel);
  return panel;
}

/* ═══════════════════════════════════════════════════════════════════════════
   20. LISTEN FOR SCAN RESULTS — threatlens:result CustomEvent
═══════════════════════════════════════════════════════════════════════════ */

function listenForScanResults() {
  document.addEventListener("threatlens:result", (e) => {
    const d = e.detail || {};
    const { score, risk_level, url_display } = d;
    if (!url_display) return;

    // Store full payload
    SESSION.lastResult = {
      score,
      risk_level,
      risk_label:      d.risk_label       || risk_level,
      url_display,
      summary:         d.summary          || "",
      indicators:      Array.isArray(d.indicators)      ? d.indicators      : [],
      recommendations: Array.isArray(d.recommendations) ? d.recommendations : [],
      disclaimer:      d.disclaimer       || "",
      ts: new Date(),
    };

    // Update counters
    SESSION.total++;
    if      (risk_level === "low")    SESSION.safe++;
    else if (risk_level === "medium") SESSION.suspicious++;
    else if (risk_level === "high")   SESSION.dangerous++;

    // Sparkline series
    SESSION._sparkData.push(SESSION.total);
    SESSION._sparkSafe.push(SESSION.safe);
    SESSION._sparkPhish.push(SESSION.suspicious);
    SESSION._sparkHigh.push(SESSION.dangerous);

    const entry = {
      url:        url_display,
      score,
      risk:       risk_level,
      risk_label: d.risk_label || risk_level,
      summary:    d.summary    || "",
      ts:         SESSION.lastResult.ts,
      indicators: SESSION.lastResult.indicators,
      recommendations: SESSION.lastResult.recommendations,
    };
    SESSION.history.unshift(entry);

    // Re-render all widgets
    renderStatCards();
    renderDonut();
    drawSparkline(SESSION._sparkData);
    drawStatSparklines();
    drawOverviewChart();
    appendRecentScan(entry);
    renderRiskPanel(SESSION.lastResult);
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   21. UTILITY
═══════════════════════════════════════════════════════════════════════════ */

/** Flash temporary text on a button/element, then restore. */
function flashEl(el, msg) {
  const orig = el.textContent;
  el.textContent = msg;
  el.disabled    = true;
  setTimeout(() => {
    el.textContent = orig;
    el.disabled    = false;
  }, 1800);
}

// Legacy alias — kept so old call sites don't break
function flashBtn(btn, msg) { flashEl(btn, msg); }

/* ═══════════════════════════════════════════════════════════════════════════
   22. SECURITY TOOLKIT — Password Analyzer, 2FA Checker, Session Monitor
       All logic runs 100% in-browser. No data sent anywhere.
       SECURITY: textContent/setAttribute only — no innerHTML / eval.
═══════════════════════════════════════════════════════════════════════════ */

/* ──────────────────────────────────────────────────────────────────────────
   22a. PASSWORD STRENGTH ANALYZER
────────────────────────────────────────────────────────────────────────── */
function initPasswordAnalyzer() {
  const input  = document.getElementById("stk-pw-input");
  const toggle = document.getElementById("stk-pw-toggle");
  if (!input || !toggle) return;

  // Toggle show/hide
  toggle.addEventListener("click", () => {
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    toggle.setAttribute("aria-pressed", String(!showing));
    const eyeOpen   = toggle.querySelector(".stk-eye-open");
    const eyeClosed = toggle.querySelector(".stk-eye-closed");
    if (eyeOpen)   eyeOpen.style.display   = showing ? "" : "none";
    if (eyeClosed) eyeClosed.style.display = showing ? "none" : "";
  });

  // Analyze on every keystroke
  input.addEventListener("input", () => {
    analyzePassword(input.value);
  });

  // Initial blank state
  analyzePassword("");
}

function analyzePassword(pw) {
  const fill    = document.getElementById("stk-pw-meter-fill");
  const label   = document.getElementById("stk-pw-strength-label");
  const elLen   = document.getElementById("stk-pw-len");
  const elEnt   = document.getElementById("stk-pw-entropy");
  const elUp    = document.getElementById("stk-pw-upper");
  const elLow   = document.getElementById("stk-pw-lower");
  const elDig   = document.getElementById("stk-pw-digits");
  const elSym   = document.getElementById("stk-pw-symbols");
  const tipList = document.getElementById("stk-pw-tips");
  if (!fill || !label || !tipList) return;

  if (!pw) {
    fill.style.width = "0%";
    fill.className = "stk-meter__fill";
    label.className = "stk-meter__label";
    label.textContent = "—";
    if (elLen) elLen.textContent = "—";
    if (elEnt) elEnt.textContent = "—";
    if (elUp)  elUp.textContent  = "—";
    if (elLow) elLow.textContent = "—";
    if (elDig) elDig.textContent = "—";
    if (elSym) elSym.textContent = "—";
    // Clear tips safely
    while (tipList.firstChild) tipList.removeChild(tipList.firstChild);
    return;
  }

  // Composition counts
  const upper   = (pw.match(/[A-Z]/g)   || []).length;
  const lower   = (pw.match(/[a-z]/g)   || []).length;
  const digits  = (pw.match(/[0-9]/g)   || []).length;
  const symbols = (pw.match(/[^A-Za-z0-9]/g) || []).length;
  const len     = pw.length;

  // Pool size for entropy
  let pool = 0;
  if (upper)   pool += 26;
  if (lower)   pool += 26;
  if (digits)  pool += 10;
  if (symbols) pool += 32;
  const entropy = pool > 0 ? Math.round(len * Math.log2(pool)) : 0;

  // Stats
  if (elLen) elLen.textContent = String(len);
  if (elEnt) elEnt.textContent = entropy + " bits";
  if (elUp)  elUp.textContent  = String(upper);
  if (elLow) elLow.textContent = String(lower);
  if (elDig) elDig.textContent = String(digits);
  if (elSym) elSym.textContent = String(symbols);

  // Score 0-5
  let score = 0;
  if (len >= 8)   score++;
  if (len >= 12)  score++;
  if (len >= 16)  score++;
  if (upper && lower && digits) score++;
  if (symbols)    score++;

  const levels = [
    { pct: 8,  cls: "weak",    text: "Very Weak"   },
    { pct: 25, cls: "weak",    text: "Weak"         },
    { pct: 45, cls: "fair",    text: "Fair"         },
    { pct: 65, cls: "good",    text: "Good"         },
    { pct: 82, cls: "strong",  text: "Strong"       },
    { pct: 100,cls: "vstrong", text: "Very Strong"  },
  ];
  const lvl = levels[Math.min(score, levels.length - 1)];

  fill.style.width = lvl.pct + "%";
  fill.className   = "stk-meter__fill stk-meter__fill--" + lvl.cls;
  label.className  = "stk-meter__label stk-meter__label--" + lvl.cls;
  label.textContent = lvl.text;

  // Build tips
  const tips = [];
  if (len < 12)   tips.push({ pass: false, msg: "Use at least 12 characters (16+ recommended)" });
  else             tips.push({ pass: true,  msg: "Good length — " + len + " characters" });

  if (!upper)     tips.push({ pass: false, msg: "Add uppercase letters (A–Z)" });
  else             tips.push({ pass: true,  msg: "Has uppercase letters" });

  if (!lower)     tips.push({ pass: false, msg: "Add lowercase letters (a–z)" });
  if (!digits)    tips.push({ pass: false, msg: "Add at least one digit (0–9)" });
  if (!symbols)   tips.push({ pass: false, msg: "Add symbols (!@#$%^&*) for extra strength" });
  else             tips.push({ pass: true,  msg: "Has special symbols" });

  if (entropy < 40) tips.push({ pass: false, msg: "Entropy too low (" + entropy + " bits) — a passphrase is stronger" });
  else if (entropy >= 80) tips.push({ pass: true, msg: "High entropy (" + entropy + " bits) — excellent!" });

  // Render tips using textContent only
  while (tipList.firstChild) tipList.removeChild(tipList.firstChild);
  tips.forEach(t => {
    const li = document.createElement("li");
    li.className = "stk-pw-tip" + (t.pass ? " stk-pw-tip--pass" : "");
    li.textContent = t.msg;
    tipList.appendChild(li);
  });
}

/* ──────────────────────────────────────────────────────────────────────────
   22b. 2FA / MFA READINESS CHECKER
────────────────────────────────────────────────────────────────────────── */
function init2FAChecker() {
  const checks = document.querySelectorAll(".stk-check");
  if (!checks.length) return;

  checks.forEach(cb => {
    cb.addEventListener("change", update2FAScore);
  });

  update2FAScore(); // initial
}

function update2FAScore() {
  const checks = document.querySelectorAll(".stk-check");
  const ringArc   = document.getElementById("stk-2fa-ring-arc");
  const scoreEl   = document.getElementById("stk-2fa-score");
  const labelEl   = document.getElementById("stk-2fa-verdict-label");
  const subEl     = document.getElementById("stk-2fa-verdict-sub");
  if (!ringArc || !scoreEl) return;

  let total = 0;
  let maxTotal = 0;
  checks.forEach(cb => {
    const w = parseInt(cb.getAttribute("data-weight") || "1", 10);
    maxTotal += w;
    if (cb.checked) total += w;
  });

  // Normalise to /10
  const score10 = maxTotal > 0 ? Math.round((total / maxTotal) * 10) : 0;
  scoreEl.textContent = String(score10);

  // Animate ring — circumference = 2π×32 ≈ 201.06
  const CIRC = 201.06;
  const offset = CIRC - (CIRC * score10 / 10);
  ringArc.style.strokeDashoffset = String(offset);

  // Colour ring by score
  let ringColor, verdictText, verdictSub;
  if (score10 <= 2) {
    ringColor   = "#ef4444";
    verdictText = "⚠ At Risk";
    verdictSub  = "Critical gaps in your authentication security";
  } else if (score10 <= 4) {
    ringColor   = "#f59e0b";
    verdictText = "Needs Improvement";
    verdictSub  = "Enable 2FA on your key accounts now";
  } else if (score10 <= 6) {
    ringColor   = "#3b82f6";
    verdictText = "Moderate Security";
    verdictSub  = "You have basic protections — level up to TOTP or hardware keys";
  } else if (score10 <= 8) {
    ringColor   = "#10b981";
    verdictText = "Good Posture";
    verdictSub  = "Strong MFA practices in place";
  } else {
    ringColor   = "#00e5ff";
    verdictText = "Excellent! ✓";
    verdictSub  = "You follow authentication best practices";
  }

  ringArc.setAttribute("stroke", ringColor);
  ringArc.style.filter = "drop-shadow(0 0 4px " + ringColor + "88)";
  if (labelEl) labelEl.textContent = verdictText;
  if (subEl)   subEl.textContent   = verdictSub;
}

/* ──────────────────────────────────────────────────────────────────────────
   22c. SESSION SECURITY MONITOR
────────────────────────────────────────────────────────────────────────── */
function initSessionMonitor() {
  const fill      = document.getElementById("stk-sess-fill");
  const gaugeLbl  = document.getElementById("stk-sess-label");
  if (!fill) return;

  // Helper to set a single indicator row
  function setIndicator(id, valId, dotId, value, dotClass) {
    const valEl = document.getElementById(valId);
    const dotEl = document.getElementById(dotId);
    if (valEl) valEl.textContent = value;
    if (dotEl) {
      dotEl.className = "stk-sess-item__dot " + dotClass;
    }
  }

  // 1. HTTPS
  const isHttps = window.location.protocol === "https:";
  const isLocalhost = window.location.hostname === "localhost"
                   || window.location.hostname === "127.0.0.1";
  const httpsOk = isHttps || isLocalhost;
  setIndicator(
    "sess-https", "sess-https-val", "sess-https-dot",
    httpsOk ? (isLocalhost ? "Localhost (dev) ✓" : "Secure HTTPS ✓") : "HTTP — Not Encrypted ✕",
    httpsOk ? "stk-dot--green" : "stk-dot--red"
  );

  // 2. Do Not Track
  const dntVal = navigator.doNotTrack || window.doNotTrack;
  const dntOn  = dntVal === "1" || dntVal === "yes";
  setIndicator(
    "sess-dnt", "sess-dnt-val", "sess-dnt-dot",
    dntOn ? "Enabled ✓" : "Not Enabled",
    dntOn ? "stk-dot--green" : "stk-dot--amber"
  );

  // 3. Cookies
  const cookiesOk = navigator.cookieEnabled;
  setIndicator(
    "sess-cookies", "sess-cookies-val", "sess-cookies-dot",
    cookiesOk ? "Enabled" : "Disabled",
    cookiesOk ? "stk-dot--cyan" : "stk-dot--amber"
  );

  // 4. JS — always true if we're running
  setIndicator(
    "sess-js", "sess-js-val", "sess-js-dot",
    "Active ✓", "stk-dot--green"
  );

  // 5. LocalStorage
  let lsOk = false;
  try {
    const k = "__stk_test__";
    localStorage.setItem(k, "1");
    localStorage.removeItem(k);
    lsOk = true;
  } catch (_) { lsOk = false; }
  setIndicator(
    "sess-storage", "sess-storage-val", "sess-storage-dot",
    lsOk ? "Available ✓" : "Blocked / Disabled",
    lsOk ? "stk-dot--cyan" : "stk-dot--amber"
  );

  // 6. Protocol
  const proto = window.location.protocol;
  setIndicator(
    "sess-protocol", "sess-protocol-val", "sess-protocol-dot",
    proto,
    isHttps || isLocalhost ? "stk-dot--green" : "stk-dot--red"
  );

  // Overall posture score
  const indicators = [httpsOk, dntOn, cookiesOk, true, lsOk, isHttps || isLocalhost];
  const passCount  = indicators.filter(Boolean).length;
  const pct        = Math.round((passCount / indicators.length) * 100);

  // Animate bar after brief delay so transition fires
  requestAnimationFrame(() => {
    setTimeout(() => {
      fill.style.width = pct + "%";
    }, 200);
  });

  if (gaugeLbl) {
    let lbl;
    if (pct >= 85)      lbl = "Secure Session ✓";
    else if (pct >= 60) lbl = "Moderate (" + pct + "%)";
    else                lbl = "Review Needed (" + pct + "%)";
    gaugeLbl.textContent = lbl;
    if (pct < 60) {
      fill.style.background = "linear-gradient(90deg, #ef4444, #f59e0b)";
      fill.style.boxShadow  = "0 0 8px rgba(239,68,68,.4)";
      gaugeLbl.style.color  = "#f87171";
    }
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   23. LIVE THREAT INTELLIGENCE PANEL
       Fetches /api/threats (same-origin — CSP safe).
       States: loading → feed | error | empty.
       Auto-loads on DOMContentLoaded; manual Refresh button with 5 s cooldown.
       SECURITY: textContent / setAttribute only — no innerHTML / eval.
═══════════════════════════════════════════════════════════════════════════ */

function initLiveThreatPanel() {
  const refreshBtn = document.getElementById("lti-refresh-btn");
  const retryBtn   = document.getElementById("lti-retry-btn");
  if (!refreshBtn) return;

  // Initial fetch
  fetchThreatFeed();

  // Refresh button — 5 s cooldown to prevent spam
  let cooldown = false;
  refreshBtn.addEventListener("click", () => {
    if (cooldown) return;
    cooldown = true;
    refreshBtn.disabled = true;
    fetchThreatFeed();
    setTimeout(() => {
      cooldown = false;
      refreshBtn.disabled = false;
    }, 5000);
  });

  retryBtn?.addEventListener("click", () => {
    fetchThreatFeed();
  });
}

/**
 * Fetch /api/threats, then render the panel.
 * All DOM writes use textContent / setAttribute — never innerHTML.
 */
function fetchThreatFeed() {
  ltiSetState("loading");

  const refreshBtn = document.getElementById("lti-refresh-btn");
  if (refreshBtn) refreshBtn.classList.add("lti-refresh-btn--spinning");

  fetch("/api/threats", {
    method: "GET",
    headers: { "Accept": "application/json" },
    credentials: "same-origin",
  })
    .then(res => {
      if (!res.ok) throw new Error("HTTP " + res.status);
      return res.json();
    })
    .then(data => {
      renderThreatFeed(data);
    })
    .catch(err => {
      ltiSetState("error", "Could not load threat data — check your connection.");
    })
    .finally(() => {
      const btn = document.getElementById("lti-refresh-btn");
      if (btn) btn.classList.remove("lti-refresh-btn--spinning");
    });
}

/** Show one of: loading | feed | error | empty */
function ltiSetState(state, errorMsg) {
  const elLoading = document.getElementById("lti-loading");
  const elError   = document.getElementById("lti-error");
  const elEmpty   = document.getElementById("lti-empty");
  const elFeed    = document.getElementById("lti-feed");
  const elChips   = document.getElementById("lti-chips");
  const elMeta    = document.getElementById("lti-meta");

  // Hide all, then show the right one
  if (elLoading) elLoading.hidden = (state !== "loading");
  if (elError)   elError.hidden   = (state !== "error");
  if (elEmpty)   elEmpty.hidden   = (state !== "empty");

  // Feed and chips are always visible once loaded, hidden during loading/error
  const showFeed = (state === "feed");
  if (elFeed)  elFeed.style.display  = showFeed ? "" : "none";
  if (elChips) elChips.style.display = showFeed ? "" : "none";
  if (elMeta)  elMeta.style.display  = showFeed ? "" : "none";

  if (state === "error" && errorMsg) {
    const msgEl = document.getElementById("lti-error-msg");
    if (msgEl) msgEl.textContent = errorMsg;
  }
}

/** Render the full panel from API payload — textContent only */
function renderThreatFeed(data) {
  const threats = Array.isArray(data.threats) ? data.threats : [];

  if (!threats.length) {
    ltiSetState("empty");
    return;
  }

  // Update meta strip
  const sourceBadge = document.getElementById("lti-source-badge");
  const updatedEl   = document.getElementById("lti-updated");
  if (sourceBadge) {
    const src = data.source || "fallback";
    sourceBadge.textContent = src === "live" ? "● Live" : src === "cache" ? "● Cached" : "● Curated";
    sourceBadge.className = "lti-source-badge lti-source-badge--" + src;
  }
  if (updatedEl) {
    const ts = data.updated || "";
    try {
      const d = new Date(ts);
      updatedEl.textContent = "Updated " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch (_) {
      updatedEl.textContent = "Just updated";
    }
  }

  // Tally severity chips
  let nCritical = 0, nHigh = 0, nMedium = 0;
  threats.forEach(t => {
    if (t.severity === "critical")     nCritical++;
    else if (t.severity === "high")    nHigh++;
    else                               nMedium++;
  });
  const elC = document.getElementById("lti-count-critical");
  const elH = document.getElementById("lti-count-high");
  const elM = document.getElementById("lti-count-medium");
  if (elC) elC.textContent = String(nCritical);
  if (elH) elH.textContent = String(nHigh);
  if (elM) elM.textContent = String(nMedium);

  // Build feed items — textContent only, no innerHTML
  const feed = document.getElementById("lti-feed");
  if (!feed) return;

  // Clear old items safely
  while (feed.firstChild) feed.removeChild(feed.firstChild);

  threats.forEach((threat, idx) => {
    const sev    = threat.severity || "medium";
    const domain = String(threat.domain || "unknown").slice(0, 50);
    const type   = String(threat.type   || "Phishing").slice(0, 60);
    const time   = String(threat.reported || "recently").slice(0, 30);
    const iocs   = Array.isArray(threat.iocs) ? threat.iocs.slice(0, 3) : [];

    const li = document.createElement("li");
    li.className = "lti-item lti-item--" + sev;
    li.style.animationDelay = (idx * 55) + "ms";

    // Dot
    const dot = document.createElement("span");
    dot.className = "lti-item__dot";
    dot.setAttribute("aria-hidden", "true");

    // Body
    const body = document.createElement("div");
    body.className = "lti-item__body";

    const domainEl = document.createElement("span");
    domainEl.className = "lti-item__domain";
    domainEl.textContent = domain;

    const typeEl = document.createElement("span");
    typeEl.className = "lti-item__type";
    typeEl.textContent = type;

    const iocsWrap = document.createElement("div");
    iocsWrap.className = "lti-item__iocs";

    iocs.forEach(ioc => {
      const tag = document.createElement("span");
      tag.className = "lti-ioc-tag";
      tag.textContent = String(ioc).slice(0, 24);
      iocsWrap.appendChild(tag);
    });

    body.append(domainEl, typeEl, iocsWrap);

    // Timestamp
    const timeEl = document.createElement("span");
    timeEl.className = "lti-item__time";
    timeEl.textContent = time;

    li.append(dot, body, timeEl);
    feed.appendChild(li);
  });

  ltiSetState("feed");
}

/* ==========================================================================
   TOOL 5 — Hash Generator
   Uses the Web Crypto API (SubtleCrypto) — zero network calls.
   ========================================================================== */

function initHashGenerator () {
  const inputEl   = document.getElementById("stk-hash-input");
  const outputEl  = document.getElementById("stk-hash-output");
  const copyBtn   = document.getElementById("stk-hash-copy");
  const algoLbl   = document.getElementById("stk-hash-algo-lbl");
  const lenEl     = document.getElementById("stk-hash-len");
  const bitsEl    = document.getElementById("stk-hash-bits");
  const algoBtns  = document.querySelectorAll("#stk-hash .stk-algo-btn");

  if (!inputEl) return;

  let currentAlgo = "SHA-256";

  const ALGO_BITS = { "SHA-256": 256, "SHA-512": 512, "SHA-1": 160 };

  // Algorithm selector
  algoBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      algoBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentAlgo = btn.dataset.algo;
      if (algoLbl) algoLbl.textContent = currentAlgo;
      computeHash();
    });
  });

  inputEl.addEventListener("input", computeHash);

  async function computeHash () {
    const text = inputEl.value;
    if (!text) {
      outputEl.textContent = "—";
      if (lenEl)  lenEl.textContent  = "—";
      if (bitsEl) bitsEl.textContent = "—";
      return;
    }
    try {
      const encoded = new TextEncoder().encode(text);
      const hashBuf = await crypto.subtle.digest(currentAlgo, encoded);
      const hashHex = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
      outputEl.textContent = hashHex;
      if (lenEl)  lenEl.textContent  = `${hashHex.length} hex chars`;
      if (bitsEl) bitsEl.textContent = `${ALGO_BITS[currentAlgo]} bits`;
    } catch (err) {
      outputEl.textContent = "Error: " + err.message;
    }
  }

  // Copy button
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      const val = outputEl.textContent;
      if (!val || val === "—") return;
      try {
        await navigator.clipboard.writeText(val);
        copyBtn.classList.add("copied");
        setTimeout(() => copyBtn.classList.remove("copied"), 1800);
      } catch (_) { /* clipboard not available */ }
    });
  }
}

/* ==========================================================================
   TOOL 6 — Payload Decoder (Base64 / URL-decode / Base64-encode)
   Runs entirely in browser — no server calls.
   ========================================================================== */

function initPayloadDecoder () {
  const inputEl   = document.getElementById("stk-dec-input");
  const outputEl  = document.getElementById("stk-dec-output");
  const statusEl  = document.getElementById("stk-dec-status");
  const copyBtn   = document.getElementById("stk-dec-copy");
  const modeBtns  = document.querySelectorAll("#stk-decoder .stk-algo-btn");

  if (!inputEl) return;

  let currentMode = "base64";

  modeBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      modeBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentMode = btn.dataset.mode;
      runDecode();
    });
  });

  inputEl.addEventListener("input", runDecode);

  function runDecode () {
    const raw = inputEl.value.trim();
    if (!raw) {
      outputEl.textContent = "—";
      setStatus("", "");
      return;
    }

    try {
      if (currentMode === "base64") {
        // Strip whitespace/newlines that many mail clients insert
        const cleaned = raw.replace(/\s/g, "");
        const decoded = atob(cleaned);
        outputEl.textContent = decoded;
        setStatus(`✓ Decoded ${decoded.length} characters`, "ok");
      } else if (currentMode === "urldecode") {
        const decoded = decodeURIComponent(raw);
        outputEl.textContent = decoded;
        setStatus(`✓ URL-decoded ${decoded.length} characters`, "ok");
      } else if (currentMode === "base64encode") {
        const encoded = btoa(unescape(encodeURIComponent(raw)));
        outputEl.textContent = encoded;
        setStatus(`✓ Encoded → ${encoded.length} characters`, "ok");
      }
    } catch (err) {
      outputEl.textContent = "—";
      setStatus(`✗ ${err.message}`, "err");
    }
  }

  function setStatus (msg, cls) {
    if (!statusEl) return;
    statusEl.textContent = msg;
    statusEl.className   = "stk-dec-status " + cls;
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      const val = outputEl.textContent;
      if (!val || val === "—") return;
      try {
        await navigator.clipboard.writeText(val);
        copyBtn.classList.add("copied");
        setTimeout(() => copyBtn.classList.remove("copied"), 1800);
      } catch (_) { /* clipboard not available */ }
    });
  }
}

/* ==========================================================================
   TOOL 7 — Email Header Analyser
   Parses raw email headers client-side and surfaces:
   - From / Reply-To mismatch
   - Authentication-Results (SPF / DKIM / DMARC) pass/fail
   - X-Originating-IP
   - Received: hop chain
   ========================================================================== */

function initEmailHeaderAnalyser () {
  const analyzeBtn = document.getElementById("stk-email-analyze");
  const inputEl    = document.getElementById("stk-email-input");
  const resultsEl  = document.getElementById("stk-email-results");
  const verdictEl  = document.getElementById("stk-email-verdict");
  const findingsEl = document.getElementById("stk-email-findings");
  const hopsEl     = document.getElementById("stk-email-hops");

  if (!analyzeBtn) return;

  analyzeBtn.addEventListener("click", () => {
    const raw = (inputEl.value || "").trim();
    if (!raw) return;
    analyzeHeaders(raw);
  });

  function parseHeaders (raw) {
    // Unfold RFC 5322 multi-line headers (CRLF or LF + whitespace continuation)
    const unfolded = raw.replace(/\r?\n[ \t]+/g, " ");
    const lines    = unfolded.split(/\r?\n/);
    const headers  = {};
    for (const line of lines) {
      const colon = line.indexOf(":");
      if (colon < 1) continue;
      const key = line.slice(0, colon).trim().toLowerCase();
      const val = line.slice(colon + 1).trim();
      if (!headers[key]) headers[key] = [];
      headers[key].push(val);
    }
    return headers;
  }

  function analyzeHeaders (raw) {
    const h = parseHeaders(raw);
    const findings = [];
    let riskScore  = 0;   // 0=clean, 1=warn, 2+=danger

    // ── 1. From vs Reply-To mismatch ────────────────────────────────────────
    const from     = (h["from"]     || [""])[0];
    const replyTo  = (h["reply-to"] || [""])[0];
    const fromAddr = extractEmail(from);
    const replyAddr = extractEmail(replyTo);

    if (fromAddr && replyAddr && fromAddr !== replyAddr) {
      findings.push({ cls: "warn", icon: "⚠", text: `From and Reply-To differ — From: ${fromAddr} · Reply-To: ${replyAddr}. Phishers use this to receive replies at an attacker address.` });
      riskScore += 2;
    } else if (fromAddr) {
      findings.push({ cls: "pass", icon: "✓", text: `From address: ${fromAddr}` });
    }

    // ── 2. Authentication-Results (SPF / DKIM / DMARC) ──────────────────────
    const authResults = (h["authentication-results"] || []).join(" ").toLowerCase();
    if (authResults) {
      checkAuthField("spf",   authResults, findings);
      checkAuthField("dkim",  authResults, findings);
      checkAuthField("dmarc", authResults, findings);
      const failCount = (authResults.match(/\bfail\b|\bfailure\b|\bnone\b/g) || []).length;
      riskScore += failCount;
    } else {
      findings.push({ cls: "warn", icon: "⚠", text: "No Authentication-Results header found — cannot verify SPF/DKIM/DMARC." });
      riskScore += 1;
    }

    // ── 3. DKIM-Signature present ────────────────────────────────────────────
    if (h["dkim-signature"]) {
      findings.push({ cls: "pass", icon: "✓", text: "DKIM-Signature header is present." });
    } else {
      findings.push({ cls: "warn", icon: "⚠", text: "No DKIM-Signature header — message was not cryptographically signed." });
      riskScore += 1;
    }

    // ── 4. X-Originating-IP ──────────────────────────────────────────────────
    const xip = (h["x-originating-ip"] || h["x-sender-ip"] || [])[0];
    if (xip) {
      findings.push({ cls: "info", icon: "ℹ", text: `Originating IP: ${xip}` });
    }

    // ── 5. Received: hop count ───────────────────────────────────────────────
    const received = h["received"] || [];
    if (received.length > 6) {
      findings.push({ cls: "warn", icon: "⚠", text: `${received.length} routing hops detected — unusually many hops can indicate obfuscation or relay abuse.` });
      riskScore += 1;
    } else if (received.length > 0) {
      findings.push({ cls: "pass", icon: "✓", text: `${received.length} routing hop(s) — within normal range.` });
    }

    // ── 6. Return-Path vs From mismatch ─────────────────────────────────────
    const returnPath = extractEmail((h["return-path"] || [""])[0]);
    if (returnPath && fromAddr && returnPath !== fromAddr) {
      const fromDomain      = fromAddr.split("@")[1]   || "";
      const returnDomain    = returnPath.split("@")[1]  || "";
      if (fromDomain && returnDomain && fromDomain !== returnDomain) {
        findings.push({ cls: "warn", icon: "⚠", text: `Return-Path domain (${returnDomain}) differs from From domain (${fromDomain}) — a common indicator of spoofing.` });
        riskScore += 2;
      }
    }

    // ── Render verdict ───────────────────────────────────────────────────────
    let verdictCls, verdictText;
    if (riskScore === 0) {
      verdictCls  = "ok";
      verdictText = "✓ Headers look clean — no obvious spoofing indicators.";
    } else if (riskScore <= 2) {
      verdictCls  = "warning";
      verdictText = "⚠ Suspicious — one or more authentication or routing anomalies detected. Verify before trusting this email.";
    } else {
      verdictCls  = "danger";
      verdictText = "✗ High Risk — multiple spoofing indicators found. This email may be forged or maliciously crafted.";
    }
    verdictEl.className   = "stk-email-verdict " + verdictCls;
    verdictEl.textContent = verdictText;

    // ── Render findings ──────────────────────────────────────────────────────
    while (findingsEl.firstChild) findingsEl.removeChild(findingsEl.firstChild);
    for (const f of findings) {
      const li   = document.createElement("li");
      li.className = "stk-email-finding " + f.cls;
      const iconSpan = document.createElement("span");
      iconSpan.className = "stk-email-finding__icon";
      iconSpan.setAttribute("aria-hidden", "true");
      iconSpan.textContent = f.icon;
      const textSpan = document.createElement("span");
      textSpan.textContent = safeText(f.text);
      li.append(iconSpan, textSpan);
      findingsEl.appendChild(li);
    }

    // ── Render routing hops ──────────────────────────────────────────────────
    while (hopsEl.firstChild) hopsEl.removeChild(hopsEl.firstChild);
    received.forEach((hop, i) => {
      const li   = document.createElement("li");
      li.className = "stk-email-hop";
      const fromMatch = hop.match(/from\s+(\S+)/i);
      const byMatch   = hop.match(/by\s+(\S+)/i);
      const hopText   = [
        fromMatch ? `from ${fromMatch[1]}` : null,
        byMatch   ? `by ${byMatch[1]}`     : null,
      ].filter(Boolean).join(" → ") || hop.slice(0, 80);
      const numSpan  = document.createElement("span");
      numSpan.className = "stk-email-hop__num";
      numSpan.textContent = String(i + 1);
      const textSpan = document.createElement("span");
      textSpan.className = "stk-email-hop__text";
      textSpan.textContent = safeText(hopText);
      li.append(numSpan, textSpan);
      hopsEl.appendChild(li);
    });
    if (received.length === 0) {
      const li = document.createElement("li");
      li.className = "stk-email-hop";
      const textSpan = document.createElement("span");
      textSpan.className = "stk-email-hop__text";
      textSpan.style.color = "var(--db-t3)";
      textSpan.textContent = "No Received: headers found.";
      li.appendChild(textSpan);
      hopsEl.appendChild(li);
    }

    resultsEl.hidden = false;
  }

  function checkAuthField (field, authStr, findings) {
    const passRe = new RegExp(`\\b${field}=pass`);
    const failRe = new RegExp(`\\b${field}=(fail|failure|none)`);
    if (passRe.test(authStr)) {
      findings.push({ cls: "pass", icon: "✓", text: `${field.toUpperCase()} passed.` });
    } else if (failRe.test(authStr)) {
      findings.push({ cls: "fail", icon: "✗", text: `${field.toUpperCase()} failed — this message may be forged or relayed.` });
    } else {
      findings.push({ cls: "info", icon: "ℹ", text: `${field.toUpperCase()} result not found in Authentication-Results.` });
    }
  }

  function extractEmail (str) {
    if (!str) return "";
    const m = str.match(/<([^>]+)>/) || str.match(/\S+@\S+\.\S+/);
    return m ? m[1] || m[0] : "";
  }

  function safeText (s) {
    return String(s || "");
  }
}

/* ── Wire up all new tools on DOMContentLoaded ─────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  initHashGenerator();
  initPayloadDecoder();
  initEmailHeaderAnalyser();
  initChintu();
});

/* ═══════════════════════════════════════════════════════════════════════════
   CHINTU — ThreatLens AI Assistant  (100% client-side, no external API)
   Knowledge base covers cybersecurity topics relevant to ThreatLens.
   SECURITY: All DOM writes use textContent/createElement — no innerHTML/eval.
═══════════════════════════════════════════════════════════════════════════ */

/* ── Knowledge base ────────────────────────────────────────────────────────── */
const CHINTU_KB = [
  {
    id: "phishing",
    keywords: ["phishing","phish","fake","spoof","credential","harvest"],
    title: "Phishing Attacks",
    answer: `**Phishing** is a social-engineering attack where an attacker masquerades as a trusted entity to steal credentials or sensitive data.\n\n*How to spot it:*\n- Urgency language ("Act now!", "Your account will be closed")\n- Sender domain slightly misspelled (paypal.support.xyz)\n- Generic greeting ("Dear Customer")\n- Links that hover-show a different domain\n- Requests for passwords, OTPs, or card numbers via email\n\n*ThreatLens detects:* misleading brand names in subdomains, suspicious TLDs, IP-address hosts, punycode domains, and URL shorteners — all common phishing indicators.`,
  },
  {
    id: "score",
    keywords: ["score","risk","rating","number","points","percentage","scale","mean","level"],
    title: "Risk Score Explained",
    answer: `ThreatLens produces a **risk score from 0 to 100** by summing the weights of every triggered heuristic rule:\n\n| Score | Level | Meaning |\n|---|---|---|\n| 0-24 | **Low** | No significant structural indicators |\n| 25-59 | **Medium** | One or more moderate indicators |\n| 60-100 | **High** | Multiple or severe indicators |\n\nThe score is *structural* — it reflects URL anatomy, not real-time threat intelligence. A score of 0 does **not** guarantee the site is safe.`,
  },
  {
    id: "https",
    keywords: ["https","http","ssl","tls","certificate","padlock","secure","encryption"],
    title: "HTTPS vs HTTP",
    answer: `**HTTPS** encrypts the connection between browser and server using TLS, preventing eavesdropping and man-in-the-middle attacks.\n\n*Key facts:*\n- The padlock icon means the *connection* is encrypted — it says nothing about whether the *site* is legitimate.\n- Phishing sites routinely obtain free TLS certificates (e.g. from Let\'s Encrypt). Over 80% of phishing pages now use HTTPS.\n- ThreatLens adds +10 to the risk score for http:// URLs, but a zero-score https:// URL can still be a phishing page.\n\n*Always check the domain name, not just the padlock.*`,
  },
  {
    id: "punycode",
    keywords: ["punycode","xn--","idn","homograph","unicode domain","cyrillic","lookalike","internationalized"],
    title: "Punycode / IDN Homograph Attacks",
    answer: `**Punycode** is an ASCII encoding of Unicode domain labels. Attackers use Unicode characters that look identical to Latin letters to register deceptive domains.\n\n*Example:* xn--pypal-4ve.com renders as paypal.com with a Cyrillic 'a' (U+0430), not a Latin 'a'.\n\nThreatLens flags any domain containing xn-- labels with a **+20 weight** — one of the highest single-rule penalties.`,
  },
  {
    id: "tld",
    keywords: ["tld","top level","domain extension",".xyz",".tk",".ml",".top",".click","suspicious tld","free domain"],
    title: "Suspicious TLDs",
    answer: `Certain top-level domains are disproportionately abused in phishing campaigns because they are free or very cheap:\n\n.xyz .tk .ml .ga .cf .gq .top .click .loan .work .date .faith .racing .stream .download\n\nThreatLens adds **+15** for any URL in this list. This does not mean every .xyz site is malicious — it is one signal among many.`,
  },
  {
    id: "url_shortener",
    keywords: ["short","bit.ly","tinyurl","t.co","shortener","shortened url","redirect","link shortener"],
    title: "URL Shorteners",
    answer: `**URL shorteners** (bit.ly, tinyurl.com, t.co, etc.) hide the real destination, making them a favourite tool for phishing and malware distribution.\n\n*Risks:*\n- The real URL is only revealed after you click\n- Shorteners can redirect differently based on geography or user-agent\n- Malicious campaigns rotate shortened URLs to avoid blocklists\n\nThreatLens adds **+15** for known shortener hosts. Always expand a short link with a preview tool before visiting.`,
  },
  {
    id: "ip_host",
    keywords: ["ip address","ip url","192.168","numeric ip","raw ip","ip host","ipv4","ipv6"],
    title: "IP Address as Host",
    answer: `Legitimate services almost never use a raw IP address in their public URLs. Phishing pages frequently use IP-hosted sites because:\n- No domain registration needed (avoids identity trails)\n- Easy to spin up and tear down quickly\n- No brand-spoof blocklist match\n\nThreatLens applies the **highest single-rule weight of +25** for this indicator.`,
  },
  {
    id: "subdomains",
    keywords: ["subdomain","sub-domain","too many dots","excessive subdomain","subdomain abuse","deep subdomain"],
    title: "Excessive Subdomains",
    answer: `A legitimate URL like mail.google.com has 1 subdomain. Phishing URLs often use many subdomain labels to hide the real registered domain:\n\nlogin.secure.paypal.verify.account.evil.com\n\nThe *registered domain* here is evil.com — not PayPal. ThreatLens flags **more than 3 subdomain labels** with a **+20 weight**.`,
  },
  {
    id: "misleading_brand",
    keywords: ["brand","impersonation","paypal","google","apple","microsoft","amazon","fake brand","brand abuse"],
    title: "Brand Impersonation",
    answer: `ThreatLens checks whether a well-known brand name (PayPal, Google, Apple, Microsoft, Amazon, etc.) appears in the *subdomain or path* while the *registered domain* is something else entirely.\n\n*Example:* paypal.secure-login.xyz/account — 'paypal' is in the subdomain, but the registered domain is 'secure-login.xyz'.\n\nThis rule carries a **+20 weight**.`,
  },
  {
    id: "2fa",
    keywords: ["2fa","two factor","mfa","multi factor","authenticator","otp","totp","sms code","verification code"],
    title: "Two-Factor Authentication (2FA)",
    answer: `**2FA** adds a second verification step beyond your password, dramatically reducing account-takeover risk even if your password is stolen.\n\n*Types (strongest to weakest):*\n1. **Hardware key** (YubiKey, FIDO2) — phishing-resistant\n2. **Authenticator app** (Google Authenticator, Authy, Aegis) — strong\n3. **Push notification** — moderate\n4. **SMS / email OTP** — weakest (SIM-swap, interception risk)\n\n*Note:* 2FA does **not** protect against real-time phishing proxies that relay your OTP instantly. Hardware FIDO2 keys are the only true phishing-resistant defence.`,
  },
  {
    id: "sql_injection",
    keywords: ["sql","sql injection","sqli","database","union select","drop table","injection","orm","prepared statement"],
    title: "SQL Injection",
    answer: `**SQL injection** occurs when untrusted user input is concatenated directly into a SQL query, allowing attackers to read, modify, or delete database data.\n\n*Classic example:*\nEntering ' OR '1'='1 in a login field returns all rows.\n\n*Defences:*\n- **Parameterised queries / prepared statements** — the only reliable fix\n- ORM with query builders (SQLAlchemy, Django ORM)\n- Input validation and type enforcement\n- Principle of least privilege on DB accounts\n\nThreatLens itself has no SQL backend, so it is not vulnerable to SQLi.`,
  },
  {
    id: "xss",
    keywords: ["xss","cross site scripting","script injection","dom xss","reflected","stored","csp","content security policy"],
    title: "Cross-Site Scripting (XSS)",
    answer: `**XSS** allows attackers to inject malicious scripts into web pages viewed by other users.\n\n*Types:*\n- **Stored XSS** — payload saved in the database, executed when others load the page\n- **Reflected XSS** — payload in the URL, executed immediately\n- **DOM XSS** — payload processed by client-side JS without server involvement\n\n*ThreatLens defences:*\n- All DOM output via textContent / createElement — no innerHTML\n- CSP: script-src 'self' only (no unsafe-inline)\n- Jinja2 auto-escaping enabled for all templates\n\n*General defences:* output encoding, strict CSP, HttpOnly cookies.`,
  },
  {
    id: "ssrf",
    keywords: ["ssrf","server side request","request forgery","internal network","localhost","127.0.0.1","metadata endpoint"],
    title: "Server-Side Request Forgery (SSRF)",
    answer: `**SSRF** tricks the server into making HTTP requests to internal resources (localhost, cloud metadata endpoints, internal services).\n\n*Classic target:* http://169.254.169.254/latest/meta-data/ (AWS metadata service)\n\n*ThreatLens SSRF posture:* analyzer.py is pure string/parse — zero network calls, zero I/O imports. It is physically impossible for ThreatLens to be used as an SSRF vector because the server never fetches submitted URLs.`,
  },
  {
    id: "owasp",
    keywords: ["owasp","top 10","owasp top","vulnerability list","common vulnerabilities","web security"],
    title: "OWASP Top 10",
    answer: `The **OWASP Top 10** (2021) lists the most critical web application security risks:\n\n1. **A01 Broken Access Control** — unauthorised access to resources\n2. **A02 Cryptographic Failures** — weak or missing encryption\n3. **A03 Injection** — SQLi, XSS, command injection\n4. **A04 Insecure Design** — missing threat modelling\n5. **A05 Security Misconfiguration** — default creds, open S3 buckets\n6. **A06 Vulnerable & Outdated Components** — unpatched libraries\n7. **A07 Identification & Authentication Failures** — weak passwords, no 2FA\n8. **A08 Software & Data Integrity Failures** — CI/CD compromise\n9. **A09 Security Logging & Monitoring Failures** — no audit trail\n10. **A10 SSRF** — server fetching attacker-controlled URLs`,
  },
  {
    id: "password",
    keywords: ["password","passphrase","strong password","password manager","breach","haveibeenpwned","credential stuffing","dictionary attack","brute force"],
    title: "Password Security",
    answer: `**Password best practices:**\n\n- Use a **password manager** (Bitwarden, 1Password, KeePass) to generate and store unique passwords\n- Minimum **16 characters**, random mix of letters, digits, symbols\n- **Never reuse** a password across sites\n- Check for breaches at haveibeenpwned.com\n- Enable **2FA** on all accounts that support it\n\n*Why length matters:* an 8-char password with 94 possible chars has 94^8 combinations — crackable in hours with modern GPUs. A 20-char password is effectively uncrackable by brute force.`,
  },
  {
    id: "email_spoofing",
    keywords: ["email spoof","spoofed email","from header","spf","dkim","dmarc","sender policy","mail authentication","fake email"],
    title: "Email Spoofing & Authentication",
    answer: `**Email spoofing** fakes the From: header to impersonate a trusted sender. Three DNS-based controls combat this:\n\n- **SPF** (Sender Policy Framework) — lists which mail servers may send on behalf of a domain\n- **DKIM** (DomainKeys Identified Mail) — cryptographic signature on outgoing mail\n- **DMARC** — policy that tells receivers what to do when SPF/DKIM fail (p=reject is strongest)\n\nThreatLens Email Header Analyser checks Authentication-Results headers for SPF, DKIM, and DMARC pass/fail and flags From/Reply-To mismatches.`,
  },
  {
    id: "social_engineering",
    keywords: ["social engineering","pretexting","vishing","smishing","baiting","tailgating","human hacking"],
    title: "Social Engineering",
    answer: `**Social engineering** manipulates people rather than systems. Common techniques:\n\n- **Phishing** — deceptive emails\n- **Vishing** — voice calls (fake bank/IT helpdesk)\n- **Smishing** — SMS-based phishing\n- **Pretexting** — fabricated scenario to extract information\n- **Baiting** — infected USB drives left in car parks\n- **Tailgating** — following an authorised person through a secure door\n\n*Defence:* security awareness training, verification callbacks, zero-trust access.`,
  },
  {
    id: "malware",
    keywords: ["malware","virus","trojan","ransomware","spyware","keylogger","rootkit","worm","payload","dropper"],
    title: "Malware Types",
    answer: `**Malware** (malicious software) categories:\n\n- **Virus** — self-replicates by attaching to legitimate files\n- **Worm** — self-replicates over networks without a host file\n- **Trojan** — disguises itself as legitimate software\n- **Ransomware** — encrypts files and demands payment\n- **Spyware / Keylogger** — silently records activity and keystrokes\n- **Rootkit** — hides in OS kernel for persistent stealthy access\n- **Dropper** — downloads and installs other malware\n\n*Key defences:* up-to-date AV/EDR, application allowlisting, least-privilege accounts, regular offline backups.`,
  },
  {
    id: "vpn",
    keywords: ["vpn","virtual private network","tunneling","proxy","tor","anonymity","privacy","ip mask"],
    title: "VPNs & Privacy",
    answer: `A **VPN** (Virtual Private Network) encrypts your traffic and routes it through a server in another location, masking your real IP address.\n\n*What a VPN does:*\n- Encrypts traffic on untrusted networks (public Wi-Fi)\n- Hides your IP from websites and your ISP\n\n*What a VPN does NOT do:*\n- Make you anonymous (the VPN provider can see your traffic)\n- Protect against phishing or malware on the destination site\n- Prevent browser fingerprinting\n\nFor stronger anonymity, **Tor** routes traffic through multiple relays, but is significantly slower.`,
  },
  {
    id: "firewall",
    keywords: ["firewall","waf","network security","packet filter","stateful","web application firewall","intrusion detection","ids","ips"],
    title: "Firewalls & WAFs",
    answer: `**Firewall** types:\n\n- **Packet filter** — allows/blocks traffic by IP/port rules\n- **Stateful inspection** — tracks connection state for smarter filtering\n- **Application-layer / NGFW** — inspects payload content\n- **WAF** (Web Application Firewall) — specifically defends HTTP/HTTPS apps against SQLi, XSS, CSRF, and other OWASP Top 10 attacks\n\nA WAF sits in front of your web server and can block or rate-limit malicious request patterns before they reach your application code.`,
  },
  {
    id: "cve",
    keywords: ["cve","vulnerability","exploit","patch","zero day","0day","disclosure","nvd","cvss"],
    title: "CVEs & Vulnerability Management",
    answer: `**CVE** (Common Vulnerabilities and Exposures) is a standardised identifier for publicly known vulnerabilities (e.g. CVE-2021-44228 = Log4Shell).\n\n**CVSS** rates severity 0-10:\n- 9.0-10.0 = Critical\n- 7.0-8.9 = High\n- 4.0-6.9 = Medium\n- 0.1-3.9 = Low\n\n*Lifecycle:* Discovery, vendor notification, patch release, public disclosure. A **zero-day** is a vulnerability with no patch yet available.`,
  },
  {
    id: "rate_limiting",
    keywords: ["rate limit","too many requests","429","dos","ddos","throttle","brute force protection","abuse"],
    title: "Rate Limiting & Brute-Force Protection",
    answer: `ThreatLens enforces **30 requests/minute per IP** on /api/analyze using flask-limiter. Exceeding this returns HTTP 429 Too Many Requests.\n\n*Why rate limiting matters:*\n- Prevents automated brute-force attacks\n- Limits credential-stuffing attempts\n- Reduces DoS amplification\n\n*Note:* With 2 Gunicorn workers the effective limit is 60 req/min. For accurate cross-worker limiting, set RATELIMIT_STORAGE_URI=redis://...`,
  },
  {
    id: "csp",
    keywords: ["csp","content security policy","script src","unsafe inline","frame ancestors","security header","http header"],
    title: "Content Security Policy (CSP)",
    answer: `**CSP** is an HTTP response header that tells browsers which sources of scripts, styles, images, and other resources are allowed.\n\nThreatLens CSP directives:\n- script-src 'self' (no external scripts, no inline)\n- object-src 'none'\n- base-uri 'self'\n- form-action 'self'\n- frame-ancestors 'none' (prevents clickjacking)\n\nscript-src 'self' blocks all inline scripts and external script loads — a strong XSS mitigation.`,
  },
  {
    id: "cookies",
    keywords: ["cookie","session","httponly","samesite","secure flag","csrf","cross site request","token"],
    title: "Cookies & CSRF",
    answer: `**Secure cookie flags:**\n- HttpOnly — JavaScript cannot access the cookie (mitigates XSS-based cookie theft)\n- Secure — cookie only sent over HTTPS\n- SameSite=Strict — cookie not sent in cross-site requests (strong CSRF protection)\n- SameSite=Lax — cookie sent on top-level navigation (balanced protection)\n\n**CSRF** (Cross-Site Request Forgery) tricks a logged-in user into making state-changing requests to a site they trust. Defences: SameSite cookies, CSRF tokens, Origin/Referer header checks.`,
  },
  {
    id: "dns",
    keywords: ["dns","domain name","nameserver","dns poisoning","dns spoofing","dnssec","typosquatting"],
    title: "DNS & Typosquatting",
    answer: `**DNS** (Domain Name System) translates domain names to IP addresses. Attacks on DNS include:\n\n- **DNS cache poisoning** — injects fake records into a resolver cache\n- **DNS hijacking** — changes legitimate DNS records at the registrar level\n- **Typosquatting** — registering domains similar to popular brands (googgle.com, paypa1.com)\n- **DNS tunnelling** — exfiltrates data by encoding it in DNS query strings\n\n**DNSSEC** signs DNS records cryptographically to prevent poisoning attacks.`,
  },
  {
    id: "api_security",
    keywords: ["api","rest","jwt","token","bearer","api key","authentication","authorisation","oauth"],
    title: "API Security",
    answer: `Common API security issues:\n\n- **Broken Object Level Authorisation (BOLA)** — accessing another user\'s resources by changing an ID\n- **Excessive Data Exposure** — returning more fields than the client needs\n- **Broken Authentication** — weak tokens, no expiry, predictable keys\n- **Injection** — SQLi/XSS via API request bodies\n- **Rate limiting absent** — enables brute force and enumeration\n\nThreatLens API defences: input validation, strict Content-Type enforcement, 2 KB request size cap, rate limiting, no CORS, security headers on every response.`,
  },
  {
    id: "incident_response",
    keywords: ["incident","breach","response","ir","contain","eradicate","recover","forensic","dfir"],
    title: "Incident Response",
    answer: `The **NIST Incident Response lifecycle** has 4 phases:\n\n1. **Preparation** — policies, runbooks, tools, training\n2. **Detection & Analysis** — identify and scope the incident\n3. **Containment, Eradication & Recovery** — isolate affected systems, remove threat, restore service\n4. **Post-Incident Activity** — lessons learned, timeline reconstruction, report\n\n*First actions in a suspected breach:* isolate the affected system from the network, preserve logs before clearing, change credentials, notify relevant parties.`,
  },
  {
    id: "cryptography",
    keywords: ["encryption","decrypt","aes","rsa","hash","sha","md5","asymmetric","symmetric","key","cipher"],
    title: "Cryptography Basics",
    answer: `**Symmetric encryption** (AES-256) — same key encrypts and decrypts. Fast; key exchange is the challenge.\n\n**Asymmetric encryption** (RSA, ECC) — public key encrypts, private key decrypts. Slower; solves key distribution.\n\n**Hashing** (SHA-256, SHA-3) — one-way function; same input always produces the same digest; any change in input produces a completely different digest.\n\n*MD5 and SHA-1 are cryptographically broken* — do not use them for security. Use SHA-256 or better.\n\nThreatLens Hash Generator uses the browser Web Crypto API (SHA-1, SHA-256, SHA-512) for in-browser hashing.`,
  },
  {
    id: "threatlens_how",
    keywords: ["how does threatlens","how it works","how threatlens","what does threatlens","tool explanation","threatlens works","what rules","heuristic"],
    title: "How ThreatLens Works",
    answer: `**ThreatLens** analyses the *structure* of a URL using 17 heuristic rules — it never fetches or visits the URL.\n\n*Pipeline:*\n1. URL submitted via the scan form or POST /api/analyze\n2. analyzer.py normalises the URL (strips credentials, lowercases host)\n3. Each of the 17 rules inspects the parsed URL components\n4. Triggered rule weights are summed and clamped to [0, 100]\n5. Score is classified as Low / Medium / High\n6. Results (score, indicators, recommendations, disclaimer) returned as JSON\n7. dashboard-ui.js renders the result and updates all live charts\n\n*No data is ever stored.* Each scan result lives only in your browser session.`,
  },
  {
    id: "chintu_self",
    keywords: ["who are you","what are you","about you","chintu","ai assistant","your name","introduce yourself","hello","hi","hey"],
    title: "About Chintu",
    answer: `Hi! I\'m **Chintu**, the ThreatLens AI assistant.\n\nI run entirely in your browser — no data is sent to any server. I know about:\n- Phishing tactics and URL indicators\n- How ThreatLens scores and classifies URLs\n- Web security (XSS, SQLi, SSRF, CSRF, CSP)\n- Password security, 2FA, and cryptography\n- OWASP Top 10, CVEs, incident response\n- Email spoofing, DNS attacks, malware types\n\nAsk me anything about cybersecurity or how ThreatLens works!`,
  },
];

const CHINTU_FALLBACKS = [
  `Hmm, that one\'s outside my knowledge base. Try asking about phishing, XSS, HTTPS, 2FA, OWASP, or how ThreatLens works!`,
  `I\'m not sure about that. I\'m best at cybersecurity topics — phishing, URL analysis, passwords, encryption, and more.`,
  `Good question! That\'s outside my current knowledge. Ask me about ThreatLens heuristic rules or common web vulnerabilities.`,
  `I didn\'t quite catch that. Could you try rephrasing? I know a lot about phishing, malware, firewalls, CVEs, and web security.`,
  `That topic is beyond my expertise. Try: What is XSS? or How does ThreatLens score URLs? or What is 2FA?`,
];

/* ── Response engine ──────────────────────────────────────────────────────── */
function chintuRespond (msg) {
  const q = msg.toLowerCase().replace(/[^\w\s]/g, " ");
  const words = q.split(/\s+/).filter(Boolean);

  // Score each KB entry by keyword match count
  let best = null;
  let bestScore = 0;

  for (const entry of CHINTU_KB) {
    let score = 0;
    for (const kw of entry.keywords) {
      if (q.includes(kw)) score += kw.split(" ").length * 2;  // multi-word = higher weight
    }
    // Fuzzy: partial word matches
    if (score === 0) {
      for (const kw of entry.keywords) {
        for (const w of words) {
          if (w.length > 3 && kw.includes(w)) score += 1;
        }
      }
    }
    if (score > bestScore) { bestScore = score; best = entry; }
  }

  if (best && bestScore > 0) {
    return { title: best.title, answer: best.answer };
  }
  const fallback = CHINTU_FALLBACKS[Math.floor(Math.random() * CHINTU_FALLBACKS.length)];
  return { title: null, answer: fallback };
}

/* ── Markdown-lite renderer (returns DocumentFragment, no innerHTML) ──────── */
function renderMarkdownLite (text) {
  const frag = document.createDocumentFragment();
  const lines = text.split("\n");

  let inList = false;
  let listEl = null;
  let inTable = false;
  let tableEl = null;

  const flushList = () => {
    if (inList && listEl) { frag.appendChild(listEl); inList = false; listEl = null; }
  };
  const flushTable = () => {
    if (inTable && tableEl) { frag.appendChild(tableEl); inTable = false; tableEl = null; }
  };

  const makeSpans = (raw) => {
    // Parse inline **bold**, *italic*, `code` into child nodes
    const span = document.createDocumentFragment();
    const re = /(\*\*(.+?)\*\*|\*(.+?)\*|`([^`]+)`)/g;
    let last = 0, m;
    while ((m = re.exec(raw)) !== null) {
      if (m.index > last) span.appendChild(document.createTextNode(raw.slice(last, m.index)));
      if (m[2] !== undefined) {
        const b = document.createElement("strong"); b.textContent = m[2]; span.appendChild(b);
      } else if (m[3] !== undefined) {
        const em = document.createElement("em"); em.textContent = m[3]; span.appendChild(em);
      } else if (m[4] !== undefined) {
        const code = document.createElement("code"); code.textContent = m[4]; span.appendChild(code);
      }
      last = re.lastIndex;
    }
    if (last < raw.length) span.appendChild(document.createTextNode(raw.slice(last)));
    return span;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Code block (``` fence)
    if (line.startsWith("```")) {
      flushList(); flushTable();
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      i++;
      const codeLines = [];
      while (i < lines.length && !lines[i].startsWith("```")) { codeLines.push(lines[i]); i++; }
      code.textContent = codeLines.join("\n");
      pre.appendChild(code);
      frag.appendChild(pre);
      continue;
    }

    // Table row  |a|b|c|
    if (line.startsWith("|") && line.endsWith("|")) {
      flushList();
      if (!inTable) {
        inTable = true;
        tableEl = document.createElement("table");
        tableEl.className = "chintu-table";
      }
      // Skip separator rows |---|---|
      if (/^\|[-:\s|]+\|$/.test(line)) continue;
      const cols = line.slice(1, -1).split("|").map(c => c.trim());
      const isHeader = lines[i - 1] === undefined || !lines[i - 1].startsWith("|");
      const row = document.createElement("tr");
      cols.forEach(col => {
        const cell = document.createElement(isHeader ? "th" : "td");
        cell.appendChild(makeSpans(col));
        row.appendChild(cell);
      });
      tableEl.appendChild(row);
      continue;
    } else if (inTable) {
      flushTable();
    }

    // Heading #
    if (/^#{1,3}\s/.test(line)) {
      flushList(); flushTable();
      const level = line.match(/^(#+)/)[1].length;
      const el = document.createElement("h" + Math.min(level + 2, 6));
      el.appendChild(makeSpans(line.replace(/^#+\s*/, "")));
      frag.appendChild(el);
      continue;
    }

    // Bullet list  - or *
    if (/^[-*]\s+/.test(line)) {
      flushTable();
      if (!inList) {
        inList = true;
        listEl = document.createElement("ul");
      }
      const li = document.createElement("li");
      li.appendChild(makeSpans(line.replace(/^[-*]\s+/, "")));
      listEl.appendChild(li);
      continue;
    }

    // Numbered list  1.
    if (/^\d+\.\s+/.test(line)) {
      flushTable();
      if (!inList || listEl.tagName !== "OL") {
        flushList();
        inList = true;
        listEl = document.createElement("ol");
      }
      const li = document.createElement("li");
      li.appendChild(makeSpans(line.replace(/^\d+\.\s+/, "")));
      listEl.appendChild(li);
      continue;
    }

    // Blank line
    if (line.trim() === "") {
      flushList(); flushTable();
      continue;
    }

    // Normal paragraph
    flushList(); flushTable();
    const p = document.createElement("p");
    p.appendChild(makeSpans(line));
    frag.appendChild(p);
  }

  flushList(); flushTable();
  return frag;
}

/* ── DOM helpers ──────────────────────────────────────────────────────────── */
function chintuTimestamp () {
  const now = new Date();
  return now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function chintuAppendMessage (role, text, messagesEl) {
  const row = document.createElement("div");  row.className = "chintu-msg chintu-msg--" + role;

  // Avatar
  const avatar = document.createElement("span");
  avatar.className = "chintu-msg__avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.textContent = role === "bot" ? "C" : "U";

  // Bubble
  const bubble = document.createElement("div");
  bubble.className = "chintu-msg__bubble";
  bubble.appendChild(renderMarkdownLite(text));

  // Timestamp
  const ts = document.createElement("span");
  ts.className = "chintu-msg__time";
  ts.textContent = chintuTimestamp();

  row.append(avatar, bubble, ts);
  messagesEl.appendChild(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function chintuShowTyping (messagesEl) {
  const row = document.createElement("div");
  row.className = "chintu-msg chintu-msg--bot";
  row.id = "chintu-typing-dynamic";

  const avatar = document.createElement("span");
  avatar.className = "chintu-msg__avatar";
  avatar.setAttribute("aria-hidden", "true");
  avatar.textContent = "C";

  const dotsWrap = document.createElement("div");
  dotsWrap.className = "chintu-typing__dots";
  dotsWrap.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 3; i++) {
    const dot = document.createElement("span");
    dotsWrap.appendChild(dot);
  }

  row.append(avatar, dotsWrap);
  messagesEl.appendChild(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return row;
}

/* ── Main init ────────────────────────────────────────────────────────────── */
function initChintu () {
  const bubble     = document.getElementById("chintu-bubble");
  const panel      = document.getElementById("chintu-panel");
  const closeBtn   = document.getElementById("chintu-close-btn");
  const minimiseBtn= document.getElementById("chintu-min-btn");
  const sendBtn    = document.getElementById("chintu-send-btn");
  const inputEl    = document.getElementById("chintu-input");
  const messagesEl = document.getElementById("chintu-messages");
  const badge      = document.getElementById("chintu-notif");
  const clearBtn   = document.getElementById("chintu-clear-btn");
  const pillsEl    = document.getElementById("chintu-topics");

  if (!bubble || !panel || !messagesEl || !inputEl || !sendBtn) return;

  // ── State ────────────────────────────────────────────────────────────────
  let isOpen = false;
  let unread = 0;

  // ── Open / close ─────────────────────────────────────────────────────────
  function openPanel () {
    isOpen = true;
    panel.hidden = false;
    panel.setAttribute("aria-hidden", "false");
    bubble.setAttribute("aria-expanded", "true");
    inputEl.focus();
    unread = 0;
    if (badge) { badge.textContent = "0"; badge.hidden = true; }
  }

  function closePanel () {
    isOpen = false;
    panel.hidden = true;
    panel.setAttribute("aria-hidden", "true");
    bubble.setAttribute("aria-expanded", "false");
    bubble.focus();
  }

  bubble.addEventListener("click", () => isOpen ? closePanel() : openPanel());
  bubble.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); isOpen ? closePanel() : openPanel(); } });

  if (closeBtn)    closeBtn.addEventListener("click",    closePanel);
  if (minimiseBtn) minimiseBtn.addEventListener("click", closePanel);

  // Close on Escape
  panel.addEventListener("keydown", (e) => { if (e.key === "Escape") closePanel(); });

  // ── Drag support ─────────────────────────────────────────────────────────
  const header = panel.querySelector(".chintu-header");
  if (header) {
    let dragging = false, ox = 0, oy = 0, startRight = 0, startBottom = 0;

    header.style.cursor = "grab";

    header.addEventListener("mousedown", (e) => {
      if (e.target === closeBtn || e.target === minimiseBtn) return;
      dragging = true;
      header.style.cursor = "grabbing";
      const rect  = panel.getBoundingClientRect();
      ox = e.clientX - rect.left;
      oy = e.clientY - rect.top;
      // Convert current right/bottom to concrete px
      startRight  = window.innerWidth  - rect.right;
      startBottom = window.innerHeight - rect.bottom;
      panel.style.right  = startRight  + "px";
      panel.style.bottom = startBottom + "px";
      panel.style.left   = "auto";
      panel.style.top    = "auto";
      e.preventDefault();
    });

    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      const newLeft   = e.clientX - ox;
      const newTop    = e.clientY - oy;
      const newRight  = window.innerWidth  - newLeft - panel.offsetWidth;
      const newBottom = window.innerHeight - newTop  - panel.offsetHeight;
      panel.style.right  = Math.max(0, newRight)  + "px";
      panel.style.bottom = Math.max(0, newBottom) + "px";
    });

    document.addEventListener("mouseup", () => {
      if (dragging) { dragging = false; header.style.cursor = "grab"; }
    });
  }

  // ── Send message ─────────────────────────────────────────────────────────
  function sendMessage () {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = "";

    chintuAppendMessage("user", text, messagesEl);

    // Typing indicator
    const typingEl = chintuShowTyping(messagesEl);

    setTimeout(() => {
      typingEl.remove();
      const { title, answer } = chintuRespond(text);
      const response = title ? `**${title}**\n\n${answer}` : answer;
      chintuAppendMessage("bot", response, messagesEl);

      if (!isOpen) {
        unread++;
        if (badge) { badge.textContent = String(unread); badge.hidden = false; }
      }
    }, 500 + Math.random() * 400);
  }

  sendBtn.addEventListener("click", sendMessage);
  inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  // ── Clear chat ────────────────────────────────────────────────────────────
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      while (messagesEl.firstChild) messagesEl.removeChild(messagesEl.firstChild);
      chintuAppendMessage("bot", "Chat cleared! Ask me anything about cybersecurity or ThreatLens.", messagesEl);
    });
  }

  // ── Topic pills ───────────────────────────────────────────────────────────
  if (pillsEl) {
    pillsEl.addEventListener("click", (e) => {
      const btn = e.target.closest(".chintu-topic-pill");
      if (!btn) return;
      const topic = btn.dataset.topic || btn.textContent.trim();
      inputEl.value = topic;
      sendMessage();
    });
  }

  // ── Greeting ──────────────────────────────────────────────────────────────
  setTimeout(() => {
    chintuAppendMessage("bot",
      "Hi! I'm **Chintu**, your ThreatLens AI assistant. 👋\n\nI can help with:\n- How ThreatLens scores URLs\n- Phishing, XSS, SQLi, SSRF, and other threats\n- Password security, 2FA, encryption\n- OWASP Top 10, CVEs, incident response\n\nWhat would you like to know?",
      messagesEl
    );
    if (!isOpen) {
      unread++;
      if (badge) { badge.textContent = String(unread); badge.hidden = false; }
    }
  }, 1200);
}
