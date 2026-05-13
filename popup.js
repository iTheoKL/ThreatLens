// ThreatLens Popup Script
"use strict";

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const enableToggle   = document.getElementById("enableToggle");
const statusBar      = document.getElementById("statusBar");
const statusText     = document.getElementById("statusText");
const listsLoaded    = document.getElementById("listsLoaded");
const safeCount      = document.getElementById("safeCount");
const warningCount   = document.getElementById("warningCount");
const dangerCount    = document.getElementById("dangerCount");
const lastScanEl     = document.getElementById("lastScan");
const totalScannedEl = document.getElementById("totalScanned");
const rescanBtn      = document.getElementById("rescanBtn");
const resetBtn       = document.getElementById("resetBtn");
const clearListsBtn  = document.getElementById("clearListsBtn");

// Safety indicator
const safetyBlock    = document.getElementById("safetyBlock");
const safetyOrb      = document.getElementById("safetyOrb");
const safetyLabel    = document.getElementById("safetyLabel");
const safetySub      = document.getElementById("safetySub");

// Footer site
const footerSite     = document.getElementById("footerSite");
const siteFavicon    = document.getElementById("siteFavicon");
const siteHostname   = document.getElementById("siteHostname");

// ─── Safety indicator icons ────────────────────────────────────────────────────
const SAFETY_ICONS = {
  safe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M20 6L9 17l-5-5"/>
  </svg>`,
  warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>`,
  danger: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="12" cy="12" r="10"/>
    <line x1="15" y1="9" x2="9" y2="15"/>
    <line x1="9" y1="9" x2="15" y2="15"/>
  </svg>`,
  idle: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>`,
};

const SAFETY_LABELS = {
  safe:    "Safe",
  warning: "Suspicious",
  danger:  "Dangerous",
  idle:    "Not scanned",
};

const SAFETY_SUBS = {
  safe:    "No threats detected on this page",
  warning: "Suspicious patterns detected — use caution",
  danger:  "Phishing detected — do not interact",
  idle:    "Open a page and click Re-scan",
};

function updateSafetyIndicator(level) {
  const l = ["safe","warning","danger"].includes(level) ? level : "idle";
  safetyBlock.className = "safety-block " + l;
  safetyOrb.innerHTML = SAFETY_ICONS[l];
  safetyLabel.textContent = SAFETY_LABELS[l];
  safetySub.textContent   = SAFETY_SUBS[l];
}

// ─── Tab handling ──────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

// ─── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg) {
  let toast = document.querySelector(".toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add("show");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove("show"), 2000);
}

// ─── Count animation ──────────────────────────────────────────────────────────
function animateCount(el, target) {
  const start = parseInt(el.textContent) || 0;
  if (start === target) return;
  const duration = 380;
  const startTime = performance.now();
  function step(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    el.textContent = Math.round(start + (target - start) * progress);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

function formatTime(isoString) {
  if (!isoString) return "No scans yet";
  const d = new Date(isoString);
  return "Last scan " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// ─── Status banner ─────────────────────────────────────────────────────────────
function updateStatusBanner(enabled) {
  if (enabled) {
    statusBar.classList.remove("disabled");
    statusText.textContent = "Protection active";
  } else {
    statusBar.classList.add("disabled");
    statusText.textContent = "Protection paused";
  }
}

// ─── Derive safety level from stats ───────────────────────────────────────────
function levelFromStats(s) {
  if (!s || (!s.safe && !s.warning && !s.danger)) return "idle";
  if (s.danger  > 0) return "danger";
  if (s.warning > 0) return "warning";
  return "safe";
}

// ─── Load stats from background ───────────────────────────────────────────────
function loadStats() {
  chrome.runtime.sendMessage({ type: "GET_STATS" }, (resp) => {
    if (chrome.runtime.lastError || !resp || !resp.stats) return;
    const s = resp.stats;
    animateCount(safeCount, s.safe || 0);
    animateCount(warningCount, s.warning || 0);
    animateCount(dangerCount, s.danger || 0);
    lastScanEl.textContent = formatTime(s.lastScan);
    totalScannedEl.textContent = (s.totalScanned || 0) + " scanned";
    updateSafetyIndicator(levelFromStats(s));
  });
}

// ─── Load settings ─────────────────────────────────────────────────────────────
function loadSettings() {
  chrome.storage.local.get(["threatlensEnabled", "threatlensSettings"], (data) => {
    const enabled = data.threatlensEnabled !== false;
    enableToggle.checked = enabled;
    updateStatusBanner(enabled);

    const settings = data.threatlensSettings || {};
    const mapping = {
      "chk-phishing": settings.checkPhishingDB !== false,
      "chk-domain":   settings.checkDomains !== false,
      "chk-ssl":      settings.checkSSL !== false,
      "chk-mismatch": settings.checkLinkMismatch !== false,
      "chk-urgency":  settings.checkUrgency !== false,
    };
    for (const [id, on] of Object.entries(mapping)) {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = on ? "ON" : "OFF";
        el.className = "check-pill " + (on ? "on" : "off");
      }
    }
  });
}

// ─── Load and display custom list metadata ─────────────────────────────────────
function loadCustomListsMeta() {
  chrome.storage.local.get(["tl_custom_domains", "tl_custom_ips", "tl_custom_links"], (data) => {
    const domainArr = data.tl_custom_domains || [];
    const ipArr     = data.tl_custom_ips     || [];
    const linkArr   = data.tl_custom_links   || [];
    const total     = [domainArr, ipArr, linkArr].filter(a => a.length > 0).length;

    listsLoaded.textContent = total > 0
      ? `${total} custom list${total > 1 ? "s" : ""} active`
      : "No custom lists";

    updateSlot("domains", domainArr);
    updateSlot("ips",     ipArr);
    updateSlot("links",   linkArr);

    const customPill = document.getElementById("chk-custom");
    const customSub  = document.getElementById("customListsSub");
    if (total > 0) {
      const totalEntries = domainArr.length + ipArr.length + linkArr.length;
      customPill.textContent = "ON";
      customPill.className = "check-pill on";
      customSub.textContent = `${totalEntries.toLocaleString()} entries across ${total} list${total > 1 ? "s" : ""}`;
    } else {
      customPill.textContent = "OFF";
      customPill.className = "check-pill off";
      customSub.textContent = "No lists loaded";
    }
  });
}

function updateSlot(type, arr) {
  const slot  = document.getElementById("slot-" + type);
  const count = document.getElementById("count-" + type);
  if (!slot || !count) return;
  if (arr.length > 0) {
    slot.classList.add("loaded");
    count.textContent = arr.length.toLocaleString() + " entries";
  } else {
    slot.classList.remove("loaded");
    count.textContent = "Not loaded";
  }
}

// ─── Current site in footer ────────────────────────────────────────────────────
function loadCurrentSite() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) return;
    try {
      const url = new URL(tab.url);
      if (!["http:", "https:"].includes(url.protocol)) return;
      const hostname = url.hostname.replace(/^www\./, "");
      siteHostname.textContent = hostname;
      siteFavicon.src = `https://www.google.com/s2/favicons?domain=${hostname}&sz=16`;
      siteFavicon.onerror = () => { siteFavicon.style.display = "none"; };
      footerSite.style.display = "flex";
    } catch { /* non-navigable tab */ }
  });
}

// ─── File loading ──────────────────────────────────────────────────────────────
function parseListFile(text) {
  return text
    .split(/\r?\n/)
    .map(line => line.trim().replace(/^#.*/, "").trim())
    .filter(Boolean);
}

document.querySelectorAll(".file-input").forEach(input => {
  input.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const listType = input.dataset.list;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const entries = parseListFile(ev.target.result);
      const key = "tl_custom_" + listType;
      chrome.storage.local.set({ [key]: entries }, () => {
        showToast(`Loaded ${entries.length.toLocaleString()} ${listType}`);
        loadCustomListsMeta();
      });
    };
    reader.readAsText(file);
    input.value = "";
  });
});

// ─── Clear all lists ───────────────────────────────────────────────────────────
clearListsBtn.addEventListener("click", () => {
  chrome.storage.local.remove(["tl_custom_domains", "tl_custom_ips", "tl_custom_links"], () => {
    showToast("Custom lists cleared");
    loadCustomListsMeta();
  });
});

// ─── Enable toggle ─────────────────────────────────────────────────────────────
enableToggle.addEventListener("change", () => {
  const enabled = enableToggle.checked;
  chrome.storage.local.set({ threatlensEnabled: enabled });
  updateStatusBanner(enabled);
});

// ─── Rescan ─────────────────────────────────────────────────────────────────────
rescanBtn.addEventListener("click", () => {
  rescanBtn.classList.add("spinning");
  rescanBtn.disabled = true;
  chrome.runtime.sendMessage({ type: "RESCAN_TAB" }, () => {
    setTimeout(() => {
      rescanBtn.classList.remove("spinning");
      rescanBtn.disabled = false;
      loadStats();
    }, 1200);
  });
});

// ─── Reset stats ───────────────────────────────────────────────────────────────
resetBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "RESET_STATS" }, () => {
    animateCount(safeCount, 0);
    animateCount(warningCount, 0);
    animateCount(dangerCount, 0);
    lastScanEl.textContent = "No scans yet";
    totalScannedEl.textContent = "0 scanned";
    updateSafetyIndicator("idle");
    showToast("Stats reset");
  });
});

// ─── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  loadStats();
  loadCustomListsMeta();
  loadCurrentSite();
});
