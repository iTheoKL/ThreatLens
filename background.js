// ThreatLens Background Service Worker
// Manages extension state, badge, and per-tab scan statistics

"use strict";

// ─── State ────────────────────────────────────────────────────────────────────
// Per-tab stats map: { [tabId]: { safe, warning, danger, lastScan, totalScanned } }
let tabStats = {};

function getTabStats(tabId) {
  if (!tabStats[tabId]) {
    tabStats[tabId] = { safe: 0, warning: 0, danger: 0, lastScan: null, totalScanned: 0 };
  }
  return tabStats[tabId];
}

// ─── Badge helpers ────────────────────────────────────────────────────────────
const BADGE_CONFIG = {
  safe:    { text: "✓",  color: "#22c55e" },
  warning: { text: "!",  color: "#f59e0b" },
  danger:  { text: "!!",  color: "#ef4444" },
  idle:    { text: "",   color: "#64748b" },
};

function setBadge(level, tabId) {
  const cfg = BADGE_CONFIG[level] || BADGE_CONFIG.idle;
  const details      = tabId ? { text: cfg.text,  tabId } : { text: cfg.text };
  const colorDetails = tabId ? { color: cfg.color, tabId } : { color: cfg.color };
  chrome.action.setBadgeText(details);
  chrome.action.setBadgeBackgroundColor(colorDetails);
}

function updateBadgeFromStats(tabId) {
  const s = tabId ? getTabStats(tabId) : { safe: 0, warning: 0, danger: 0 };
  if (s.danger > 0)       setBadge("danger",  tabId);
  else if (s.warning > 0) setBadge("warning", tabId);
  else if (s.safe > 0)    setBadge("safe",    tabId);
  else                    setBadge("idle",    tabId);
}

// ─── Bundled threat-list loader ───────────────────────────────────────────────
const BUNDLED_LISTS = [
  { file: "data/phishing-domains.txt", key: "tl_custom_domains", normalize: normalizeDomain },
  { file: "data/phishing-ips.txt",     key: "tl_custom_ips",     normalize: s => s },
  { file: "data/phishing-links.txt",   key: "tl_custom_links",   normalize: normalizeLink  },
];

function normalizeDomain(entry) {
  return entry.toLowerCase().replace(/^https?:\/\//i, "").replace(/^www\./i, "").split("/")[0];
}

function normalizeLink(entry) {
  return entry.toLowerCase().replace(/^https?:\/\//i, "").replace(/^www\./i, "").replace(/\/$/, "");
}

function parseListText(text, normalizeFn) {
  return text
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"))
    .map(normalizeFn)
    .filter(Boolean);
}

async function loadBundledThreatLists() {
  for (const { file, key, normalize } of BUNDLED_LISTS) {
    try {
      // Only skip loading if list exists AND is not empty
      const existing = await chrome.storage.local.get(key);
      if (existing[key]?.length > 0) continue;

      const url  = chrome.runtime.getURL(file);
      const resp = await fetch(url);
      if (!resp.ok) continue;

      const text    = await resp.text();
      const entries = parseListText(text, normalize);
      await chrome.storage.local.set({ [key]: entries });
    } catch (err) {
      console.warn(`[ThreatLens] Failed to load ${file}:`, err);
    }
  }
}


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_RESULT") {
    const tabId = sender.tab?.id;
    if (!tabId) { sendResponse({ ok: false }); return true; }

    tabStats[tabId] = {
      safe: msg.level === "safe" ? 1 : 0,
      warning: msg.level === "warning" ? 1 : 0,
      danger: msg.level === "danger" ? 1 : 0,
      totalScanned: (tabStats[tabId]?.totalScanned || 0) + 1,
      lastScan: new Date().toISOString()
    };
    updateBadgeFromStats(tabId);

    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "GET_STATS") {
    // Return stats for the currently active tab only
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      sendResponse({ stats: tabId ? getTabStats(tabId) : {} });
    });
    return true; // keep channel open for async sendResponse
  }

  if (msg.type === "RESET_STATS") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      if (tabId) {
        tabStats[tabId] = { safe: 0, warning: 0, danger: 0, lastScan: null, totalScanned: 0 };
        setBadge("idle", tabId);
      }
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.type === "RESCAN_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const tabId = tabs[0].id;
        // Reset stats before rescan to prevent accumulation
        tabStats[tabId] = { safe: 0, warning: 0, danger: 0, lastScan: null, totalScanned: 0 };
        setBadge("idle", tabId);
        chrome.tabs.sendMessage(tabId, { type: "RESCAN" });
      }
    });
    sendResponse({ ok: true });
    return true;
  }
});

// ─── Tab events ───────────────────────────────────────────────────────────────
chrome.tabs.onActivated.addListener(({ tabId }) => {
  // Restore this tab's badge when it becomes active
  updateBadgeFromStats(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    // Navigation started — only reset badge, let new scan overwrite stats
    setBadge("idle", tabId);
  }
});

// Clean up when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabStats[tabId];
});

// ─── On install / startup ─────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  // Set default settings
  chrome.storage.local.set({
    threatlensEnabled: true,
    threatlensSettings: {
      checkPhishingDB: true,
      checkSSL: true,
      checkLinkMismatch: true,
      checkDomains: true,
      checkUrgency: true,
    },
  });

  // Load bundled threat intelligence files into storage
  loadBundledThreatLists();
});

chrome.runtime.onStartup.addListener(() => {
  // Re-seed threat lists if storage was cleared between sessions
  loadBundledThreatLists();
});
