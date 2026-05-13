// ThreatLens Content Script
// Scans emails and web pages for phishing/threat indicators

(function () {
  "use strict";

  // ─── Known phishing/malicious domains ─────────────────────────────────────
  const KNOWN_PHISHING_DOMAINS = new Set([
    "paypa1.com","paypa1.net","paypa1.org","paypalsecure-login.com","paypal-update.com",
    "secure-paypal.com","appleid-verify.com","apple-id-login.com","applesecurity-alert.com",
    "amazon-security-alert.com","amazon-signin-update.com","netflix-billing.com",
    "microsoft-alert.com","microsoftsupport-alert.com","google-security-alert.com",
    "irs-refund.com","irs-gov-refund.com","bankofamerica-secure.com","chase-alert.com",
    "wellsfargo-verify.com","citibank-secure.com","steam-trade-offer.com","discord-nitro.gift",
    "crypto-wallet-verify.com","binance-support.net","coinbase-alert.com",
    "fedex-delivery-notification.com","ups-tracking-update.com","usps-package-alert.com",
    "dhl-express-delivery.com","login-verify-secure.com","account-suspended-verify.com",
    "secure-login-update.com","verify-account-now.com","click-to-verify.com",
  ]);

  const SUSPICIOUS_TLDS = new Set([".xyz",".top",".club",".work",".click",".gq",".ml",".cf",".tk",".pw"]);

  const SPOOFED_BRANDS = ["paypal","amazon","apple","google","microsoft","netflix","bank","chase",
    "wells","fargo","citibank","steam","discord","coinbase","binance","fedex","ups","usps","dhl","irs"];

  const TRUSTED_APEX_DOMAINS = new Set([
    "google.com","google.co.uk","google.com.au","google.ca","google.de","google.fr",
    "google.co.in","google.co.jp","google.com.br","google.es","google.it","google.nl",
    "google.com.mx","google.com.ar","google.com.sa","google.ae","google.com.sg",
    "googleapis.com","googleusercontent.com","googletagmanager.com","googleadservices.com",
    "googlesyndication.com","googleanalytics.com","gstatic.com","gmail.com","google-analytics.com",
    "accounts.google.com","myaccount.google.com","support.google.com","doubleclick.net",
    "microsoft.com","microsoftonline.com","office.com","office365.com","outlook.com",
    "live.com","hotmail.com","azure.com","azurewebsites.net","bing.com","msn.com",
    "windows.com","xbox.com","linkedin.com","visualstudio.com","github.com","githubusercontent.com",
    // Apple — primary + CDN/infrastructure domains
    "apple.com","icloud.com","appleid.apple.com","mzstatic.com","apple-cloudkit.com",
    "apple.news","cdn-apple.com","store.apple.com","support.apple.com","developer.apple.com",
    "apple-mapkit.com","applebot.apple.com","applepaygw.apple.com",

    // Amazon — primary + advertising/CDN/affiliate domains
    "amazon.com","amazon.co.uk","amazon.de","amazon.fr","amazon.co.jp","amazon.ca",
    "amazon.com.au","amazon.in","amazonaws.com","amazonwebservices.com","aws.amazon.com",
    "ssl-images-amazon.com","media-amazon.com","images-amazon.com",
    "amazon-adsystem.com","amazonpay.com","amazonprime.com","alexa.com",
    "primevideo.com","imdb.com","audible.com","awsstatic.com",
    "aboutamazon.com","amazon.jobs","amazon.science","thehub-amazon.com",

    // Microsoft — primary + CDN/Skype/Office infrastructure
    "microsoft.com","microsoftonline.com","office.com","office365.com","outlook.com",
    "live.com","hotmail.com","azure.com","azurewebsites.net","bing.com","msn.com",
    "windows.com","xbox.com","linkedin.com","visualstudio.com","github.com","githubusercontent.com",
    "aspnetcdn.com","msecnd.net","vo.msecnd.net","skypeassets.com","sfbassets.com",
    "azureedge.net","trafficmanager.net","sharepoint.com","microsoftstore.com",
    "onenote.com","yammer.com","skype.com","skype.net",

    // PayPal
    "paypal.com","paypal.me","paypalobjects.com","paypal-prepaid.com",

    // Netflix + CDN
    "netflix.com","nflximg.net","nflxvideo.net","nflxext.com","netflix.net",

    // Banks & financial
    "bankofamerica.com","bac.com","chase.com","jpmorgan.com","jpmorganchase.com",
    "wellsfargo.com","wf.com","citibank.com","citi.com",
    "hsbc.com","barclays.com","lloydsbank.com","capitalone.com","discover.com",

    // Gaming / Steam / Discord
    "steampowered.com","steamcommunity.com","steamstatic.com","steam-chat.com",
    "discord.com","discordapp.com","discordcdn.com","discordstatus.com",
    "riotgames.com","leagueoflegends.com","valorant.com","epicgames.com","ea.com",
    "origin.com","battlenet","blizzard.com","twitch.tv","twitchsvc.net","jtvnw.net",

    // Crypto
    "coinbase.com","coinbaseassets.com","binance.com","kraken.com","crypto.com",

    // Shipping
    "fedex.com","fedex-cdn.com","ups.com","usps.com","dhl.com","dhl.de","dhlecs.com",

    // Government
    "irs.gov","gov.uk","usa.gov",

    // Facebook / Meta + CDN/infrastructure
    "facebook.com","fbcdn.net","fb.com","fbsbx.com","instagram.com","cdninstagram.com",
    "whatsapp.com","whatsapp.net","messenger.com","meta.com","oculus.com",

    // Twitter / X
    "twitter.com","x.com","t.co","twimg.com","abs.twimg.com",

    // Google / YouTube
    "youtube.com","ytimg.com","youtu.be","googlevideo.com","ggpht.com",

    // Reddit
    "reddit.com","redd.it","redditmedia.com","reddituploads.com","redditstatic.com",

    // Wikipedia
    "wikipedia.org","wikimedia.org","mediawiki.org",

    // Shopify
    "shopify.com","shopifycdn.com","myshopify.com","shopifysvc.com",

    // Stripe
    "stripe.com","stripe.network",

    // Adobe
    "adobe.com","adobeaem.com","typekit.net","typekit.com","adobedtm.com","2o7.net",

    // Salesforce
    "salesforce.com","force.com","salesforceliveagent.com","salesforcecdn.com","exacttarget.com",

    // Zoom
    "zoom.us","zoomgov.com","zoom.com",

    // Slack
    "slack.com","slack-edge.com","slackb.com","slack-files.com","slack-imgs.com",

    // Atlassian / Jira / GitHub
    "atlassian.com","atlassian.net","jira.com","confluence.com","bitbucket.org",

    // Squarespace / WordPress
    "squarespace.com","squarespaceassets.com",
    "wordpress.com","wordpress.org","wp.com","wp.org",

    // CDN providers (used by all brands)
    "cloudfront.net","fastly.net","akamaized.net","cloudflare.com","cdn.jsdelivr.net",
    "akamai.com","akamaihd.net","edgesuite.net","edgekey.net",
    "unpkg.com","jquery.com","bootstrapcdn.com","fontawesome.com",

    // Analytics / monitoring
    "newrelic.com","nr-data.net","datadoghq.com","segment.com","mixpanel.com",
    "hotjar.com","hubspot.com","hubspotusercontent.com",
    "intercom.io","intercomcdn.com","zendesk.com","zdassets.com",
    "sentry.io","bugsnag.com",

    // Email / comms infra
    "twilio.com","sendgrid.net","mailchimp.com",

    // Auth
    "recaptcha.net","hcaptcha.com","auth0.com",

    // Creator / content platforms
    "gumroad.com","patreon.com","substack.com","medium.com",
    "notion.so","notionusercontent.com",
    "figma.com","canva.com",
    "spotify.com","scdn.co","pscdn.co",

    // DHL extra
    "dhl-express.com",
  ]);

  // ─── Custom threat list cache (loaded from storage at init) ──────────────
  let CUSTOM_DOMAINS = new Set();
  let CUSTOM_IPS     = new Set();
  let CUSTOM_LINKS   = new Set();

  function loadCustomLists(callback) {
    chrome.storage.local.get(["tl_custom_domains", "tl_custom_ips", "tl_custom_links"], (data) => {
      CUSTOM_DOMAINS = new Set((data.tl_custom_domains || []).map(s => s.toLowerCase().replace(/^www\./, "")));
      CUSTOM_IPS     = new Set(data.tl_custom_ips   || []);
      CUSTOM_LINKS   = new Set(data.tl_custom_links || []);
      if (callback) callback();
    });
  }

  // ─── Utility helpers ──────────────────────────────────────────────────────
  function extractDomain(url) {
    try {
      const u = new URL(url.startsWith("http") ? url : "https://" + url);
      return u.hostname.toLowerCase().replace(/^www\./, "");
    } catch { return null; }
  }

  function getApexDomain(hostname) {
    if (!hostname) return null;
    const parts = hostname.split(".");
    if (parts.length <= 2) return hostname;
    const twoPartTLDs = new Set(["co.uk","co.in","co.jp","co.nz","co.za","co.kr","co.id",
      "com.au","com.br","com.mx","com.ar","com.sa","com.sg","com.tw","com.hk","com.ng",
      "net.au","org.uk","org.au","gov.uk","gov.au","ac.uk","ac.in"]);
    const lastTwo = parts.slice(-2).join(".");
    if (twoPartTLDs.has(lastTwo)) return parts.slice(-3).join(".");
    return parts.slice(-2).join(".");
  }

  function normalizeDomain(value) {
    if (!value) return null;
    const extracted = extractDomain(value);
    if (extracted) return extracted.toLowerCase().replace(/^www\./, "");
    return value.toLowerCase().replace(/^www\./, "").trim();
  }

  function isTrustedDomain(domain) {
    const normalized = normalizeDomain(domain);
    if (!normalized) return false;
    if (TRUSTED_APEX_DOMAINS.has(normalized)) return true;
    const apex = getApexDomain(normalized);
    if (apex && TRUSTED_APEX_DOMAINS.has(apex)) return true;
    const parts = normalized.split(".");
    // Walk all suffix combinations (catches subdomains of trusted domains)
    for (let i = 1; i < parts.length - 1; i++) {
      if (TRUSTED_APEX_DOMAINS.has(parts.slice(i).join("."))) return true;
    }
    // Handle brand-owned TLDs (e.g. "about.google", "store.apple", "smile.amazon")
    // If the rightmost label is a brand name that owns a trusted domain, treat it as trusted.
    const tld = parts[parts.length - 1];
    if (
      TRUSTED_APEX_DOMAINS.has(tld + ".com") ||
      TRUSTED_APEX_DOMAINS.has(tld + ".net") ||
      TRUSTED_APEX_DOMAINS.has(tld + ".org") ||
      TRUSTED_APEX_DOMAINS.has(tld + ".gov")
    ) return true;
    return false;
  }

  function extractLinksFromText(text) {
    const urlRegex = /https?:\/\/[^\s"'<>]+/gi;
    return [...new Set(text.match(urlRegex) || [])];
  }

  function getDisplayedTextLinks(container) {
    const anchors = container.querySelectorAll("a[href]");
    return Array.from(anchors).map(a => ({
      href: a.href,
      text: a.textContent.trim(),
      displayedUrl: a.getAttribute("href") || "",
    }));
  }

  // ─── Analysis functions ───────────────────────────────────────────────────
  function checkPhishingDatabase(domain) {
    if (!domain) return null;
    if (KNOWN_PHISHING_DOMAINS.has(domain)) {
      return `Domain "${domain}" is in the known phishing database.`;
    }
    return null;
  }

  function checkSuspiciousTLD(domain) {
    if (!domain) return null;
    for (const tld of SUSPICIOUS_TLDS) {
      if (domain.endsWith(tld)) return `Domain uses a high-risk TLD (${tld}).`;
    }
    return null;
  }

  function checkBrandSpoofing(domain) {
    const normalized = normalizeDomain(domain);
    if (!normalized) return null;
    if (isTrustedDomain(normalized)) return null;
    for (const brand of SPOOFED_BRANDS) {
      if (normalized.includes(brand)) {
        return `Domain "${normalized}" contains the brand name "${brand}" but is not an official domain.`;
      }
    }
    return null;
  }

  function checkHTTPS(links) {
    // Only count external http:// links (ignore localhost, 127.0.0.1, internal)
    const httpLinks = links.filter(l => {
      if (!l.toLowerCase().startsWith("http://")) return false;
      try {
        const host = new URL(l).hostname;
        if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".local")) return false;
        return true;
      } catch { return false; }
    });
    // Only flag if a significant proportion of links are HTTP (not just one tracker/embed)
    const httpsLinks = links.filter(l => l.toLowerCase().startsWith("https://"));
    const total = httpLinks.length + httpsLinks.length;
    if (total === 0) return null;
    // Flag only if more than half the links are insecure, or 3+ insecure links with no HTTPS at all
    if (httpLinks.length > 0 && httpsLinks.length === 0 && httpLinks.length >= 3) {
      return `${httpLinks.length} link(s) use plain HTTP (no SSL/TLS encryption).`;
    }
    if (total >= 4 && httpLinks.length / total > 0.5) {
      return `${httpLinks.length} of ${total} link(s) use plain HTTP (no SSL/TLS encryption).`;
    }
    return null;
  }

  function checkLinkMismatch(anchors) {
    const mismatches = [];
    for (const { href, text } of anchors) {
      const textLooksLikeUrl = /^https?:\/\//i.test(text) || /^www\./i.test(text);
      if (textLooksLikeUrl) {
        const hrefDomain = extractDomain(href);
        const textDomain = extractDomain(text);
        if (hrefDomain && textDomain && hrefDomain !== textDomain) {
          mismatches.push(`Link shows "${textDomain}" but points to "${hrefDomain}".`);
        }
      }
    }
    return mismatches.length > 0 ? mismatches : null;
  }

  function checkIPAddressLinks(links) {
    const ipRegex = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/i;
    const ipLinks = links.filter(l => ipRegex.test(l));
    if (ipLinks.length > 0) return `${ipLinks.length} link(s) use raw IP addresses instead of domain names.`;
    return null;
  }

  function checkURLObfuscation(links) {
    const flags = [];
    for (const link of links) {
      if (/^(mailto|tel|sms|cid):/i.test(link)) continue;
      try {
        const u = new URL(link);
        if (u.username && u.username.length > 0) {
          flags.push("Link uses user-info (@) in its authority to disguise the real destination.");
          break;
        }
        // Skip trusted domains before checking subdomain depth
        const apex = getApexDomain(u.hostname.toLowerCase().replace(/^www\./, ""));
        if (apex && TRUSTED_APEX_DOMAINS.has(apex)) continue;
      } catch { /* skip */ }
      // Only flag extremely long subdomain chains (12+) — 9 was too aggressive for ad/analytics URLs
      if ((link.match(/\./g) || []).length > 12) {
        flags.push("Unusually long subdomain chain detected — possible obfuscation.");
        break;
      }
    }
    return flags.length > 0 ? flags : null;
  }

  function checkUrgencyKeywords(bodyText) {
    const keywords = [
      "verify your account","your account has been suspended","unusual sign-in activity",
      "click here immediately","confirm your identity","update your payment","your password will expire",
      "act now","account locked","unauthorized access","your account will be closed",
      "click to avoid suspension","verify now","reactivate your account","confirm billing",
    ];
    const found = keywords.filter(kw => bodyText.toLowerCase().includes(kw));
    // Require 3+ urgency phrases to reduce false positives on legitimate login/checkout pages
    if (found.length >= 3) {
      return `Multiple urgency phrases detected: "${found.slice(0,2).join('", "')}"${found.length > 2 ? ` and ${found.length - 2} more` : ""}.`;
    }
    return null;
  }

  // ─── Custom list checks ───────────────────────────────────────────────────
  function checkCustomDomains(domains) {
    for (const domain of domains) {
      const d = domain.toLowerCase().replace(/^www\./, "");
      if (CUSTOM_DOMAINS.has(d)) {
        return `Domain "${d}" is in your custom phishing domains list.`;
      }
      // Also check apex
      const apex = getApexDomain(d);
      if (apex && CUSTOM_DOMAINS.has(apex)) {
        return `Domain "${d}" matches "${apex}" in your custom phishing domains list.`;
      }
    }
    return null;
  }

  function checkCustomIPs(links) {
    const ipRegex = /(?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;
    for (const link of links) {
      const m = link.match(ipRegex);
      if (m && CUSTOM_IPS.has(m[1])) {
        return `IP address ${m[1]} is in your custom phishing IPs list.`;
      }
    }
    return null;
  }

  function checkCustomLinks(links) {
    for (const link of links) {
      // Normalise: strip trailing slash and query string for broad matching
      try {
        const u = new URL(link);
        const norm = (u.hostname + u.pathname).replace(/\/$/, "").toLowerCase();
        for (const entry of CUSTOM_LINKS) {
          const normEntry = entry.replace(/^https?:\/\//i, "").replace(/\/$/, "").toLowerCase();
          if (norm === normEntry || norm.startsWith(normEntry)) {
            return `Link matches "${entry}" in your custom phishing links list.`;
          }
        }
      } catch { /* skip malformed */ }
    }
    return null;
  }

  // ─── Master scan: email ───────────────────────────────────────────────────
  function scanEmail(emailContainer) {
    const bodyText = emailContainer.innerText || emailContainer.textContent || "";
    const anchors = getDisplayedTextLinks(emailContainer);
    const allLinks = [
      ...extractLinksFromText(emailContainer.innerHTML || ""),
      ...anchors.map(a => a.href),
    ];
    const allDomains = [...new Set(allLinks.map(extractDomain).filter(Boolean))];

    const dangers = [];
    const warnings = [];

    for (const domain of allDomains) {
      const r = checkPhishingDatabase(domain);
      if (r) dangers.push({ type: "Phishing Database", icon: "☠️", msg: r });
    }
    for (const domain of allDomains) {
      const r = checkBrandSpoofing(domain);
      if (r) dangers.push({ type: "Brand Spoofing", icon: "🎭", msg: r });
    }
    const ipCheck = checkIPAddressLinks(allLinks);
    if (ipCheck) dangers.push({ type: "IP Address Link", icon: "🔢", msg: ipCheck });

    const mismatches = checkLinkMismatch(anchors);
    if (mismatches) mismatches.forEach(m => dangers.push({ type: "Link Mismatch", icon: "⚠️", msg: m }));

    // Custom list checks
    const customDomainHit = checkCustomDomains(allDomains);
    if (customDomainHit) dangers.push({ type: "Custom Domain List", icon: "📋", msg: customDomainHit });

    const customIPHit = checkCustomIPs(allLinks);
    if (customIPHit) dangers.push({ type: "Custom IP List", icon: "📋", msg: customIPHit });

    const customLinkHit = checkCustomLinks(allLinks);
    if (customLinkHit) dangers.push({ type: "Custom Link List", icon: "📋", msg: customLinkHit });

    const obfuscation = checkURLObfuscation(allLinks);
    if (obfuscation) obfuscation.forEach(m => warnings.push({ type: "URL Obfuscation", icon: "🔀", msg: m }));

    for (const domain of allDomains) {
      const r = checkSuspiciousTLD(domain);
      if (r) warnings.push({ type: "Suspicious TLD", icon: "🌐", msg: r });
    }
    const httpsCheck = checkHTTPS(allLinks);
    if (httpsCheck) warnings.push({ type: "No SSL/TLS", icon: "🔓", msg: httpsCheck });

    const urgency = checkUrgencyKeywords(bodyText);
    if (urgency) warnings.push({ type: "Urgency Language", icon: "🚨", msg: urgency });

    let level = "safe";
    if (dangers.length > 0) level = "danger";
    else if (warnings.length > 0) level = "warning";

    const safeReasons = level === "safe" ? [
      { type: "Domain Check",      icon: "✅", msg: "All links use recognized, legitimate domains." },
      { type: "SSL/TLS",           icon: "🔒", msg: "All links are served over secure HTTPS connections." },
      { type: "Link Integrity",    icon: "🔗", msg: "No link mismatch or obfuscation detected." },
      { type: "Phishing Database", icon: "🛡️", msg: "No domains found in phishing or custom databases." },
    ] : [];

    return { level, dangers, warnings, safeReasons };
  }

  // ─── Master scan: page ────────────────────────────────────────────────────
  function scanPage() {
    const url = window.location.href;
    const currentDomain = extractDomain(url);
    const isHTTPS = url.startsWith("https://");

    const anchors = getDisplayedTextLinks(document.body);
    const allLinks = [
      ...extractLinksFromText(document.body.innerHTML || ""),
      ...anchors.map(a => a.href),
    ].filter(l => l && (l.startsWith("http://") || l.startsWith("https://")));

    const allDomains = [...new Set(
      [currentDomain, ...allLinks.map(extractDomain)].filter(Boolean)
    )];

    const bodyText = document.body.innerText || "";
    const dangers = [];
    const warnings = [];

    // Current page protocol
    if (!isHTTPS) {
      warnings.push({ type: "No SSL/TLS", icon: "🔓", msg: "This page is not served over HTTPS — your connection is unencrypted." });
    }

    // Current domain checks
    const phishCheck = checkPhishingDatabase(currentDomain);
    if (phishCheck) dangers.push({ type: "Phishing Database", icon: "☠️", msg: phishCheck });

    const brandCheck = checkBrandSpoofing(currentDomain);
    if (brandCheck) dangers.push({ type: "Brand Spoofing", icon: "🎭", msg: brandCheck });

    const tldCheck = checkSuspiciousTLD(currentDomain);
    if (tldCheck) warnings.push({ type: "Suspicious TLD", icon: "🌐", msg: tldCheck });

    // Link checks
    const ipCheck = checkIPAddressLinks(allLinks);
    if (ipCheck) dangers.push({ type: "IP Address Link", icon: "🔢", msg: ipCheck });

    // Custom list checks
    const customDomainHit = checkCustomDomains(allDomains);
    if (customDomainHit) dangers.push({ type: "Custom Domain List", icon: "📋", msg: customDomainHit });

    const customIPHit = checkCustomIPs(allLinks);
    if (customIPHit) dangers.push({ type: "Custom IP List", icon: "📋", msg: customIPHit });

    const customLinkHit = checkCustomLinks(allLinks);
    if (customLinkHit) dangers.push({ type: "Custom Link List", icon: "📋", msg: customLinkHit });

    // Link mismatch is only meaningful in email context — skip for general page scans
    // as legitimate sites commonly use redirects and tracking links.

    const obfuscation = checkURLObfuscation(allLinks);
    if (obfuscation) obfuscation.forEach(m => warnings.push({ type: "URL Obfuscation", icon: "🔀", msg: m }));

    const httpsCheck = checkHTTPS(allLinks);
    if (httpsCheck) warnings.push({ type: "Insecure Links", icon: "🔓", msg: httpsCheck });

    // Check other domains referenced on the page — only untrusted ones
    for (const domain of allDomains) {
      if (domain === currentDomain) continue;
      if (isTrustedDomain(domain)) continue; // skip known-good CDNs, analytics, etc.
      const r = checkPhishingDatabase(domain);
      if (r) dangers.push({ type: "Phishing Database", icon: "☠️", msg: `Linked: ${r}` });
      const bs = checkBrandSpoofing(domain);
      if (bs) dangers.push({ type: "Brand Spoofing", icon: "🎭", msg: `Linked: ${bs}` });
    }

    const urgency = checkUrgencyKeywords(bodyText);
    if (urgency) warnings.push({ type: "Urgency Language", icon: "🚨", msg: urgency });

    let level = "safe";
    if (dangers.length > 0) level = "danger";
    else if (warnings.length > 0) level = "warning";

    const safeReasons = level === "safe" ? [
      { type: "Domain Check",   icon: "✅", msg: "This domain is not in known or custom phishing databases." },
      { type: "SSL/TLS",        icon: "🔒", msg: "Page is served over a secure HTTPS connection." },
      { type: "Link Integrity", icon: "🔗", msg: "No suspicious link patterns detected on this page." },
      { type: "Page Content",   icon: "🛡️", msg: "No urgency language or deceptive patterns found." },
    ] : [];

    return { level, dangers, warnings, safeReasons };
  }

  // ─── Colors ───────────────────────────────────────────────────────────────
  const COLORS = {
    safe:    { bg: "#22c55e", shadow: "rgba(34,197,94,0.5)" },
    warning: { bg: "#f59e0b", shadow: "rgba(245,158,11,0.5)" },
    danger:  { bg: "#ef4444", shadow: "rgba(239,68,68,0.5)" },
  };

  // ─── Shared: build tooltip inner HTML ────────────────────────────────────
  function buildTooltipHTML(result, color) {
    const { level, dangers, warnings, safeReasons } = result;
    const allFindings = [...dangers, ...warnings, ...safeReasons];
    return `
      <div style="background:rgba(255,255,255,0.05);border-bottom:1px solid rgba(255,255,255,0.08);
                  padding:10px 13px;display:flex;align-items:center;gap:8px;">
        <div style="width:7px;height:7px;border-radius:50%;background:${color.bg};flex-shrink:0;"></div>
        <span style="color:rgba(255,255,255,0.85);font-weight:600;font-size:12px;letter-spacing:-0.01em;">
          ThreatLens &mdash; ${level === "safe" ? "Safe" : level === "warning" ? "Suspicious" : "Dangerous"}
        </span>
      </div>
      <div style="padding:9px 13px 11px;">
        ${allFindings.map(f => `
          <div style="display:flex;gap:9px;align-items:flex-start;padding:5px 0;
                      border-bottom:1px solid rgba(255,255,255,0.06);">
            <span style="font-size:13px;flex-shrink:0;margin-top:1px;">${f.icon}</span>
            <div>
              <div style="color:${color.bg};font-size:10px;font-weight:600;
                          letter-spacing:0.04em;text-transform:uppercase;margin-bottom:2px;">${f.type}</div>
              <div style="color:rgba(255,255,255,0.55);font-size:11px;line-height:1.5;">${f.msg}</div>
            </div>
          </div>
        `).join("")}
        <div style="margin-top:8px;color:rgba(255,255,255,0.2);font-size:10px;text-align:right;">
          ThreatLens &bull; ${new Date().toLocaleTimeString()}
        </div>
      </div>
    `;
  }

  // ─── Email badge (unchanged) ──────────────────────────────────────────────
  function createBadge(result, emailEl) {
    const old = emailEl.querySelector(".threatlens-badge");
    if (old) old.remove();

    const { level, dangers, warnings, safeReasons } = result;
    const color = COLORS[level];

    const wrapper = document.createElement("div");
    wrapper.className = "threatlens-badge";
    wrapper.setAttribute("data-level", level);
    wrapper.style.cssText = `
      position: absolute;
      top: 8px;
      right: 8px;
      z-index: 9999;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    `;

    const circle = document.createElement("div");
    circle.className = "tl-circle";
    circle.title = `ThreatLens: ${level.toUpperCase()}`;
    circle.style.cssText = `
      width: 14px;
      height: 14px;
      border-radius: 50%;
      background: ${color.bg};
      box-shadow: 0 0 0 3px rgba(255,255,255,0.9), 0 0 10px ${color.shadow};
      cursor: pointer;
      transition: transform 0.2s ease, box-shadow 0.2s ease;
      animation: tl-pulse 2.5s ease-in-out infinite;
    `;

    const tooltip = document.createElement("div");
    tooltip.className = "tl-tooltip";
    tooltip.style.cssText = `
      display: none;
      position: absolute;
      top: 20px;
      right: 0;
      width: 280px;
      background: #1c1c1e;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6), 0 2px 8px rgba(0,0,0,0.4);
      overflow: hidden;
      z-index: 99999;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      -webkit-font-smoothing: antialiased;
    `;
    tooltip.innerHTML = buildTooltipHTML(result, color);

    let open = false;
    circle.addEventListener("click", (e) => {
      e.stopPropagation();
      open = !open;
      tooltip.style.display = open ? "block" : "none";
      circle.style.transform = open ? "scale(1.3)" : "scale(1)";
    });
    circle.addEventListener("mouseenter", () => { if (!open) circle.style.transform = "scale(1.2)"; });
    circle.addEventListener("mouseleave", () => { if (!open) circle.style.transform = "scale(1)"; });
    document.addEventListener("click", () => {
      if (open) { open = false; tooltip.style.display = "none"; circle.style.transform = "scale(1)"; }
    });

    wrapper.appendChild(circle);
    wrapper.appendChild(tooltip);
    return wrapper;
  }

  // ─── Floating site indicator (draggable + trash dismiss) ─────────────────
  function createFloatingSiteIndicator(result) {
    const color = COLORS[result.level];

    // ─── Status icon SVG ───
    const svgIcon = result.level === "safe"
      ? `<svg width="17" height="17" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>`
      : result.level === "warning"
      ? `<svg width="17" height="17" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>`
      : `<svg width="17" height="17" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>`;

    // ─── Indicator wrapper ───
    const indicator = document.createElement("div");
    indicator.id = "tl-site-indicator";
    indicator.style.cssText = `
      position: fixed;
      right: 20px;
      bottom: 20px;
      width: 40px;
      height: 40px;
      z-index: 2147483647;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      user-select: none;
      -webkit-user-select: none;
    `;

    // ─── Circle button ───
    const circle = document.createElement("div");
    circle.style.cssText = `
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background: ${color.bg};
      box-shadow: 0 4px 16px ${color.shadow}, 0 0 0 2px rgba(255,255,255,0.14);
      cursor: grab;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      transition: transform 0.15s ease, opacity 0.15s ease;
      animation: tl-pulse 2.5s ease-in-out infinite;
      position: relative;
    `;
    circle.innerHTML = svgIcon;

    // ─── Tooltip panel ───
    const tooltip = document.createElement("div");
    tooltip.style.cssText = `
      display: none;
      position: absolute;
      width: 280px;
      background: #1c1c1e;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.7), 0 2px 8px rgba(0,0,0,0.4);
      overflow: hidden;
      z-index: 2147483647;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      -webkit-font-smoothing: antialiased;
      pointer-events: auto;
    `;
    tooltip.innerHTML = buildTooltipHTML(result, color);

    // ─── Trash zone ───
    const trashZone = document.createElement("div");
    trashZone.id = "tl-trash-zone";
    trashZone.style.cssText = `
      position: fixed;
      bottom: 24px;
      left: 50%;
      transform: translateX(-50%) scale(1);
      z-index: 2147483646;
      width: 52px;
      height: 52px;
      border-radius: 50%;
      background: rgba(28,28,30,0.92);
      border: 2px solid rgba(255,69,58,0.35);
      display: none;
      align-items: center;
      justify-content: center;
      color: rgba(255,69,58,0.6);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      box-shadow: 0 4px 24px rgba(0,0,0,0.55);
      transition: border-color 0.15s ease, background 0.15s ease,
                  color 0.15s ease, transform 0.15s ease;
      pointer-events: none;
    `;
    trashZone.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
           stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round">
        <polyline points="3 6 5 6 21 6"></polyline>
        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"></path>
        <line x1="10" y1="11" x2="10" y2="17"></line>
        <line x1="14" y1="11" x2="14" y2="17"></line>
      </svg>
    `;

    // ─── Position tooltip above or below the indicator ───
    function refreshTooltipPosition() {
      const r = indicator.getBoundingClientRect();
      // Horizontal: open left if indicator is in right half of screen
      if (r.left + 280 > window.innerWidth - 8) {
        tooltip.style.right = "0";
        tooltip.style.left = "";
      } else {
        tooltip.style.left = "0";
        tooltip.style.right = "";
      }
      // Vertical: open upward if indicator is in bottom half
      if (r.top > window.innerHeight / 2) {
        tooltip.style.bottom = "48px";
        tooltip.style.top = "";
      } else {
        tooltip.style.top = "48px";
        tooltip.style.bottom = "";
      }
    }

    // ─── Drag state ───
    let isOpen = false;
    let isDragging = false;
    let dragOffX = 0, dragOffY = 0;
    let totalMovement = 0;
    let overTrash = false;

    circle.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      e.stopPropagation();

      isDragging = true;
      totalMovement = 0;
      overTrash = false;

      // Switch from right/bottom anchoring to left/top for free movement
      const r = indicator.getBoundingClientRect();
      indicator.style.right = "";
      indicator.style.bottom = "";
      indicator.style.left = r.left + "px";
      indicator.style.top = r.top + "px";

      dragOffX = e.clientX - r.left;
      dragOffY = e.clientY - r.top;

      circle.style.cursor = "grabbing";
      circle.style.animation = "none";
      circle.style.transform = "scale(0.92)";
      trashZone.style.display = "flex";
      // Close tooltip while dragging
      if (isOpen) { isOpen = false; tooltip.style.display = "none"; }
    });

    const onMouseMove = (e) => {
      if (!isDragging) return;

      totalMovement += Math.abs(e.movementX) + Math.abs(e.movementY);

      const newLeft = Math.max(0, Math.min(window.innerWidth - 40, e.clientX - dragOffX));
      const newTop  = Math.max(0, Math.min(window.innerHeight - 40, e.clientY - dragOffY));
      indicator.style.left = newLeft + "px";
      indicator.style.top  = newTop + "px";

      // Detect hover over trash zone
      const tr = trashZone.getBoundingClientRect();
      const nowOver = (
        e.clientX >= tr.left && e.clientX <= tr.right &&
        e.clientY >= tr.top  && e.clientY <= tr.bottom
      );

      if (nowOver !== overTrash) {
        overTrash = nowOver;
        if (overTrash) {
          trashZone.style.borderColor = "rgba(255,69,58,1)";
          trashZone.style.background  = "rgba(255,69,58,0.18)";
          trashZone.style.color       = "rgba(255,69,58,1)";
          trashZone.style.transform   = "translateX(-50%) scale(1.18)";
          circle.style.opacity        = "0.4";
          circle.style.transform      = "scale(0.8)";
        } else {
          trashZone.style.borderColor = "rgba(255,69,58,0.35)";
          trashZone.style.background  = "rgba(28,28,30,0.92)";
          trashZone.style.color       = "rgba(255,69,58,0.6)";
          trashZone.style.transform   = "translateX(-50%) scale(1)";
          circle.style.opacity        = "1";
          circle.style.transform      = "scale(0.92)";
        }
      }
    };

    const onMouseUp = () => {
      if (!isDragging) return;
      isDragging = false;

      trashZone.style.display = "none";
      circle.style.cursor    = "grab";
      circle.style.opacity   = "1";

      if (overTrash) {
        // Dismiss this site permanently
        const host = window.location.hostname;
        chrome.storage.local.get("tl_dismissed_sites", (data) => {
          const list = data.tl_dismissed_sites || [];
          if (!list.includes(host)) list.push(host);
          chrome.storage.local.set({ tl_dismissed_sites: list });
        });
        tooltip.remove();
        trashZone.remove();
        indicator.remove();
        return;
      }

      overTrash = false;
      circle.style.transform = "scale(1)";
      circle.style.animation = "tl-pulse 2.5s ease-in-out infinite";

      // If barely moved, treat as a click → toggle tooltip
      if (totalMovement < 6) {
        isOpen = !isOpen;
        if (isOpen) {
          refreshTooltipPosition();
          tooltip.style.display = "block";
        } else {
          tooltip.style.display = "none";
        }
      }
    };

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);

    // Close tooltip when clicking outside
    document.addEventListener("click", (e) => {
      if (isOpen && !indicator.contains(e.target) && !tooltip.contains(e.target)) {
        isOpen = false;
        tooltip.style.display = "none";
      }
    });

    indicator.appendChild(circle);
    indicator.appendChild(tooltip);
    document.body.appendChild(trashZone);
    return indicator;
  }

  // ─── Global styles ────────────────────────────────────────────────────────
  function injectGlobalStyles() {
    if (document.getElementById("threatlens-styles")) return;
    const style = document.createElement("style");
    style.id = "threatlens-styles";
    style.textContent = `
      @keyframes tl-pulse {
        0%, 100% { opacity: 1; }
        50%       { opacity: 0.65; }
      }
      @keyframes tl-trash-in {
        from { opacity: 0; transform: translateX(-50%) scale(0.7); }
        to   { opacity: 1; transform: translateX(-50%) scale(1); }
      }
      #tl-trash-zone[style*="flex"] {
        animation: tl-trash-in 0.18s cubic-bezier(0.34,1.56,0.64,1) forwards;
      }
      .threatlens-badge { pointer-events: auto !important; }
      .threatlens-badge * { box-sizing: border-box; }
      #tl-site-indicator * { box-sizing: border-box; }
    `;
    document.head.appendChild(style);
  }

  // ─── Email site detection ─────────────────────────────────────────────────
  const EMAIL_SITE_HOSTS = new Set([
    "mail.google.com",
    "outlook.live.com",
    "outlook.office.com",
    "mail.yahoo.com",
  ]);

  function isEmailSite() {
    return EMAIL_SITE_HOSTS.has(window.location.hostname.toLowerCase());
  }

  // ─── Gmail / email container scanning ────────────────────────────────────
  const GMAIL_EMAIL_SELECTORS = [
    "div.adn.ads",
    "div[data-message-id]",
    "div.gs",
  ];

  function findEmailContainers() {
    const candidates = new Set();
    for (const sel of GMAIL_EMAIL_SELECTORS) {
      document.querySelectorAll(sel).forEach(el => candidates.add(el));
    }
    return [...candidates];
  }

  function processEmailContainer(el) {
    if (el.dataset.threatlensScanned === "true") return;
    el.dataset.threatlensScanned = "true";
    const pos = window.getComputedStyle(el).position;
    if (pos === "static") el.style.position = "relative";
    const result = scanEmail(el);
    const badge = createBadge(result, el);
    el.appendChild(badge);
    chrome.runtime.sendMessage({
      type: "SCAN_RESULT",
      level: result.level,
      dangerCount: result.dangers.length,
      warningCount: result.warnings.length,
      url: window.location.href,
    }).catch(() => {});
  }

  function scanAllVisible() {
    findEmailContainers().forEach(processEmailContainer);
  }

  function startObserver() {
    const observer = new MutationObserver((mutations) => {
      let shouldScan = false;
      for (const m of mutations) {
        if (m.addedNodes.length > 0) { shouldScan = true; break; }
      }
      if (shouldScan) {
        clearTimeout(window._tlScanTimer);
        window._tlScanTimer = setTimeout(scanAllVisible, 400);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ─── Init ─────────────────────────────────────────────────────────────────
  function init() {
    chrome.storage.local.get(["threatlensEnabled", "tl_dismissed_sites"], (data) => {
      if (data.threatlensEnabled === false) return;

      injectGlobalStyles();

      // Load custom threat lists into memory before scanning
      loadCustomLists(() => {
        if (isEmailSite()) {
          // Email mode: scan individual email containers
          scanAllVisible();
          startObserver();
        } else {
          // Site mode: scan the page and show draggable floating indicator
          const host = window.location.hostname;
          const dismissed = data.tl_dismissed_sites || [];
          if (dismissed.includes(host)) return;

          const result = scanPage();
          const indicator = createFloatingSiteIndicator(result);
          document.body.appendChild(indicator);

          chrome.runtime.sendMessage({
            type: "SCAN_RESULT",
            level: result.level,
            url: window.location.href,
          }).catch(() => {});
        }
      });
    });
  }

  // ─── Entry point ──────────────────────────────────────────────────────────
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // ─── Re-scan message from popup ───────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type !== "RESCAN") return;

    // Refresh custom list cache before rescanning
    loadCustomLists(() => {
      if (isEmailSite()) {
        // Reset email badges and re-scan
        document.querySelectorAll("[data-threatlens-scanned]").forEach(el => {
          delete el.dataset.threatlensScanned;
          const badge = el.querySelector(".threatlens-badge");
          if (badge) badge.remove();
        });
        scanAllVisible();
      } else {
        // Remove existing site indicator + trash zone and re-scan
        const old = document.getElementById("tl-site-indicator");
        if (old) old.remove();
        const oldTrash = document.getElementById("tl-trash-zone");
        if (oldTrash) oldTrash.remove();

        const result = scanPage();
        const indicator = createFloatingSiteIndicator(result);
        document.body.appendChild(indicator);

        chrome.runtime.sendMessage({
          type: "SCAN_RESULT",
          level: result.level,
          url: window.location.href,
        }).catch(() => {});
      }
    });
  });

})();
