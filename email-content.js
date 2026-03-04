const SCAM_GUARD_ATTRIBUTE = "data-scam-guard-checked";

let spamModel = null;
const SPAM_THRESHOLD = 0.5;

function tokenize(text) {
  const cleaned = text.toLowerCase().replace(/[^a-z0-9\s]/g, " ");
  return cleaned.split(/\s+/).filter(w => w.length > 1);
}

async function loadSpamModel() {
  if (spamModel) return spamModel;
  try {
    const url = typeof chrome !== "undefined" && chrome.runtime
      ? chrome.runtime.getURL("spam_model.json")
      : browser?.runtime?.getURL?.("spam_model.json");
    if (!url) return null;
    const res = await fetch(url);
    spamModel = await res.json();
    return spamModel;
  } catch (e) {
    console.warn("Scam Guard: Could not load ML model", e);
    return null;
  }
}

function predictSpam(text) {
  if (!spamModel) return { spam: false, prob: 0 };
  const words = tokenize(text);
  if (words.length === 0) return { spam: false, prob: 0 };

  let logSpam = spamModel.logPriorSpam;
  let logHam = spamModel.logPriorHam;
  const def = spamModel.defaultLogProb ?? -15;

  for (const w of words) {
    logSpam += (spamModel.logProbSpam[w] ?? def);
    logHam += (spamModel.logProbHam[w] ?? def);
  }

  const maxLog = Math.max(logSpam, logHam);
  const probSpam = Math.exp(logSpam - maxLog) / (Math.exp(logSpam - maxLog) + Math.exp(logHam - maxLog));
  return { spam: probSpam >= SPAM_THRESHOLD, prob: probSpam };
}

const DETECTION_RULES = [
  { id: "otp_request", phrases: ["otp", "one time password", "verification code", "verification otp"], score: 4 },
  { id: "bank_details", phrases: ["bank account", "account number", "ifsc", "iban"], score: 4 },
  { id: "card_details", phrases: ["cvv", "pin code", "card number", "debit card", "credit card"], score: 5 },
  { id: "prize_lottery", phrases: ["you have won", "u have won", "congratulations you won", "congrats u won", "lottery winner", "won the lottery", "won a lottery", "won lottery", "prize money", "lottery", "you won", "u won"], score: 4 },
  { id: "bank_contact", phrases: ["contact the bank", "contact bank", "contact to the bank", "visit the bank", "call the bank"], score: 4 },
  { id: "urgent_action", phrases: ["urgent action", "limited time", "act now", "immediately", "within 5 minutes", "asap", "right now"], score: 2 },
  { id: "money_request", phrases: ["send money", "wire money", "transfer money", "pay the fee", "pay fee"], score: 4 },
  { id: "giftcard_crypto", phrases: ["gift card", "google play card", "itunes card", "bitcoin", "crypto"], score: 4 },
  { id: "investment", phrases: ["investment opportunity", "double your money", "guaranteed returns"], score: 3 },
  { id: "inheritance", phrases: ["inheritance", "foreign fund", "unclaimed funds"], score: 3 },
  { id: "keep_secret", phrases: ["do not tell anyone", "keep this confidential"], score: 3 },
  { id: "account_verify", phrases: ["verify your account", "confirm your identity", "kyc update"], score: 3 }
];

const ADVANCED_PATTERNS = [
  { pattern: /\b(u|you)\s+have\s+won\b/i, reason: "won/lottery (u/you variant)", score: 4 },
  { pattern: /\bwon\s+(a\s+)?lottery\b/i, reason: "won lottery", score: 5 },
  { pattern: /\blottery\b.*\bbank\b/i, reason: "lottery + bank", score: 5 },
  { pattern: /\bbank\b.*\blottery\b/i, reason: "bank + lottery", score: 5 },
  { pattern: /\bcontact\b.*\bbank\b/i, reason: "contact bank", score: 4 },
  { pattern: /\bbank\b.*\bcontact\b/i, reason: "bank contact", score: 4 },
  { pattern: /\bclaim\s+(your\s+)?(prize|money|reward)\b/i, reason: "claim prize", score: 4 },
  { pattern: /\b(congrats|congratulations)\b.*\b(won|winner)\b/i, reason: "congrats won", score: 4 },
];

function isSuspiciousText(text) {
  const lowered = text.toLowerCase();
  const matchedReasons = [];
  let totalScore = 0;

  for (const rule of DETECTION_RULES) {
    for (const phrase of rule.phrases) {
      if (lowered.includes(phrase)) {
        matchedReasons.push(phrase);
        totalScore += rule.score;
        break;
      }
    }
  }

  for (const { pattern, reason, score } of ADVANCED_PATTERNS) {
    if (pattern.test(text)) {
      matchedReasons.push(reason);
      totalScore += score;
    }
  }

  const moneyRegex = /(\b(?:rs\.?|inr|₹|usd|\$|eur|£|rupees|dollars?)\s?\d{3,}|\d{3,}\s?(?:rs\.?|inr|₹|\$|eur|£))/i;
  if (moneyRegex.test(text)) {
    matchedReasons.push("large money amount mentioned");
    totalScore += 3;
  }

  const urlRegex = /(https?:\/\/[^\s]+)/gi;
  const urls = text.match(urlRegex) || [];

  const suspiciousShorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"];

  for (const url of urls) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      for (const shortener of suspiciousShorteners) {
        if (host === shortener || host.endsWith("." + shortener)) {
          matchedReasons.push("link via url shortener (" + shortener + ")");
          totalScore += 3;
        }
      }
    } catch (e) {
    }
  }

  const ruleSuspicious = totalScore >= 3;
  const mlResult = predictSpam(text);
  const mlSuspicious = mlResult.spam;
  const suspicious = ruleSuspicious || mlSuspicious;

  const reasons = Array.from(new Set(matchedReasons));
  if (mlSuspicious && mlResult.prob >= 0.7) {
    reasons.push("ML model predicted spam (" + (mlResult.prob * 100).toFixed(0) + "% confidence)");
  }

  let score = totalScore;
  if (mlSuspicious) score = Math.max(score, mlResult.prob >= 0.8 ? 8 : 5);

  return {
    suspicious,
    reasons,
    urls,
    score
  };
}

function buildAdviceText(reasons) {
  const baseAdvice = [
    "Do not share OTPs, passwords, PINs, or card details.",
    "Do not click on suspicious links or download unknown attachments.",
    "Do not send money, gift cards, or crypto to unknown people.",
    "Verify requests through official channels (bank app, company website, phone number from their official site).",
    "If unsure, ignore the message and do not reply."
  ];

  const extra = [];

  for (const reason of reasons) {
    if (reason.includes("otp") || reason.includes("password") || reason.includes("pin")) {
      extra.push("Legitimate companies and banks will never ask for OTPs or full passwords over email.");
    } else if (reason.includes("won") || reason.includes("lottery") || reason.includes("prize")) {
      extra.push("Random emails telling you that you won money or prizes are almost always scams.");
    } else if (reason.includes("send money") || reason.includes("gift card") || reason.includes("bitcoin") || reason.includes("crypto")) {
      extra.push("Never send money or gift cards to someone you only know through email.");
    } else if (reason.includes("url shortener")) {
      extra.push("Shortened links can hide the real website; open them only if you fully trust the sender.");
    }
  }

  const allAdvice = baseAdvice.concat(extra);
  const uniqueAdvice = Array.from(new Set(allAdvice));
  return uniqueAdvice;
}

function createWarningElement(analysis) {
  const container = document.createElement("div");
  container.style.border = "1px solid #e53935";
  container.style.borderRadius = "6px";
  container.style.padding = "6px 8px";
  container.style.marginTop = "8px";
  container.style.backgroundColor = "rgba(229,57,53,0.08)";
  container.style.fontSize = "12px";
  container.style.color = "#b71c1c";
  container.style.maxWidth = "100%";
  container.style.fontFamily = "system-ui, -apple-system, sans-serif";

  const title = document.createElement("div");
  const riskLabel = analysis.score >= 7 ? "high risk" : "medium risk";
  title.textContent = "Scam Guard: " + riskLabel + " email";
  title.style.fontWeight = "600";
  title.style.marginBottom = "4px";
  container.appendChild(title);

  if (analysis.reasons.length > 0) {
    const reasonsEl = document.createElement("div");
    reasonsEl.textContent = "Suspicious because: " + analysis.reasons.join(", ");
    reasonsEl.style.marginBottom = "4px";
    container.appendChild(reasonsEl);
  }

  const adviceList = document.createElement("ul");
  adviceList.style.paddingLeft = "18px";
  adviceList.style.margin = "0";

  const adviceItems = buildAdviceText(analysis.reasons);
  for (const advice of adviceItems) {
    const li = document.createElement("li");
    li.textContent = advice;
    adviceList.appendChild(li);
  }

  container.appendChild(adviceList);

  return container;
}

function isGmail() {
  return window.location.hostname === "mail.google.com";
}

function isOutlook() {
  const h = window.location.hostname;
  return h === "outlook.live.com" || h === "outlook.office.com";
}

function findEmailContentElements(root) {
  const elements = [];
  const seen = new Set();

  if (isGmail()) {
    const gmailSelectors = [
      'div.ii',
      'div[class*="ii"]',
      'div.a3s',
      'div[class*="a3s"]',
      'div[role="main"] div[dir="ltr"]',
      'div[role="main"] div[class*="ii"]',
      'div[role="main"] div[class*="a3s"]',
      'div[data-message-id]',
      'div[role="main"] [role="listitem"] div',
      'div[data-message-id] div[dir="ltr"]',
      'div[role="main"] div'
    ];
    for (const sel of gmailSelectors) {
      try {
        const found = root.querySelectorAll(sel);
        for (const el of found) {
          if (seen.has(el)) continue;
          const text = (el.innerText || el.textContent || "").trim();
          if (text.length > 15 && !el.closest("[data-scam-guard-checked]")) {
            const isLikelyBody = !el.querySelector(sel) || el.children.length <= 5;
            if (isLikelyBody || text.length > 50) {
              elements.push(el);
              seen.add(el);
            }
          }
        }
      } catch (e) {}
    }
    if (elements.length === 0) {
      const main = root.querySelector('div[role="main"]');
      if (main) {
        const divs = main.querySelectorAll('div');
        for (const el of divs) {
          if (seen.has(el)) continue;
          const text = (el.innerText || el.textContent || "").trim();
          if (text.length >= 10 && text.length <= 100000 && !el.closest("[data-scam-guard-checked]")) {
            const childTextLen = Array.from(el.children).reduce((max, c) =>
              Math.max(max, (c.innerText || c.textContent || "").trim().length), 0);
            if (childTextLen < text.length * 0.95) {
              elements.push(el);
              seen.add(el);
            }
          }
        }
      }
    }
  } else if (isOutlook()) {
    const outlookSelectors = [
      'div[role="main"] [aria-label="Message body"]',
      'div[role="main"] .Xb0hB',
      'div[role="main"] div[class*="readingPane"] div',
      'div[role="main"] .readingPaneContainerSource div',
      'div[role="main"] [class*="Body"] div'
    ];
    for (const sel of outlookSelectors) {
      try {
        const found = root.querySelectorAll(sel);
        for (const el of found) {
          if (el.innerText && el.innerText.trim().length > 20 && !el.closest("[data-scam-guard-checked]")) {
            elements.push(el);
          }
        }
      } catch (e) {
      }
    }
    const fallback = root.querySelectorAll('div[role="main"] div[style*="font"]');
    for (const el of fallback) {
      const text = el.innerText || "";
      if (text.trim().length > 50 && !el.closest("[data-scam-guard-checked]") && !elements.includes(el)) {
        const hasChildWithText = Array.from(el.children).some(c => (c.innerText || "").trim().length > 50);
        if (!hasChildWithText) elements.push(el);
      }
    }
  }

  return Array.from(new Set(elements));
}

function findEmailContainer(element) {
  if (isGmail()) {
    return element.closest('div[role="main"]') ||
           element.closest('div[data-message-id]') ||
           element.closest('div[class*="a3s"]') ||
           element.closest('div[class*="ii"]') ||
           element.closest('table[role="presentation"]') ||
           element.parentElement;
  }
  if (isOutlook()) {
    return element.closest('[role="main"] > div') ||
           element.closest('.readingPaneContainerSource') ||
           element.parentElement;
  }
  return element.parentElement;
}

function markEmailElement(contentEl, analysis) {
  const container = findEmailContainer(contentEl);
  if (!container) return;

  if (container.hasAttribute(SCAM_GUARD_ATTRIBUTE)) return;

  container.setAttribute(SCAM_GUARD_ATTRIBUTE, "true");

  if (!analysis.suspicious) return;

  if (container.querySelector(".scam-guard-warning")) return;

  container.style.border = "2px solid #e53935";
  container.style.borderRadius = "8px";
  container.style.padding = "8px";

  const warning = createWarningElement(analysis);
  warning.className = "scam-guard-warning";
  container.appendChild(warning);
}

function showTopBanner(analysis) {
  const id = "scam-guard-top-banner";
  let banner = document.getElementById(id);
  if (banner) return;

  banner = document.createElement("div");
  banner.id = id;
  banner.className = "scam-guard-warning";
  banner.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b71c1c;color:#fff;padding:10px 16px;font-size:13px;font-family:system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,0.3);";

  const riskLabel = analysis.score >= 7 ? "HIGH RISK" : "SUSPICIOUS";
  banner.innerHTML = "<strong>Scam Guard: " + riskLabel + " email</strong> – " +
    (analysis.reasons.length ? analysis.reasons.slice(0, 3).join(", ") + ". " : "") +
    "Do not share OTPs, passwords, or send money. " +
    "<button id='scam-guard-dismiss' style='margin-left:12px;padding:4px 8px;cursor:pointer;background:#fff;color:#b71c1c;border:none;border-radius:4px;font-weight:600;'>Dismiss</button>";

  document.body.insertBefore(banner, document.body.firstChild);

  document.getElementById("scam-guard-dismiss").onclick = () => banner.remove();
}

function scanExistingEmails() {
  const root = document.body;
  const contentNodes = findEmailContentElements(root);

  for (const node of contentNodes) {
    const text = (node.innerText || node.textContent || "").trim();
    if (text.length < 15) continue;

    const analysis = isSuspiciousText(text);
    if (analysis.suspicious) {
      markEmailElement(node, analysis);
    } else {
      const c = findEmailContainer(node);
      if (c) c.setAttribute(SCAM_GUARD_ATTRIBUTE, "true");
    }
  }

  if (isGmail()) {
    const main = root.querySelector('div[role="main"]');
    if (main) {
      const fullText = (main.innerText || main.textContent || "").trim();
      if (fullText.length > 20) {
        const mainAnalysis = isSuspiciousText(fullText);
        if (mainAnalysis.suspicious) {
          showTopBanner(mainAnalysis);
        }
      }
    }
  }
}

function observeNewEmails() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        const contentNodes = findEmailContentElements(node);
        for (const msgNode of contentNodes) {
          const text = (msgNode.innerText || msgNode.textContent || "").trim();
          if (text.length < 20) continue;

          const analysis = isSuspiciousText(text);
          if (analysis.suspicious) {
            markEmailElement(msgNode, analysis);
          } else {
            const c = findEmailContainer(msgNode);
            if (c) c.setAttribute(SCAM_GUARD_ATTRIBUTE, "true");
          }
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function showScamGuardActiveBanner() {
  const existing = document.getElementById("scam-guard-active-banner");
  if (existing) return;

  const banner = document.createElement("div");
  banner.id = "scam-guard-active-banner";
  banner.textContent = "Scam Guard is active on this page";
  banner.style.position = "fixed";
  banner.style.bottom = "12px";
  banner.style.right = "12px";
  banner.style.zIndex = "99999";
  banner.style.backgroundColor = "rgba(25,118,210,0.9)";
  banner.style.color = "#ffffff";
  banner.style.padding = "6px 10px";
  banner.style.borderRadius = "4px";
  banner.style.fontSize = "12px";
  banner.style.boxShadow = "0 2px 6px rgba(0,0,0,0.3)";

  document.body.appendChild(banner);

  setTimeout(() => {
    banner.remove();
  }, 5000);
}

function initScamGuard() {
  try {
    if (!isGmail() && !isOutlook()) return;

    showScamGuardActiveBanner();
    observeNewEmails();
    scanExistingEmails();

    loadSpamModel().then(() => scanExistingEmails());

    setInterval(scanExistingEmails, 2000);
    setTimeout(scanExistingEmails, 1500);
    setTimeout(scanExistingEmails, 4000);
    window.addEventListener("hashchange", () => setTimeout(scanExistingEmails, 800));
  } catch (e) {
    console.error("Scam Guard init error:", e);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initScamGuard);
} else {
  initScamGuard();
}
