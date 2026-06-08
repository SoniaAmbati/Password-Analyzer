const password = document.getElementById("password");
const strengthFill = document.getElementById("strengthFill");
const strengthText = document.getElementById("strengthText");
const entropyText = document.getElementById("entropyText");
const toggleBtn = document.getElementById("toggleBtn");
const suggestionsList = document.getElementById("suggestionsList");

const checks = {
  length: document.getElementById("length"),
  uppercase: document.getElementById("uppercase"),
  lowercase: document.getElementById("lowercase"),
  number: document.getElementById("number"),
  special: document.getElementById("special")
};

// HIBP k-Anonymity helpers
let pwnedTimer = null;
let lastPwnedHash = null;

// Small built-in common passwords list (case-insensitive)
const _builtInCommon = [
  "password",
  "123456",
  "123456789",
  "qwerty",
  "abc123",
  "111111",
  "12345678",
  "admin",
  "letmein",
  "welcome"
];
const commonPasswords = new Set(_builtInCommon.map(p => p.toLowerCase()));
let externalCommonSet = null; // will hold a Set when lazy-loaded

password.addEventListener("input", () => {
  const val = password.value;

  // lazy-load external list when user types a few characters
  if (!externalCommonSet && val.length >= 4) {
    loadCommonPasswords();
  }

  const rules = {
    length: val.length >= 8,
    uppercase: /[A-Z]/.test(val),
    lowercase: /[a-z]/.test(val),
    number: /[0-9]/.test(val),
    special: /[^A-Za-z0-9]/.test(val)
  };

  let score = 0;

  for (let key in rules) {
    if (rules[key]) {
      checks[key].classList.add("valid");
      checks[key].classList.remove("invalid");
      score++;
    } else {
      checks[key].classList.add("invalid");
      checks[key].classList.remove("valid");
    }
  }

  updateStrength(score);

  // Calculate and display entropy + security level
  const entropy = calculateEntropy(val);
  const rounded = Math.round(entropy);
  const level = getSecurityLevel(entropy);

  if (val.length === 0) {
    entropyText.innerHTML = `Entropy: 0 bits<br>Security Level: None`;
    entropyText.style.color = "#fff";
  } else {
    entropyText.innerHTML = `Entropy: ${rounded} bits<br>Security Level: ${level.text}`;
    entropyText.style.color = level.color;
  }

  if (val.length === 0) {
    strengthText.textContent = "Strength: None";
    strengthText.style.color = "#fff";

    strengthFill.style.width = "0%";
    strengthFill.style.background = "transparent";
  }

  // Common password check (case-insensitive)
  const isCommon = checkCommonPassword(val);
  if (isCommon) {
    strengthText.textContent = "Common Password Detected";
    strengthText.style.color = "#ef4444";
    strengthFill.style.width = "10%";
    strengthFill.style.background = "#ef4444";
    entropyText.innerHTML = `Entropy: 0 bits<br>Security Level: Very Weak`;
    entropyText.style.color = "#ef4444";
  }

  // Compute and render suggestions immediately
  const suggestions = getSuggestions(val, rules, entropy, isCommon);
  renderSuggestions(suggestions);

  // Schedule HIBP breach check (debounced). Skip if empty or already common.
  if (pwnedTimer) clearTimeout(pwnedTimer);
  if (!val) return;

  pwnedTimer = setTimeout(async () => {
    try {
      const count = await checkPwnedPassword(val);
      if (count > 0) {
        strengthText.textContent = `Compromised: seen ${count} times`;
        strengthText.style.color = "#ef4444";
        strengthFill.style.width = "10%";
        strengthFill.style.background = "#ef4444";
        entropyText.innerHTML = `Entropy: 0 bits<br>Security Level: Very Weak`;
        entropyText.style.color = "#ef4444";
        // update suggestions to warn user
        renderSuggestions([`This password was found in breaches (${count} times) — choose a unique password`]);
      }
    } catch (e) {
      // network or crypto errors — silently ignore
    }
  }, 700);
});

function updateStrength(score) {
  let width = "0%";
  let color = "";
  let text = "";

  switch(score) {
    case 0:
    case 1:
      width = "20%";
      color = "#ef4444";
      text = "Very Weak";
      break;

    case 2:
      width = "40%";
      color = "#f97316";
      text = "Weak";
      break;

    case 3:
      width = "60%";
      color = "#eab308";
      text = "Medium";
      break;

    case 4:
      width = "80%";
      color = "#22c55e";
      text = "Strong";
      break;

    case 5:
      width = "100%";
      color = "#16a34a";
      text = "Very Strong";
      break;
  }

  strengthFill.style.width = width;
  strengthFill.style.background = color;

  strengthText.textContent = `Strength: ${text}`;
  strengthText.style.color = color;
}

function calculateEntropy(password) {
  let pool = 0;

  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;

  const entropy = password.length * Math.log2(pool || 1);
  return isFinite(entropy) ? entropy : 0;
}

function getSecurityLevel(entropy) {
  if (entropy <= 28) return { text: "Very Weak", color: "#ef4444" };
  if (entropy <= 36) return { text: "Weak", color: "#f97316" };
  if (entropy <= 60) return { text: "Medium", color: "#eab308" };
  if (entropy <= 100) return { text: "Strong", color: "#22c55e" };
  return { text: "Excellent", color: "#16a34a" };
}

async function sha1Hex(input) {
  const enc = new TextEncoder();
  const data = enc.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const bytes = Array.from(new Uint8Array(hashBuffer));
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Returns number of times password seen in breaches (0 if not found)
async function checkPwnedPassword(password) {
  const hash = await sha1Hex(password);
  if (hash === lastPwnedHash) return 0; // already checked same hash recently
  lastPwnedHash = hash;

  const prefix = hash.slice(0,5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!res.ok) return 0;
  const txt = await res.text();
  const lines = txt.split(/\r?\n/);
  for (const line of lines) {
    const [hashSuffix, countStr] = line.split(':');
    if (!hashSuffix) continue;
    if (hashSuffix.toUpperCase() === suffix.toUpperCase()) {
      const count = parseInt(countStr.replace(/\D/g, ''), 10) || 0;
      return count;
    }

  function getSuggestions(password, rules, entropy, isCommon) {
    const out = [];
    if (!password) return out;

    // Length suggestion (recommend 12+)
    const desired = 12;
    if (password.length < desired) {
      const need = desired - password.length;
      out.push(`Add ${need} more character${need > 1 ? 's' : ''}`);
    }

    if (!rules.uppercase) out.push('Include an uppercase letter');
    if (!rules.lowercase) out.push('Include a lowercase letter');
    if (!rules.number) out.push('Include a number');
    if (!rules.special) out.push('Include a special character');

    if (hasRepeatedPatterns(password)) out.push('Avoid repeated characters or repeated patterns');
    if (hasSequentialChars(password, 4)) out.push('Avoid sequential characters (e.g. 1234 or abcd)');

    if (isCommon) out.unshift('Avoid commonly used passwords');

    // Low entropy suggestion
    if (entropy <= 28 && out.indexOf('Avoid commonly used passwords') === -1) {
      out.push('Increase length and character variety to raise entropy');
    }

    return out;
  }

  function renderSuggestions(list) {
    if (!suggestionsList) return;
    if (!list || list.length === 0) {
      suggestionsList.innerHTML = '<li>None — good job!</li>';
      return;
    }
    suggestionsList.innerHTML = list.map(s => `<li>${s}</li>`).join('');
  }

  function hasRepeatedPatterns(pw) {
    if (!pw) return false;
    if (/(.)\1{2,}/.test(pw)) return true; // aaa
    if (/([\w\W]{2,})\1/.test(pw)) return true; // abcdabcd
    return false;
  }

  function hasSequentialChars(pw, minLen = 4) {
    if (!pw || pw.length < minLen) return false;
    const seq = (a, b) => b.charCodeAt(0) - a.charCodeAt(0);
    // check for increasing or decreasing runs
    for (let i = 0; i <= pw.length - minLen; i++) {
      let inc = true, dec = true;
      for (let j = i; j < i + minLen - 1; j++) {
        const diff = pw.charCodeAt(j+1) - pw.charCodeAt(j);
        if (diff !== 1) inc = false;
        if (diff !== -1) dec = false;
      }
      if (inc || dec) return true;
    }
    return false;
  }
  }
  return 0;
}

function checkCommonPassword(val) {
  if (!val) return false;
  const low = val.toLowerCase();
  if (commonPasswords.has(low)) return true;
  if (externalCommonSet && externalCommonSet.has(low)) return true;
  return false;
}

// Lazy-load a larger common passwords file named 'common-passwords.txt' (one per line).
// This is optional — if the file isn't present or fetch fails, we silently continue.
async function loadCommonPasswords() {
  if (externalCommonSet) return;
  try {
    const res = await fetch('common-passwords.txt');
    if (!res.ok) return;
    const txt = await res.text();
    const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    externalCommonSet = new Set(lines.map(l => l.toLowerCase()));
    // merge into the built-in set for faster single-set checks
    for (const p of externalCommonSet) commonPasswords.add(p);
  } catch (e) {
    // ignore; fetching may fail when opened via file:// or not served
  }
}

toggleBtn.addEventListener("click", () => {

  const isHidden = password.type === "password";

  password.type = isHidden ? "text" : "password";

  toggleBtn.textContent = isHidden ? "Hide" : "Show";
});