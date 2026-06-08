const password = document.getElementById("password");
const strengthFill = document.getElementById("strengthFill");
const strengthLabel = document.getElementById("strengthLabel");
const strengthIcon = document.getElementById("strengthIcon");
const entropyLabel = document.getElementById("entropyLabel");
const entropyIcon = document.getElementById("entropyIcon");
const toggleBtn = document.getElementById("toggleBtn");

const checks = {
  length: document.getElementById("length"),
  uppercase: document.getElementById("uppercase"),
  lowercase: document.getElementById("lowercase"),
  number: document.getElementById("number"),
  special: document.getElementById("special")
};

const suggestionsList = document.getElementById("suggestionsList");

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
    entropyLabel.innerHTML = `Entropy: 0 bits<br>Security Level: None`;
    entropyLabel.style.color = "#fff";
    entropyIcon.textContent = "⚪";
    entropyIcon.style.color = "#cbd5e1";
  } else {
    entropyLabel.innerHTML = `Entropy: ${rounded} bits<br>Security Level: ${level.text}`;
    entropyLabel.style.color = level.color;
    // set entropy icon based on level
    entropyIcon.textContent = level.text === 'Very Weak' ? '❌' : level.text === 'Weak' ? '⚠️' : level.text === 'Medium' ? '🟡' : level.text === 'Strong' ? '✅' : '🔒';
    entropyIcon.style.color = level.color;
  }

  // Generate and display real-time suggestions
  const suggestions = generateSuggestions(val, rules, entropy);
  renderSuggestions(suggestions);

  if (val.length === 0) {
    strengthLabel.textContent = "Strength: None";
    strengthLabel.style.color = "#fff";
    strengthIcon.textContent = "🔒";
    strengthIcon.style.color = "#cbd5e1";

    strengthFill.style.width = "0%";
    strengthFill.style.background = "transparent";
  }

  // Common password check (case-insensitive)
  const isCommon = checkCommonPassword(val);
  if (isCommon) {
    strengthLabel.textContent = "Common Password Detected";
    strengthLabel.style.color = "#ef4444";
    strengthIcon.textContent = "⚠️";
    strengthIcon.style.color = "#ef4444";
    strengthFill.style.width = "10%";
    strengthFill.style.background = "#ef4444";
    entropyLabel.innerHTML = `Entropy: 0 bits<br>Security Level: Very Weak`;
    entropyLabel.style.color = "#ef4444";
    entropyIcon.textContent = "❌";
    entropyIcon.style.color = "#ef4444";
  }

  // Schedule HIBP breach check (debounced). Skip if empty or already common.
  if (pwnedTimer) clearTimeout(pwnedTimer);
  if (!val || isCommon) return;

  pwnedTimer = setTimeout(async () => {
    try {
      const count = await checkPwnedPassword(val);
      if (count > 0) {
        strengthLabel.textContent = `Compromised: seen ${count} times`;
        strengthLabel.style.color = "#ef4444";
        strengthIcon.textContent = "❗";
        strengthIcon.style.color = "#ef4444";
        strengthFill.style.width = "10%";
        strengthFill.style.background = "#ef4444";
        entropyLabel.innerHTML = `Entropy: 0 bits<br>Security Level: Very Weak`;
        entropyLabel.style.color = "#ef4444";
        entropyIcon.textContent = "❌";
        entropyIcon.style.color = "#ef4444";
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

  strengthLabel.textContent = `Strength: ${text}`;
  strengthLabel.style.color = color;
  // set icon
  strengthIcon.textContent = text === 'Very Weak' ? '❌' : text === 'Weak' ? '⚠️' : text === 'Medium' ? '🟡' : text === 'Strong' ? '✅' : '🔒';
  strengthIcon.style.color = color;
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

function generateSuggestions(val, rules, entropy) {
  const s = [];
  if (!val) return s;

  // Length recommendation (target 12)
  const target = 12;
  if (val.length < target) {
    s.push(`Add ${target - val.length} more character${target - val.length > 1 ? 's' : ''}`);
  }

  if (!rules.uppercase) s.push('Include an uppercase letter');
  if (!rules.lowercase) s.push('Include a lowercase letter');
  if (!rules.number) s.push('Include a number');
  if (!rules.special) s.push('Include a special character');

  // Repeated characters
  if (/(.)\1{2,}/.test(val)) s.push('Avoid repeated characters (e.g. "aaa")');

  // Repeated sequence (e.g. abcabc)
  if (/(.+)\1{1,}/.test(val)) s.push('Avoid repeated patterns');

  // Simple sequential check for digits (e.g. 1234)
  if (/0123|1234|2345|3456|4567|5678|6789/.test(val)) s.push('Avoid sequential patterns (e.g. "1234")');

  // If entropy is low for length, suggest more unpredictability
  if (entropy < 40 && val.length >= target) s.push('Increase unpredictability (use varied characters)');

  // Deduplicate and limit suggestions
  return [...new Set(s)].slice(0, 6);
}

function renderSuggestions(items) {
  suggestionsList.innerHTML = '';
  if (!items || items.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No suggestions — looking good.';
    suggestionsList.appendChild(li);
    return;
  }

  for (const it of items) {
    const li = document.createElement('li');
    li.textContent = it;
    suggestionsList.appendChild(li);
  }
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

  // Use icons and update accessible label
  if (isHidden) {
    // now visible
    toggleBtn.textContent = '🙈';
    toggleBtn.setAttribute('aria-pressed', 'true');
    toggleBtn.setAttribute('aria-label', 'Hide password');
  } else {
    // now hidden
    toggleBtn.textContent = '👁️';
    toggleBtn.setAttribute('aria-pressed', 'false');
    toggleBtn.setAttribute('aria-label', 'Show password');
  }
});