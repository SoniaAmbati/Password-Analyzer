const password = document.getElementById("password");
const strengthFill = document.getElementById("strengthFill");
const strengthText = document.getElementById("strengthText");
const entropyText = document.getElementById("entropyText");
const toggleBtn = document.getElementById("toggleBtn");

const checks = {
  length: document.getElementById("length"),
  uppercase: document.getElementById("uppercase"),
  lowercase: document.getElementById("lowercase"),
  number: document.getElementById("number"),
  special: document.getElementById("special")
};

password.addEventListener("input", () => {
  const val = password.value;

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

toggleBtn.addEventListener("click", () => {

  const isHidden = password.type === "password";

  password.type = isHidden ? "text" : "password";

  toggleBtn.textContent = isHidden ? "Hide" : "Show";
});