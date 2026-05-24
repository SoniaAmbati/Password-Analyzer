const password = document.getElementById("password");
const strengthFill = document.getElementById("strengthFill");
const strengthText = document.getElementById("strengthText");
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

toggleBtn.addEventListener("click", () => {
  if (password.type === "password") {
    password.type = "text";
    toggleBtn.textContent = "Hide";
  } else {
    password.type = "password";
    toggleBtn.textContent = "Show";
  }
});