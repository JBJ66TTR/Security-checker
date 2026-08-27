const scanButton = document.getElementById("scanButton");
const codeInput = document.getElementById("code");
const results = document.getElementById("results");
const resultList = document.getElementById("resultList");

const rules = [
  {
    name: "Possible API key",
    severity: "high",
    pattern: /(api[_-]?key)\s*[:=]\s*["'`](?!your[-_ ]?secret|example|xxxxxxxx)([^"'`]{12,})["'`]/i,
    advice:
      "Move the API key into an environment variable instead of storing it in source code."
  },

  {
    name: "Possible password",
    severity: "high",
    pattern: /(password|passwd|pwd)\s*[:=]\s*["'`](?!password|example|changeme)([^"'`]{6,})["'`]/i,
    advice:
      "Do not hard-code passwords. Use a secret manager or environment variable."
  },

  {
    name: "Possible access token",
    severity: "high",
    pattern: /(access[_-]?token|auth[_-]?token)\s*[:=]\s*["'`](?!example|your[-_ ]?token)([^"'`]{12,})["'`]/i,
    advice:
      "Store authentication tokens outside the source code."
  },

  {
    name: "Possible private key",
    severity: "high",
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i,
    advice:
      "Never commit a private key. Revoke the key if it has already been exposed."
  },

  {
    name: "Possible database credential",
    severity: "high",
    pattern: /(mongodb|postgres|mysql|redis):\/\/[^"'`\s]+/i,
    advice:
      "Database connection strings can contain credentials. Store them securely outside the repository."
  }
];

function scanCode(code) {
  const findings = [];
  const lines = code.split("\n");

  lines.forEach((line, index) => {
    rules.forEach((rule) => {
      if (rule.pattern.test(line)) {
        findings.push({
          name: rule.name,
          severity: rule.severity,
          line: index + 1,
          advice: rule.advice
        });
      }

      // Reset regex state for global patterns.
      rule.pattern.lastIndex = 0;
    });
  });

  return findings;
}

function showResults(findings) {
  results.classList.remove("hidden");
  resultList.innerHTML = "";

  if (findings.length === 0) {
    resultList.innerHTML = `
      <div class="success">
        ✓ No obvious exposed secrets detected.
      </div>
    `;

    return;
  }

  findings.forEach((finding) => {
    const element = document.createElement("div");

    element.className = `result ${finding.severity}`;

    element.innerHTML = `
      <h3>⚠️ ${escapeHtml(finding.name)}</h3>
      <p>
        <strong>Line:</strong> ${finding.line}
      </p>
      <p>
        ${escapeHtml(finding.advice)}
      </p>
    `;

    resultList.appendChild(element);
  });
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

scanButton.addEventListener("click", () => {
  const code = codeInput.value;

  if (!code.trim()) {
    results.classList.remove("hidden");

    resultList.innerHTML = `
      <div class="result info">
        <h3>ℹ️ Nothing to scan</h3>
        <p>Paste some source code and try again.</p>
      </div>
    `;

    return;
  }

  const findings = scanCode(code);

  showResults(findings);
});
