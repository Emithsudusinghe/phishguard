"""
PhishGuard — Flask Web App
Emith Sudusinghe / E194040
"""

from flask import Flask, render_template_string, request, jsonify
from detector import analyze_email

app = Flask(__name__)

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard — Email Threat Detector</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --ink:       #1a1a1a;
  --ink-mid:   #555550;
  --ink-light: #999991;
  --rule:      #ddddd8;
  --paper:     #f7f6f3;
  --white:     #ffffff;
  --safe:      #276749;
  --safe-bg:   #edf7f1;
  --warn:      #92610a;
  --warn-bg:   #fdf6e3;
  --danger:    #b91c1c;
  --danger-bg: #fef2f2;
  --accent:    #1a1a1a;
  --sans: 'DM Sans', sans-serif;
  --mono: 'DM Mono', monospace;
}

html { font-size: 16px; }
body {
  font-family: var(--sans);
  background: var(--paper);
  color: var(--ink);
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* ── HEADER ── */
.site-header {
  border-bottom: 1.5px solid var(--ink);
  padding: 0 48px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  background: var(--white);
}

.wordmark {
  font-size: 15px;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ink);
  display: flex;
  align-items: center;
  gap: 10px;
}

.wordmark-badge {
  background: var(--danger);
  color: #fff;
  font-size: 10px;
  font-weight: 500;
  padding: 2px 7px;
  border-radius: 2px;
  letter-spacing: 0.04em;
}

.header-meta {
  font-size: 12px;
  color: var(--ink-light);
  font-weight: 400;
}

/* ── LAYOUT ── */
.workspace {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 1fr;
  min-height: calc(100vh - 56px);
}

/* ── LEFT PANEL ── */
.input-panel {
  padding: 48px;
  border-right: 1.5px solid var(--rule);
  display: flex;
  flex-direction: column;
}

.panel-eyebrow {
  font-size: 11px;
  font-weight: 500;
  color: var(--ink-light);
  letter-spacing: 0.08em;
  margin-bottom: 6px;
  text-transform: uppercase;
}

.panel-title {
  font-size: 28px;
  font-weight: 600;
  letter-spacing: -0.03em;
  line-height: 1.15;
  margin-bottom: 6px;
}

.panel-desc {
  font-size: 14px;
  color: var(--ink-mid);
  line-height: 1.6;
  margin-bottom: 32px;
  max-width: 52ch;
}

.samples-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 28px;
  padding-bottom: 28px;
  border-bottom: 1px solid var(--rule);
}

.sample-chip {
  font-size: 12px;
  font-weight: 500;
  font-family: var(--sans);
  padding: 5px 14px;
  border-radius: 100px;
  border: 1.5px solid var(--rule);
  background: var(--white);
  color: var(--ink-mid);
  cursor: pointer;
  transition: border-color 0.12s, color 0.12s;
  white-space: nowrap;
}

.sample-chip:hover { border-color: var(--ink); color: var(--ink); }
.sample-chip.phishing { border-color: var(--danger); color: var(--danger); background: var(--danger-bg); }
.sample-chip.warn     { border-color: var(--warn);   color: var(--warn);   background: var(--warn-bg); }
.sample-chip.safe     { border-color: var(--safe);   color: var(--safe);   background: var(--safe-bg); }

.field { margin-bottom: 20px; }

.field label {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--ink-mid);
  margin-bottom: 6px;
}

.field input,
.field textarea {
  width: 100%;
  font-family: var(--sans);
  font-size: 14px;
  color: var(--ink);
  background: var(--white);
  border: 1.5px solid var(--rule);
  border-radius: 6px;
  padding: 10px 14px;
  outline: none;
  transition: border-color 0.12s;
  resize: vertical;
}

.field input:focus,
.field textarea:focus { border-color: var(--ink); }
.field textarea { min-height: 180px; line-height: 1.6; }

.actions {
  display: flex;
  gap: 10px;
  margin-top: 4px;
}

.btn-primary {
  font-family: var(--sans);
  font-size: 14px;
  font-weight: 600;
  background: var(--ink);
  color: var(--white);
  border: none;
  border-radius: 6px;
  padding: 11px 24px;
  cursor: pointer;
  transition: opacity 0.12s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-primary:hover { opacity: 0.8; }
.btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

.btn-secondary {
  font-family: var(--sans);
  font-size: 14px;
  font-weight: 500;
  background: transparent;
  color: var(--ink-mid);
  border: 1.5px solid var(--rule);
  border-radius: 6px;
  padding: 11px 20px;
  cursor: pointer;
  transition: border-color 0.12s, color 0.12s;
}

.btn-secondary:hover { border-color: var(--ink-mid); color: var(--ink); }

/* ── RIGHT PANEL ── */
.result-panel {
  padding: 48px;
  display: flex;
  flex-direction: column;
}

.result-empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  color: var(--ink-light);
}

.result-empty-icon {
  font-size: 40px;
  margin-bottom: 16px;
  opacity: 0.3;
}

.result-empty p { font-size: 14px; max-width: 28ch; line-height: 1.6; }

/* verdict */
.verdict { display: none; }

.verdict-stamp {
  display: inline-flex;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 8px;
}

.verdict-word {
  font-size: 48px;
  font-weight: 600;
  letter-spacing: -0.04em;
  line-height: 1;
}

.verdict-word.safe    { color: var(--safe); }
.verdict-word.suspicious { color: var(--warn); }
.verdict-word.phishing   { color: var(--danger); }

.verdict-score {
  font-family: var(--mono);
  font-size: 14px;
  color: var(--ink-light);
  font-weight: 400;
  align-self: flex-end;
  padding-bottom: 8px;
}

.verdict-desc {
  font-size: 14px;
  color: var(--ink-mid);
  line-height: 1.6;
  margin-bottom: 28px;
  max-width: 52ch;
}

/* score bar */
.score-bar-wrap {
  margin-bottom: 32px;
  padding-bottom: 28px;
  border-bottom: 1px solid var(--rule);
}

.score-bar-labels {
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--ink-light);
  margin-bottom: 6px;
  font-family: var(--mono);
}

.score-track {
  height: 5px;
  background: var(--rule);
  border-radius: 3px;
  overflow: hidden;
}

.score-fill {
  height: 100%;
  border-radius: 3px;
  width: 0%;
  transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
}

.score-fill.safe    { background: var(--safe); }
.score-fill.suspicious { background: var(--warn); }
.score-fill.phishing   { background: var(--danger); }

/* rules */
.rules-heading {
  font-size: 11px;
  font-weight: 500;
  color: var(--ink-light);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin-bottom: 14px;
}

.rule-row {
  padding: 16px 0;
  border-bottom: 1px solid var(--rule);
}

.rule-row:first-of-type { border-top: none; }

.rule-top {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 6px;
}

.rule-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
}

.rule-pts {
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 500;
  color: var(--danger);
}

.rule-indicators {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 10px;
}

.indicator {
  font-size: 11px;
  font-family: var(--mono);
  padding: 2px 8px;
  background: var(--danger-bg);
  color: var(--danger);
  border-radius: 3px;
  border: 1px solid #fecaca;
}

.rule-tip {
  font-size: 13px;
  color: var(--ink-mid);
  line-height: 1.55;
  padding-left: 12px;
  border-left: 2px solid var(--rule);
}

.clean-msg {
  font-size: 14px;
  color: var(--safe);
  padding: 14px 0;
  font-weight: 500;
}

/* spinner */
.spin {
  display: none;
  width: 15px; height: 15px;
  border: 2px solid rgba(255,255,255,0.3);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.55s linear infinite;
}

@keyframes spin { to { transform: rotate(360deg); } }

/* responsive */
@media (max-width: 800px) {
  .workspace { grid-template-columns: 1fr; }
  .input-panel { border-right: none; border-bottom: 1.5px solid var(--rule); }
  .site-header { padding: 0 20px; }
  .input-panel, .result-panel { padding: 28px 20px; }
  .panel-title { font-size: 22px; }
}
</style>
</head>
<body>

<header class="site-header">
  <div class="wordmark">
    PhishGuard
    <span class="wordmark-badge">BETA</span>
  </div>
  <div class="header-meta">E194040 &nbsp;·&nbsp; Individual Project</div>
</header>

<div class="workspace">

  <!-- LEFT: INPUT -->
  <div class="input-panel">
    <p class="panel-eyebrow">Email threat analyser</p>
    <h1 class="panel-title">Is this email trying to trick you?</h1>
    <p class="panel-desc">Paste any email below. The system scans it for phishing signals — urgency language, sensitive info requests, link mismatches, and generic greetings — then scores and explains the risk.</p>

    <div class="samples-row">
      <span style="font-size:12px;color:var(--ink-light);align-self:center;margin-right:2px;">Try a sample:</span>
      <button class="sample-chip phishing" onclick="loadSample('phishing')">Phishing email</button>
      <button class="sample-chip warn"     onclick="loadSample('suspicious')">Suspicious email</button>
      <button class="sample-chip safe"     onclick="loadSample('safe')">Safe email</button>
    </div>

    <div class="field">
      <label>Subject line</label>
      <input type="text" id="subject" placeholder="e.g. Urgent: Your account has been suspended">
    </div>

    <div class="field">
      <label>Email body</label>
      <textarea id="body" placeholder="Paste the full email text here…"></textarea>
    </div>

    <div class="actions">
      <button class="btn-primary" id="analyseBtn" onclick="analyse()">
        <span class="spin" id="spinner"></span>
        Analyse email
      </button>
      <button class="btn-secondary" onclick="clearAll()">Clear</button>
    </div>
  </div>

  <!-- RIGHT: RESULT -->
  <div class="result-panel">

    <div class="result-empty" id="emptyState">
      <div class="result-empty-icon">⬡</div>
      <p>Your result will appear here once you analyse an email.</p>
    </div>

    <div class="verdict" id="verdict">
      <div class="verdict-stamp">
        <div class="verdict-word" id="verdictWord"></div>
        <div class="verdict-score" id="verdictScore"></div>
      </div>
      <p class="verdict-desc" id="verdictDesc"></p>

      <div class="score-bar-wrap">
        <div class="score-bar-labels">
          <span>Safe (0–2)</span>
          <span>Suspicious (3–5)</span>
          <span>Phishing (6+)</span>
        </div>
        <div class="score-track">
          <div class="score-fill" id="scoreFill"></div>
        </div>
      </div>

      <p class="rules-heading" id="rulesHeading"></p>
      <div id="rulesList"></div>
    </div>

  </div>
</div>

<script>
const SAMPLES = {
  phishing: {
    subject: "Urgent: Your Account Will Be Suspended",
    body: `Dear Customer,

We have detected unauthorized access attempts on your account. Immediate action is required within 24 hours or your account will be permanently locked.

Please verify your identity by clicking the link below and confirming your password and credit card details.

<a href="http://paypal-secure-verify.xyz-login.net/confirm">paypal.com</a>

Failure to respond may result in permanent suspension of your account.

PayPal Security Team`
  },
  suspicious: {
    subject: "Action Required: Update Your Information",
    body: `Dear Customer,

We noticed some unusual activity on your account. Please review your account details and confirm your information is up to date as soon as possible.

Visit our website for more details.

Regards,
Support Team`
  },
  safe: {
    subject: "Your October statement is ready",
    body: `Hi Sarah,

Your statement for October is now available in your online banking portal.

Log in at mybank.com to view your statement. If you have any questions, call us on 0800 123 456.

Kind regards,
MyBank Customer Services`
  }
};

function loadSample(type) {
  document.getElementById('subject').value = SAMPLES[type].subject;
  document.getElementById('body').value = SAMPLES[type].body;
  document.getElementById('verdict').style.display = 'none';
  document.getElementById('emptyState').style.display = 'flex';
}

function clearAll() {
  document.getElementById('subject').value = '';
  document.getElementById('body').value = '';
  document.getElementById('verdict').style.display = 'none';
  document.getElementById('emptyState').style.display = 'flex';
}

async function analyse() {
  const subject = document.getElementById('subject').value.trim();
  const body    = document.getElementById('body').value.trim();
  if (!subject && !body) { alert('Please paste an email first.'); return; }

  const btn = document.getElementById('analyseBtn');
  const spin = document.getElementById('spinner');
  btn.disabled = true;
  spin.style.display = 'inline-block';

  try {
    const res  = await fetch('/analyse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ subject, body })
    });
    const data = await res.json();
    render(data);
  } catch(e) {
    alert('Something went wrong. Please try again.');
  } finally {
    btn.disabled = false;
    spin.style.display = 'none';
  }
}

function render(data) {
  const cls = data.classification.toLowerCase();

  document.getElementById('emptyState').style.display = 'none';
  const v = document.getElementById('verdict');
  v.style.display = 'block';

  // word + score
  const w = document.getElementById('verdictWord');
  w.textContent = data.classification;
  w.className = 'verdict-word ' + cls;

  document.getElementById('verdictScore').textContent = 'Score ' + data.score + ' / 10';
  document.getElementById('verdictDesc').textContent  = data.description;

  // bar
  const fill = document.getElementById('scoreFill');
  fill.className = 'score-fill ' + cls;
  fill.style.width = '0%';
  setTimeout(() => { fill.style.width = Math.min(data.score / 10 * 100, 100) + '%'; }, 30);

  // rules heading
  document.getElementById('rulesHeading').textContent =
    data.rules_triggered + ' of ' + data.rules_checked + ' rules triggered';

  // rules list
  const list = document.getElementById('rulesList');
  list.innerHTML = '';

  if (data.triggered_rules.length === 0) {
    list.innerHTML = '<p class="clean-msg">No phishing signals detected in this email.</p>';
    return;
  }

  data.triggered_rules.forEach(rule => {
    const row = document.createElement('div');
    row.className = 'rule-row';
    row.innerHTML = `
      <div class="rule-top">
        <span class="rule-name">${rule.category}</span>
        <span class="rule-pts">+${rule.score} pts</span>
      </div>
      <div class="rule-indicators">
        ${rule.indicators.map(i => `<span class="indicator">${i}</span>`).join('')}
      </div>
      <p class="rule-tip">${rule.tip}</p>
    `;
    list.appendChild(row);
  });
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/analyse", methods=["POST"])
def analyse():
    data    = request.get_json()
    subject = data.get("subject", "")
    body    = data.get("body", "")
    result  = analyze_email(subject, body)
    return jsonify(result)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print("\n  PhishGuard — Phishing Email Detection System")
    print("  Emith Sudusinghe / E194040")
    print(f"\n  Running at: http://127.0.0.1:{port}\n")
    app.run(host='10.53.81.96', port=5000)
