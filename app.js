/* ── app.js ─────────────────────────────────────────────────────────────── */
/* Achilles v3 — data-driven architecture                                    */
/* Content lives in data/divisions.js + config.json. Edit behavior here.     */

// ── API ─────────────────────────────────────────────────────────────────────
// Prototype: direct browser calls (requires python3 -m http.server 8080)
// Production: switch ENDPOINT to '/.netlify/functions/analyze' and remove
//             the dangerous header — the key lives in Netlify env vars.
const IS_NETLIFY = window.location.hostname !== 'localhost'
                && window.location.hostname !== '127.0.0.1'
                && window.location.protocol !== 'file:';

const ENDPOINT = IS_NETLIFY
  ? '/.netlify/functions/analyze'
  : 'https://api.anthropic.com/v1/messages';

const API_KEY_HARDCODED = ''; // local dev only — enter key in UI or use python server.py

// ── STATE ───────────────────────────────────────────────────────────────────
const S = {
  user:      null,   // { username, cryptoKey, data: { analyses, savedApiKey } }
  division:  null,
  images:    { front: null, side: null, back: null },
  showDate:  null,   // Date | null
  showName:  '',
  chatHistory: [],
  lastReport:  null,
};

// ── CRYPTO ──────────────────────────────────────────────────────────────────
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name:'PBKDF2', salt, iterations:120000, hash:'SHA-256' }, km, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
async function deriveVerifier(password, salt) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password+'|verify'), 'PBKDF2', false, ['deriveKey']);
  const k  = await crypto.subtle.deriveKey({ name:'PBKDF2', salt, iterations:120000, hash:'SHA-256' }, km, { name:'AES-GCM', length:256 }, true, ['encrypt']);
  return bufToB64(await crypto.subtle.exportKey('raw', k));
}
async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(data)));
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(ct)) };
}
async function decrypt(obj, key) {
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(obj.iv) }, key, new Uint8Array(obj.data));
  return JSON.parse(new TextDecoder().decode(pt));
}
function bufToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64ToBuf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }

// ── STORAGE ─────────────────────────────────────────────────────────────────
function getAccounts() { try { return JSON.parse(localStorage.getItem('achilles_v2_accounts') || '{}'); } catch { return {}; } }
function saveAccounts(a) { localStorage.setItem('achilles_v2_accounts', JSON.stringify(a)); }

// ── AUTH UI ──────────────────────────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.auth-tab').forEach((t,i) =>
    t.classList.toggle('active', (i===0&&tab==='login')||(i===1&&tab==='register')));
  document.getElementById('loginPanel').classList.toggle('active', tab==='login');
  document.getElementById('registerPanel').classList.toggle('active', tab==='register');
  clearAuthError();
}
function showAuthError(msg) { const e=document.getElementById('authError'); e.textContent=msg; e.classList.add('visible'); }
function clearAuthError() { document.getElementById('authError').classList.remove('visible'); }

async function doRegister() {
  clearAuthError();
  const username = document.getElementById('regUser').value.trim();
  const pass     = document.getElementById('regPass').value;
  const confirm  = document.getElementById('regPassConfirm').value;
  if (!username) return showAuthError('Please enter a name.');
  if (pass.length < 6) return showAuthError('Password must be at least 6 characters.');
  if (pass !== confirm) return showAuthError('Passwords do not match.');
  const accounts = getAccounts();
  if (accounts[username.toLowerCase()]) return showAuthError('That name is already taken.');
  const btn = document.getElementById('registerBtn');
  btn.disabled = true; btn.textContent = 'Creating...';
  try {
    const saltBuf = crypto.getRandomValues(new Uint8Array(16));
    const salt = bufToB64(saltBuf);
    const verifier = await deriveVerifier(pass, saltBuf);
    const cryptoKey = await deriveKey(pass, saltBuf);
    const init = { analyses: [], savedApiKey: null, nutrition: { goals: { calories:0, protein:0, carbs:0, fat:0, water:128 }, logs: {} }, profile: { avatar: null }, gallery: [] };
    accounts[username.toLowerCase()] = { displayName: username, salt, verifier, encryptedData: await encrypt(init, cryptoKey) };
    saveAccounts(accounts);
    S.user = { username, cryptoKey, data: init };
    enterApp();
  } catch(e) { showAuthError('Error creating account: '+e.message); }
  finally { btn.disabled=false; btn.textContent='Create Account'; }
}

async function doLogin() {
  clearAuthError();
  const username = document.getElementById('loginUser').value.trim();
  const pass     = document.getElementById('loginPass').value;
  if (!username||!pass) return showAuthError('Please enter your name and password.');
  const accounts = getAccounts();
  const record   = accounts[username.toLowerCase()];
  if (!record) return showAuthError('No account found with that name.');
  const btn = document.getElementById('loginBtn');
  btn.disabled=true; btn.textContent='Verifying...';
  try {
    const saltBuf = b64ToBuf(record.salt);
    const verifier = await deriveVerifier(pass, saltBuf);
    if (verifier !== record.verifier) { showAuthError('Incorrect password.'); return; }
    const cryptoKey = await deriveKey(pass, saltBuf);
    const data = await decrypt(record.encryptedData, cryptoKey);
    S.user = { username: record.displayName, cryptoKey, data };
    enterApp();
  } catch { showAuthError('Login failed. Check your password.'); }
  finally { btn.disabled=false; btn.textContent='Enter'; }
}

function logout() {
  S.user=null; S.division=null; S.images={front:null,side:null,back:null}; S.chatHistory=[]; S.lastReport=null;
  document.querySelector('header').style.display = '';
  document.getElementById('navBar').style.display = '';
  document.getElementById('authScreen').classList.add('active');
  document.getElementById('appScreen').classList.remove('active');
  document.getElementById('loginUser').value='';
  document.getElementById('loginPass').value='';
  clearAuthError();
}

function enterApp() {
  // Ensure nutrition/profile data structures exist (migration for old accounts)
  if (!S.user.data.nutrition) {
    S.user.data.nutrition = { goals: { calories:0, protein:0, carbs:0, fat:0, water:128 }, logs: {} };
  }
  if (!S.user.data.profile) {
    S.user.data.profile = { avatar: null };
  }
  if (!S.user.data.gallery) {
    S.user.data.gallery = [];
  }

  document.getElementById('authScreen').classList.remove('active');
  document.getElementById('appScreen').classList.add('active');
  document.querySelector('header').style.display = 'none';
  document.getElementById('navBar').style.display = 'none';
  document.getElementById('navUsername').textContent = S.user.username.toUpperCase();
  if (!IS_NETLIFY) {
    const apiRow = document.getElementById('apiRow');
    const remRow = document.getElementById('rememberRow');
    if (apiRow) apiRow.style.display = 'flex';
    if (remRow) remRow.style.display = 'flex';
  }
  if (S.user.data.savedApiKey) {
    document.getElementById('apiKeyInput').value = S.user.data.savedApiKey;
    document.getElementById('rememberKey').checked = true;
  }
  showSection('home');
  showStep(1);
}

// ── STEP NAV ─────────────────────────────────────────────────────────────────
function showStep(n) {
  ['step1','step2','step3'].forEach((id,i) =>
    document.getElementById(id).style.display = (i+1===n)?'block':'none');
  document.getElementById('loadingScreen').classList.remove('active');
  // Hide API key row on Netlify — key lives in server env vars, not the browser
  if (IS_NETLIFY) {
    const apiRow = document.getElementById('apiRow');
    const remRow = document.querySelector('.remember-row');
    if (apiRow) apiRow.style.display = 'none';
    if (remRow) remRow.style.display = 'none';
  }
  window.scrollTo({ top:0, behavior:'smooth' });
}

// ── DIVISION ─────────────────────────────────────────────────────────────────
function selectDiv(card) {
  document.querySelectorAll('.division-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  S.division = card.dataset.division;
  const div = DIVISIONS[S.division];
  document.getElementById('criteriaTags').innerHTML = div.criteria.map(c=>`<span class="ctag">${c}</span>`).join('');
  document.getElementById('criteriaReveal').classList.add('visible');
  document.getElementById('step1Next').disabled = false;
  // Show date section only for competitive divisions
  const showSec = document.getElementById('showSection');
  showSec.style.display = S.division==='aesthetic' ? 'none' : 'block';
  // Strength inputs shown for all divisions
  const strengthSec = document.getElementById('strengthSection');
  if (strengthSec) strengthSec.style.display = 'block';
}

// ── SHOW DATE ─────────────────────────────────────────────────────────────────
function toggleShowDate() {
  const chkEl = document.getElementById('hasShowChk');
  if (!chkEl) return;
  const checked = chkEl.checked;
  document.getElementById('showDateFields')?.classList.toggle('visible', checked);
  if (!checked) { S.showDate=null; S.showName=''; document.getElementById('showCountdownPreview').style.display='none'; }
}

function updateCountdownPreview() {
  const dateVal = document.getElementById('showDateInput')?.value;
  const preview = document.getElementById('showCountdownPreview');
  if (!dateVal || !preview) return;
  const days = Math.max(0, Math.ceil((new Date(dateVal+'T12:00:00') - new Date()) / (1000*60*60*24)));
  document.getElementById('previewDays').textContent = days;
  document.getElementById('previewLabel').textContent = 'Days Until ' + (document.getElementById('showNameInput')?.value.trim() || 'Show');
  preview.style.display = 'block';
}

function readShowDate() {
  const chkEl = document.getElementById('hasShowChk');
  if (!chkEl || !chkEl.checked) { S.showDate=null; S.showName=''; return; }
  const dateVal = document.getElementById('showDateInput')?.value;
  S.showName = document.getElementById('showNameInput')?.value.trim() || 'Your Show';
  S.showDate = dateVal ? new Date(dateVal+'T12:00:00') : null;
}

function daysUntilShow() {
  if (!S.showDate) return null;
  const diff = S.showDate - new Date();
  return Math.max(0, Math.ceil(diff / (1000*60*60*24)));
}

// ── IMAGE LOAD ────────────────────────────────────────────────────────────────
function loadImage(event, previewId, zoneId, key) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const img = document.getElementById(previewId);
    img.src = e.target.result;
    img.style.display = 'block';
    document.getElementById(zoneId).classList.add('loaded');
    // Resize to ≤1568px on long edge before storing (faster + cheaper)
    resizeImage(e.target.result, 900).then(resized => { S.images[key] = resized; });
  };
  reader.readAsDataURL(file);
}

function resizeImage(dataUrl, maxPx) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const scale = Math.min(1, maxPx / Math.max(img.width, img.height));
      const canvas = document.createElement('canvas');
      canvas.width  = Math.round(img.width  * scale);
      canvas.height = Math.round(img.height * scale);
      canvas.getContext('2d').drawImage(img, 0, 0, canvas.width, canvas.height);
      resolve(canvas.toDataURL('image/jpeg', 0.80));
    };
    img.src = dataUrl;
  });
}

// ── API KEY ───────────────────────────────────────────────────────────────────
function toggleKey() {
  const inp = document.getElementById('apiKeyInput');
  const btn = document.querySelector('.toggle-key');
  inp.type = inp.type==='password' ? 'text' : 'password';
  btn.textContent = inp.type==='password' ? 'Show' : 'Hide';
}
function getApiKey() {
  const typed = document.getElementById('apiKeyInput').value.trim();
  return typed || API_KEY_HARDCODED;
}

// ── API CALL ──────────────────────────────────────────────────────────────────
async function callClaude({ system, messages, max_tokens=1500 }) {
  if (IS_NETLIFY) {
    // Production: serverless proxy, key lives in Netlify env vars
    const r = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ system, messages, max_tokens, model: 'claude-haiku-4-5-20251001' })
    });
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(e.error || e.error?.message || `Server error ${r.status}. Make sure ANTHROPIC_API_KEY is set in Netlify dashboard.`);
    }
    return r.json();
  } else {
    // Prototype: direct browser call (requires local server)
    const r = await fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'x-api-key': getApiKey(),
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
        'anthropic-dangerous-direct-browser-calls': 'true'
      },
      body: JSON.stringify({ model: 'claude-opus-4-6', max_tokens, system, messages })
    });
    if (!r.ok) { const e=await r.json().catch(()=>({})); throw new Error(e.error?.message||`API error ${r.status}`); }
    return r.json();
  }
}

// ── ANALYSIS ──────────────────────────────────────────────────────────────────
async function startAnalysis() {
  const errEl  = document.getElementById('step2Error');
  const loadEl = document.getElementById('loadingScreen');
  let iv = null;

  const showErr = (msg) => {
    if (errEl) { errEl.textContent = msg; errEl.classList.add('visible'); }
    else alert('Achilles error: ' + msg);
  };

  try {
    if (errEl) errEl.classList.remove('visible');

    const hasImage = S.images.front || S.images.side || S.images.back;
    if (!hasImage) { showErr('Please upload at least one photo.'); return; }

    const apiKey = getApiKey();
    if (!IS_NETLIFY && !apiKey) { showErr('Please enter your Anthropic API key.'); return; }

    readShowDate();

    if (document.getElementById('rememberKey')?.checked && S.user) {
      await saveUserData({ ...S.user.data, savedApiKey: apiKey });
    }

    ['step1','step2','step3'].forEach(id => document.getElementById(id).style.display='none');
    if (loadEl) loadEl.classList.add('active');

    const msgs = ['Analyzing Physique','Evaluating Proportions','Mapping Muscle Groups','Compiling Report'];
    let mi = 0;
    const lt = document.getElementById('loadingText');
    iv = setInterval(() => { mi=(mi+1)%msgs.length; if (lt) lt.textContent=msgs[mi]; }, 2200);

    const div = DIVISIONS[S.division];
    if (!div) throw new Error('No division selected. Please go back and pick a division.');
    const days = daysUntilShow();

    const imageBlocks = [];
    for (const [angle, data] of Object.entries(S.images)) {
      if (!data) continue;
      const mediaType = data.split(';')[0].split(':')[1];
      const b64 = data.split(',')[1];
      imageBlocks.push({ type:'image', source:{ type:'base64', media_type:mediaType, data:b64 } });
      imageBlocks.push({ type:'text', text:`(Above: ${angle} view)` });
    }

    const muscleGroupsJson = JSON.stringify(div.muscleGroups.reduce((a,m)=>{ a[m]={'score':0,'notes':''}; return a; }, {}));

    const showContext = days !== null
      ? `\n\nSHOW DATE CONTEXT: This athlete has a show named "${S.showName}" in ${days} days (${Math.round(days/7)} weeks out).

For show_advice: Write 3-4 sentences of targeted, honest advice specific to exactly ${days} days out — what to prioritize RIGHT NOW, what not to change, and one key warning for this stage.

For show_timeline: Generate a periodized prep timeline as a JSON array covering all phases from now through show day. Each phase: {"phase":"<name>","timeframe":"<e.g. 12-16 weeks out>","focus":"<2-3 specific, actionable sentences>"}. Phases should be appropriate for someone ${days} days out — skip phases already passed. Always include a Peak Week phase and a Show Day phase. Be specific to ${div.label} standards.`
      : '';

    // Pose / condition context (all divisions)
    const poseMap = {
      relaxed:     'Relaxed — not flexing. The athlete is unpumped and not actively flexing. Muscle separation and size will appear less than at peak. Score with this in mind — do not penalize for lack of visible separation in a relaxed state.',
      casual:      'Casual flex — somewhat flexed. The athlete is lightly flexed but not posing. A realistic everyday "flex" look.',
      flexed:      'Fully flexed and posing. The athlete is actively posing with full muscle contraction.',
      competition: 'Competition ready — peak conditioning. The athlete is peaking: dieted down, pumped, and posing under competition conditions. Hold this to the highest standard for their division.'
    };
    const poseVal = document.getElementById('poseCondition')?.value || 'relaxed';
    const poseContext = `\n\nPHOTO CONDITION: ${poseMap[poseVal] || poseMap.relaxed}`;

    // Strength context (aesthetic division only)
    // Strength context (all divisions — affects score only for aesthetic)
    let strengthContext = '';
    const bw       = parseFloat(document.getElementById('sBodyweight')?.value) || 0;
    const bench    = parseFloat(document.getElementById('sBench')?.value)       || 0;
    const squat    = parseFloat(document.getElementById('sSquat')?.value)       || 0;
    const deadlift = parseFloat(document.getElementById('sDeadlift')?.value)    || 0;
    if (bench || squat || deadlift) {
      const ratio = (lift) => bw ? ` (${(lift/bw).toFixed(2)}x BW)` : '';
      const isAesthetic = S.division === 'aesthetic';
      strengthContext = `\n\nSTRENGTH DATA PROVIDED:
- Bodyweight: ${bw || 'not provided'} lbs
- Max Bench: ${bench} lbs${ratio(bench)}
- Max Squat: ${squat} lbs${ratio(squat)}
- Max Deadlift: ${deadlift} lbs${ratio(deadlift)}

Strength standards for men (relative to bodyweight):
Bench    — Beginner <0.75x | Intermediate 1.0x | Advanced 1.25x | Elite 1.5x+
Squat    — Beginner <1.0x  | Intermediate 1.5x | Advanced 2.0x  | Elite 2.5x+
Deadlift — Beginner <1.25x | Intermediate 1.75x | Advanced 2.25x | Elite 2.75x+

${isAesthetic
  ? 'Factor this strength data into the overall score, assessment, and training priorities. If no photos were provided, base the score primarily on the strength numbers.'
  : 'Use this strength data ONLY to inform training recommendations, priorities, and genetic limiter identification — do NOT let it affect the physique score, which must be based solely on the visual assessment of the photos. Mention the lifts in the assessment and call out any strength imbalances or limiters.'
}`;
    }

    const systemPrompt = `${div.prompt}
${showContext}${poseContext}${strengthContext}

You must provide science-based, healthy, safe advice only. Never suggest extreme cutting, dehydration, or unsafe supplementation. All feedback must be constructive, never body-shaming.

Respond ONLY with this exact JSON — nothing before or after:
{
  "score": <number 1-10 one decimal>,
  "division": "<division label>",
  "strengths": ["<str1>","<str2>","<str3>"],
  "weaknesses": ["<weak1>","<weak2>","<weak3>"],
  "priorities": [
    {"rank":1,"area":"<muscle/attribute>","reason":"<specific actionable why>"},
    {"rank":2,"area":"<muscle/attribute>","reason":"<specific actionable why>"},
    {"rank":3,"area":"<muscle/attribute>","reason":"<specific actionable why>"}
  ],
  "overall_assessment": "<3-4 sentence honest, constructive assessment>",
  "potential": "<2 sentences on realistic ceiling and what it takes to get there>",
  "muscle_scores": ${muscleGroupsJson.replace(/"score":0/g,'"score":<1-10>').replace(/"notes":""/g,'"notes":"<specific observation>"')},
  "photo_annotations": [
    {"view":"front|side|back","area":"<muscle group>","note":"<brief observation>","sentiment":"positive|neutral|negative","x_pct":<0-100>,"y_pct":<0-100>}
  ],
  "show_advice": ${days!==null ? '"<targeted advice for ' + days + ' days out — what to focus on, what not to change, key warning>"' : 'null'},
  "show_timeline": ${days!==null ? '[{"phase":"<name>","timeframe":"<X-Y weeks out>","focus":"<2-3 specific sentences>"}]' : 'null'}
}`;

    const body = await callClaude({
      system: systemPrompt,
      messages: [{ role:'user', content:[
        ...imageBlocks,
        { type:'text', text:`Analyze under ${div.label} standards and return the JSON report.` }
      ]}],
      max_tokens: 1400
    });

    clearInterval(iv);
    iv = null;

    const raw = (body.content && body.content[0] && body.content[0].text || '').trim();
    if (!raw) throw new Error('Empty response from AI. Full body: ' + JSON.stringify(body).slice(0, 200));
    let report;
    try {
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON found. Response started with: ' + raw.slice(0, 150));
      report = JSON.parse(jsonMatch[0]);
    } catch(parseErr) { throw new Error('Parse failed: ' + parseErr.message + ' | Response: ' + raw.slice(0, 200)); }

    report._division = S.division;
    report._showDate = S.showDate ? S.showDate.toISOString() : null;
    report._showName = S.showName || null;

    await saveAnalysis(report);
    S.lastReport = report;

    S.chatHistory = [
      { role:'user', content:`I received my ${div.label} physique analysis: ${JSON.stringify({ score:report.score, strengths:report.strengths, weaknesses:report.weaknesses, priorities:report.priorities })}. I may ask follow-up questions.` },
      { role:'assistant', content:`I've reviewed your ${div.label} analysis — ${report.score}/10. Your top priorities are ${report.priorities.slice(0,2).map(p=>p.area).join(' and ')}. Ask me anything specific.` }
    ];

    renderReport(report);
    if (loadEl) loadEl.classList.remove('active');
    showStep(3);

  } catch(e) {
    if (iv) { clearInterval(iv); iv = null; }
    if (loadEl) loadEl.classList.remove('active');
    showStep(2);
    showErr('Error: ' + e.message);
  }
}

// ── RENDER REPORT ─────────────────────────────────────────────────────────────
function renderReport(report) {
  const div   = DIVISIONS[report._division || S.division];
  const score = parseFloat(report.score) || 0;
  const days  = report._showDate ? Math.max(0, Math.ceil((new Date(report._showDate)-new Date())/(1000*60*60*24))) : null;

  let html = '';

  // Countdown card (if show mode)
  if (days !== null) {
    html += `
    <div class="rcard countdown-card full gold-border" style="text-align:center">
      <div class="rcard-label">Show Countdown</div>
      <div class="countdown-number">${days}</div>
      <div class="countdown-label">Days Until ${report._showName || 'Show'}</div>
      ${report.show_advice ? `<p style="font-family:'Crimson Pro',serif;font-style:italic;color:var(--text-dim);font-size:0.95rem;margin-top:16px;line-height:1.7;text-align:left">${report.show_advice}</p>` : ''}
    </div>`;

    // Prep timeline
    const timeline = Array.isArray(report.show_timeline) ? report.show_timeline : null;
    if (timeline && timeline.length) {
      html += `<div class="rcard full gold-border">
        <div class="rcard-label">Prep Timeline</div>
        <div class="timeline-list">
          ${timeline.map((phase, i) => `
            <div class="timeline-phase ${i===0?'timeline-phase-current':''}">
              <div class="timeline-phase-header">
                <span class="timeline-phase-name">${phase.phase}</span>
                <span class="timeline-phase-time">${phase.timeframe}</span>
              </div>
              <p class="timeline-phase-focus">${phase.focus}</p>
            </div>
          `).join('')}
        </div>
      </div>`;
    }
  }

  // Score card
  html += `
  <div class="rcard gold-border">
    <div class="rcard-label">Achilles Score</div>
    <div class="div-badge">${div.label}</div>
    <div class="score-number">${report.score}</div>
    <div class="score-denom">Out of 10</div>
    <div class="score-bar-track"><div class="score-bar-fill" id="sBar"></div></div>
    <div class="score-tier">${scoreTier(score)}</div>
  </div>`;

  // Strengths + Weaknesses
  html += `
  <div class="rcard">
    <div class="rcard-label">Strengths</div>
    <ul>${report.strengths.map(s=>`<li>${s}</li>`).join('')}</ul>
  </div>
  <div class="rcard">
    <div class="rcard-label">Weak Points</div>
    <ul>${report.weaknesses.map(w=>`<li>${w}</li>`).join('')}</ul>
  </div>`;

  // Priorities
  html += `
  <div class="rcard">
    <div class="rcard-label">Training Priorities</div>
    <ol>${report.priorities.map(p=>`<li><strong>${p.area}</strong> — ${p.reason}</li>`).join('')}</ol>
  </div>`;

  // Muscle scores
  if (report.muscle_scores && Object.keys(report.muscle_scores).length) {
    const bars = Object.entries(report.muscle_scores).map(([muscle, data]) => {
      const s = typeof data==='object' ? data.score : data;
      const n = typeof data==='object' ? data.notes : '';
      return `<div class="muscle-bar-row" title="${n}">
        <div class="muscle-bar-label">${muscle}</div>
        <div class="muscle-bar-track"><div class="muscle-bar-fill" data-score="${s}" style="width:0"></div></div>
        <div class="muscle-bar-score">${s}</div>
      </div>`;
    }).join('');
    html += `<div class="rcard full"><div class="rcard-label">Muscle Group Breakdown</div>${bars}</div>`;
  }

  // Assessment
  html += `
  <div class="rcard full">
    <div class="rcard-label">Assessment</div>
    <p>${report.overall_assessment}</p>
    <p>${report.potential}</p>
  </div>`;

  document.getElementById('reportGrid').innerHTML = html;

  // Animate score bar
  setTimeout(() => {
    const bar = document.getElementById('sBar');
    if (bar) bar.style.width = (score/10*100)+'%';
    document.querySelectorAll('.muscle-bar-fill').forEach(b => {
      const s = parseFloat(b.dataset.score)||0;
      b.style.width = (s/10*100)+'%';
    });
  }, 150);

  // Photo annotations
  renderAnnotations(report);

  // Reset chat
  document.getElementById('chatMessages').innerHTML = `
    <div class="msg assistant">
      <div class="msg-av">A</div>
      <div class="msg-bub">Your report is ready. Ask me anything about your physique, training priorities, or how to improve your score.</div>
    </div>
    <div class="typing-row" id="typingRow">
      <div class="msg-av">A</div>
      <div class="typing-dots"><span></span><span></span><span></span></div>
    </div>`;
}

// ── PHOTO ANNOTATIONS ─────────────────────────────────────────────────────────
function renderAnnotations(report) {
  const container = document.getElementById('photoAnnotations');
  if (!container) return;

  const views = ['front','side','back'].filter(v => S.images[v]);
  if (!views.length) { container.style.display='none'; return; }

  const annotations = report.photo_annotations || [];
  container.style.display = '';

  container.innerHTML = `<div class="rcard-label" style="margin-bottom:12px">Photo Analysis</div>
    <div class="photo-analysis-grid">
      ${views.map(view => `
        <div class="photo-frame">
          <div class="photo-frame-label">${view.charAt(0).toUpperCase()+view.slice(1)}</div>
          <div class="photo-canvas-wrap" id="wrap_${view}">
            <img src="${S.images[view]}" id="pimg_${view}" alt="${view} view">
            <canvas id="canvas_${view}"></canvas>
          </div>
        </div>`).join('')}
    </div>`;

  // Draw annotations after images load
  views.forEach(view => {
    const img = document.getElementById('pimg_'+view);
    const viewAnnotations = annotations.filter(a => a.view===view);
    const draw = () => drawAnnotations(view, img, viewAnnotations);
    if (img.complete) draw(); else img.onload = draw;
  });
}

function drawAnnotations(view, img, annotations) {
  const wrap   = document.getElementById('wrap_'+view);
  const canvas = document.getElementById('canvas_'+view);
  if (!canvas || !wrap) return;

  canvas.width  = img.offsetWidth  || img.naturalWidth;
  canvas.height = img.offsetHeight || img.naturalHeight;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0,0,canvas.width,canvas.height);

  annotations.forEach(a => {
    const x = (a.x_pct/100) * canvas.width;
    const y = (a.y_pct/100) * canvas.height;
    const color = a.sentiment==='positive' ? 'rgba(74,222,128,0.9)'
                : a.sentiment==='negative' ? 'rgba(248,113,113,0.9)'
                : 'rgba(200,168,75,0.9)';

    // Dot
    ctx.beginPath();
    ctx.arc(x, y, 6, 0, Math.PI*2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = 'rgba(0,0,0,0.6)';
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Label
    const label = a.area + (a.note ? ': '+a.note : '');
    const maxW = 180;
    const fontSize = 11;
    ctx.font = `${fontSize}px 'Cinzel', serif`;
    ctx.textBaseline = 'middle';

    const textW = Math.min(ctx.measureText(label).width, maxW);
    const padX=6, padY=4, boxH=fontSize+padY*2;
    let lx = x+10;
    if (lx+textW+padX*2 > canvas.width) lx = x-textW-padX*2-10;
    const ly = y-boxH/2;

    ctx.fillStyle = 'rgba(0,0,0,0.72)';
    roundRect(ctx, lx, ly, textW+padX*2, boxH, 3);
    ctx.fill();

    ctx.fillStyle = color;
    ctx.fillText(label, lx+padX, ly+boxH/2, maxW);
  });
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x+r, y);
  ctx.lineTo(x+w-r, y);
  ctx.quadraticCurveTo(x+w, y, x+w, y+r);
  ctx.lineTo(x+w, y+h-r);
  ctx.quadraticCurveTo(x+w, y+h, x+w-r, y+h);
  ctx.lineTo(x+r, y+h);
  ctx.quadraticCurveTo(x, y+h, x, y+h-r);
  ctx.lineTo(x, y+r);
  ctx.quadraticCurveTo(x, y, x+r, y);
  ctx.closePath();
}

// ── SCORE TIER ────────────────────────────────────────────────────────────────
function scoreTier(s) {
  if (s>=9)   return 'Elite — Pro Level';
  if (s>=8)   return 'National Competitive Level';
  if (s>=7)   return 'Competitive Amateur Level';
  if (s>=6)   return 'Developing — Strong Foundation';
  if (s>=5)   return 'Early Stage — Good Potential';
  return 'Starting Point — Room to Grow';
}

// ── CHAT ──────────────────────────────────────────────────────────────────────
function handleChatKey(e) {
  if (e.key==='Enter'&&!e.shiftKey) { e.preventDefault(); sendChat(); }
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const text  = input.value.trim();
  if (!text) return;
  appendMsg('user', text);
  input.value='';
  S.chatHistory.push({ role:'user', content:text });
  const typing = document.getElementById('typingRow');
  typing.classList.add('visible');
  scrollChat();
  document.getElementById('chatSend').disabled=true;
  try {
    const div = DIVISIONS[S.division];
    const body = await callClaude({
      system: `You are Achilles — a direct, knowledgeable bodybuilding coach who evaluated this athlete under ${div.label} standards. Give blunt, specific, actionable answers grounded in exercise science. Never suggest unsafe practices, extreme cutting, or unhealthy supplementation. Keep under 150 words unless a full program is requested.`,
      messages: S.chatHistory,
      max_tokens: 600
    });
    typing.classList.remove('visible');
    const reply = body.content[0].text;
    S.chatHistory.push({ role:'assistant', content:reply });
    appendMsg('assistant', reply);
  } catch(e) {
    typing.classList.remove('visible');
    appendMsg('assistant', 'Error: '+e.message);
  }
  document.getElementById('chatSend').disabled=false;
}

function appendMsg(role, text) {
  const container = document.getElementById('chatMessages');
  const typing    = document.getElementById('typingRow');
  const d = document.createElement('div');
  d.className = `msg ${role}`;
  d.innerHTML = `<div class="msg-av">${role==='assistant'?'A':'U'}</div><div class="msg-bub">${text.replace(/\n/g,'<br>')}</div>`;
  container.insertBefore(d, typing);
  scrollChat();
}
function scrollChat() { const c=document.getElementById('chatMessages'); c.scrollTop=c.scrollHeight; }

// ── HISTORY & STORAGE ─────────────────────────────────────────────────────────
async function saveAnalysis(report) {
  if (!S.user) return;
  const entry = {
    id: Date.now(),
    date: new Date().toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}),
    timestamp: Date.now(),
    division: S.division,
    divisionLabel: DIVISIONS[S.division].label,
    ...report
  };
  S.user.data.analyses = [entry, ...(S.user.data.analyses||[])].slice(0,50);
  await saveUserData(S.user.data);
}

async function saveUserData(newData) {
  if (!S.user) return;
  S.user.data = newData;
  const accounts = getAccounts();
  const key = S.user.username.toLowerCase();
  if (!accounts[key]) return;
  accounts[key].encryptedData = await encrypt(newData, S.user.cryptoKey);
  saveAccounts(accounts);
}

function openHistory() {
  const analyses = S.user?.data?.analyses || [];
  const list = document.getElementById('historyList');

  if (!analyses.length) {
    list.innerHTML = '<div class="history-empty">No analyses yet.<br>Complete your first report to begin tracking.</div>';
  } else {
    // Progress chart
    const chartData = [...analyses].reverse().slice(-10);
    const labels = chartData.map(a => a.date.replace(/,.*$/,''));
    const scores = chartData.map(a => parseFloat(a.score)||0);

    list.innerHTML = `
      <div class="drawer-chart-wrap">
        <canvas id="progressChart"></canvas>
      </div>` +
      analyses.map((a,i) => `
      <div class="hentry" onclick="toggleEntry(${i})">
        <div class="hentry-top">
          <div class="hentry-score">${a.score}</div>
          <div class="hentry-meta">
            <div class="hentry-div">${a.divisionLabel}</div>
            <div class="hentry-date">${a.date}</div>
          </div>
        </div>
        <div class="hentry-weakpoints">${(a.weaknesses||[]).slice(0,2).join(' · ')}</div>
        <div class="hentry-detail" id="hd${i}">
          <p>${a.overall_assessment||''}</p>
          ${a._showName ? `<p style="margin-top:8px;color:var(--gold);font-style:normal">Show: ${a._showName}</p>` : ''}
        </div>
      </div>`).join('');

    // Draw chart after DOM updates
    requestAnimationFrame(() => {
      const ctx = document.getElementById('progressChart');
      if (!ctx || !window.Chart) return;
      new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [{
            label: 'Score',
            data: scores,
            borderColor: '#c8a84b',
            backgroundColor: 'rgba(200,168,75,0.08)',
            borderWidth: 2,
            pointBackgroundColor: '#c8a84b',
            pointRadius: 4,
            tension: 0.3,
            fill: true
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              min: 0, max: 10,
              ticks: { color:'#888', font:{ family:'Cinzel, serif', size:10 } },
              grid: { color:'rgba(255,255,255,0.05)' }
            },
            x: {
              ticks: { color:'#888', font:{ family:'Cinzel, serif', size:10 }, maxRotation:45 },
              grid: { color:'rgba(255,255,255,0.05)' }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#0e0e0e',
              borderColor: 'rgba(200,168,75,0.3)',
              borderWidth: 1,
              titleColor: '#c8a84b',
              bodyColor: '#ede8dc',
              titleFont: { family:'Cinzel, serif', size:11 },
              bodyFont: { family:"'Crimson Pro', serif", size:13 }
            }
          }
        }
      });
    });
  }

  document.getElementById('drawerOverlay').classList.add('open');
}

function toggleEntry(i) { document.getElementById('hd'+i)?.classList.toggle('open'); }
function closeHistory() { document.getElementById('drawerOverlay').classList.remove('open'); }
function closeHistoryOutside(e) { if (e.target===document.getElementById('drawerOverlay')) closeHistory(); }

// ── RESET ─────────────────────────────────────────────────────────────────────
function startOver() {
  S.division=null; S.images={front:null,side:null,back:null}; S.chatHistory=[]; S.lastReport=null; S.showDate=null; S.showName='';
  document.querySelectorAll('.division-card').forEach(c=>c.classList.remove('selected'));
  document.getElementById('criteriaReveal').classList.remove('visible');
  document.getElementById('step1Next').disabled=true;
  document.getElementById('hasShowChk').checked=false;
  document.getElementById('showDateFields').classList.remove('visible');
  ['pFront','pSide','pBack'].forEach(id=>{ const i=document.getElementById(id); if(i){i.src='';i.style.display='none';} });
  ['zFront','zSide','zBack'].forEach(id=>document.getElementById(id)?.classList.remove('loaded'));
  document.getElementById('step2Error').classList.remove('visible');
  // Reset pose dropdown
  const poseEl = document.getElementById('poseCondition');
  if (poseEl) poseEl.value = 'relaxed';
  // Clear strength fields
  ['sBodyweight','sBench','sSquat','sDeadlift'].forEach(id=>{ const el=document.getElementById(id); if(el) el.value=''; });
  // Reset show section
  const showSec = document.getElementById('showSection');
  if (showSec) showSec.style.display = 'none';
  const showPrev = document.getElementById('showCountdownPreview');
  if (showPrev) showPrev.style.display = 'none';
  const showNameEl = document.getElementById('showNameInput');
  if (showNameEl) showNameEl.value = '';
  const showDateEl = document.getElementById('showDateInput');
  if (showDateEl) showDateEl.value = '';
  showStep(1);
}

// ── RENDER DIVISIONS FROM DATA ────────────────────────────────────────────────
function buildDivisionGrid() {
  const grid = document.getElementById('divisionGrid');
  if (!grid) return;
  grid.innerHTML = Object.entries(DIVISIONS).map(([key, div]) => `
    <div class="division-card" data-division="${key}" onclick="selectDiv(this)">
      <div class="division-icon">${div.icon}</div>
      <div class="division-name">${div.label}</div>
      <div class="division-desc">${div.desc}</div>
    </div>`).join('');
}

document.addEventListener('DOMContentLoaded', buildDivisionGrid);

// ── SECTION NAV ───────────────────────────────────────────────────────────────
function showSection(name) {
  ['home','scan','nutrition','profile'].forEach(s => {
    const el = document.getElementById('section'+s.charAt(0).toUpperCase()+s.slice(1));
    if (el) el.classList.toggle('active', s===name);
    const btn = document.getElementById('bnav'+s.charAt(0).toUpperCase()+s.slice(1));
    if (btn) btn.classList.toggle('active', s===name);
  });
  if (name==='home')      renderHome();
  if (name==='profile')   renderProfile();
  if (name==='nutrition') { renderNutriToday(); renderMealsList(); }
  window.scrollTo({ top:0, behavior:'smooth' });
}

// ── HOME ──────────────────────────────────────────────────────────────────────
function renderHome() {
  if (!S.user) return;
  const analyses = S.user.data.analyses || [];
  const scores   = analyses.map(a => parseFloat(a.score)||0);

  document.getElementById('homeGreeting').textContent = S.user.username.toUpperCase();
  document.getElementById('hStatScore').textContent   = scores.length ? Math.max(...scores).toFixed(1) : '—';
  document.getElementById('hStatScans').textContent   = analyses.length;

  const todayLog = getTodayLog();
  const goals    = S.user.data.nutrition?.goals || {};
  const totals   = getMealTotals(todayLog.entries || []);
  document.getElementById('hStatCalories').textContent = totals.calories || '0';
  document.getElementById('hStatWater').textContent    = todayLog.water || '0';

  // Home avatar
  const avatar = S.user.data.profile?.avatar;
  const hav = document.getElementById('homeAvatar');
  if (avatar) {
    hav.style.backgroundImage = `url(${avatar})`;
    hav.style.backgroundSize = 'cover';
    hav.textContent = '';
  } else {
    hav.textContent = S.user.username.charAt(0).toUpperCase();
  }

  // Macro preview
  const macroBars = document.getElementById('homeMacroBars');
  if (goals.calories) {
    macroBars.innerHTML = buildMacroMiniBar('Calories', totals.calories, goals.calories, 'var(--gold)') +
      buildMacroMiniBar('Protein',  totals.protein,  goals.protein,  'rgba(74,222,128,0.8)') +
      buildMacroMiniBar('Carbs',    totals.carbs,    goals.carbs,    'rgba(251,191,36,0.8)') +
      buildMacroMiniBar('Fat',      totals.fat,      goals.fat,      'rgba(248,113,113,0.7)');
  } else {
    macroBars.innerHTML = '<p style="font-family:\'Crimson Pro\',serif;font-style:italic;color:var(--text-mute);font-size:0.9rem">No goals set — visit Nutrition → Calculator.</p>';
  }

  // Latest scan
  const latestEl = document.getElementById('homeLatestScan');
  if (analyses.length) {
    const a = analyses[0];
    latestEl.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <span class="score-number" style="font-size:2.5rem">${a.score}</span>
      <div style="text-align:right">
        <div class="div-badge" style="margin:0 0 4px 0">${a.divisionLabel}</div>
        <div style="font-family:'Crimson Pro',serif;font-size:0.85rem;color:var(--text-mute);font-style:italic">${a.date}</div>
      </div>
    </div>
    <p style="font-family:'Crimson Pro',serif;font-size:0.9rem;color:var(--text-dim);font-style:italic;line-height:1.6">${(a.overall_assessment||'').slice(0,160)}…</p>`;
  } else {
    latestEl.innerHTML = '<p style="font-family:\'Crimson Pro\',serif;font-style:italic;color:var(--text-mute);font-size:0.9rem">No scans yet.</p>';
  }

  renderGallery();
}

// ── GALLERY ───────────────────────────────────────────────────────────────────
function renderGallery() {
  if (!S.user) return;
  const grid = document.getElementById('galleryGrid');
  if (!grid) return;

  // Combine scan photos (from analyses) + personal uploads
  const scanPhotos = (S.user.data.analyses || [])
    .filter(a => a.photoData)
    .map(a => ({ src: a.photoData, date: a.date, type: 'scan', label: a.divisionLabel || 'Scan' }));

  const uploads = (S.user.data.gallery || [])
    .map((g, i) => ({ ...g, type: 'upload', idx: i }));

  const all = [...uploads, ...scanPhotos]; // uploads first

  if (!all.length) {
    grid.innerHTML = '<p class="gallery-empty">No photos yet. Upload one or run a scan.</p>';
    return;
  }

  grid.innerHTML = all.map((item, i) => `
    <div class="gallery-item">
      <img src="${item.src}" class="gallery-img" alt="${item.label || 'Photo'}" loading="lazy">
      <div class="gallery-overlay">
        <button class="gallery-action-btn" onclick="sharePhoto('${item.src}')" title="Share">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        </button>
        ${item.type === 'upload' ? `<button class="gallery-action-btn gallery-delete-btn" onclick="deleteGalleryPhoto(${item.idx})" title="Delete">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
        </button>` : ''}
      </div>
      <div class="gallery-badge ${item.type === 'scan' ? 'gallery-badge-scan' : 'gallery-badge-upload'}">${item.type === 'scan' ? item.label : item.caption || 'Photo'}</div>
    </div>
  `).join('');
}

async function uploadGalleryPhotos(event) {
  const files = Array.from(event.target.files);
  if (!files.length) return;
  const gallery = S.user.data.gallery || [];

  for (const file of files) {
    const base64 = await resizeFileToBase64(file, 1200);
    gallery.unshift({ src: base64, date: new Date().toISOString().slice(0,10), caption: file.name.replace(/\.[^.]+$/, '') });
  }

  await saveUserData({ ...S.user.data, gallery });
  event.target.value = '';
  renderGallery();
}

async function deleteGalleryPhoto(idx) {
  if (!confirm('Remove this photo?')) return;
  const gallery = S.user.data.gallery || [];
  gallery.splice(idx, 1);
  await saveUserData({ ...S.user.data, gallery });
  renderGallery();
}

async function sharePhoto(src) {
  try {
    const res = await fetch(src);
    const blob = await res.blob();
    const file = new File([blob], 'achilles-physique.jpg', { type: blob.type || 'image/jpeg' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: 'Achilles Physique' });
      return;
    }
  } catch(e) {}
  // Fallback: open in new tab / download
  try {
    if (navigator.share) {
      await navigator.share({ title: 'Achilles Physique', text: 'Check out my physique progress!' });
      return;
    }
  } catch(e) {}
  // Last resort: download
  const a = document.createElement('a');
  a.href = src;
  a.download = 'achilles-physique.jpg';
  a.click();
}

// Resize a File object to base64 (for gallery uploads)
function resizeFileToBase64(file, maxPx) {
  return new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = e => {
      const img = new Image();
      img.onload = () => {
        let w = img.width, h = img.height;
        if (w > maxPx || h > maxPx) {
          if (w > h) { h = Math.round(h * maxPx / w); w = maxPx; }
          else { w = Math.round(w * maxPx / h); h = maxPx; }
        }
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        canvas.getContext('2d').drawImage(img, 0, 0, w, h);
        resolve(canvas.toDataURL('image/jpeg', 0.82));
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  });
}

function buildMacroMiniBar(label, val, goal, color) {
  const pct = goal ? Math.min(100, Math.round((val/goal)*100)) : 0;
  return `<div style="margin-bottom:10px">
    <div style="display:flex;justify-content:space-between;font-family:'Cinzel',serif;font-size:0.6rem;letter-spacing:1px;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px">
      <span>${label}</span><span>${val} / ${goal}</span>
    </div>
    <div style="height:4px;background:var(--border);border-radius:99px;overflow:hidden">
      <div style="height:100%;width:${pct}%;background:${color};border-radius:99px;transition:width 0.8s ease"></div>
    </div>
  </div>`;
}

// ── PROFILE ───────────────────────────────────────────────────────────────────
function renderProfile() {
  if (!S.user) return;
  const analyses = S.user.data.analyses || [];
  const scores   = analyses.map(a => parseFloat(a.score)||0);
  const avatar   = S.user.data.profile?.avatar;

  document.getElementById('profileDisplayName').textContent = S.user.username;

  const pav = document.getElementById('profileAvatar');
  if (avatar) {
    pav.style.backgroundImage = `url(${avatar})`;
    pav.style.backgroundSize  = 'cover';
    pav.style.backgroundPosition = 'center';
    pav.textContent = '';
  } else {
    pav.textContent = S.user.username.charAt(0).toUpperCase();
  }

  document.getElementById('profileBestScore').textContent  = scores.length ? Math.max(...scores).toFixed(1) : '—';
  document.getElementById('profileTotalScans').textContent = analyses.length;
  const divCounts = {};
  analyses.forEach(a => { divCounts[a.divisionLabel] = (divCounts[a.divisionLabel]||0)+1; });
  const topDiv = Object.entries(divCounts).sort((a,b)=>b[1]-a[1])[0];
  document.getElementById('profileTopDiv').textContent = topDiv ? topDiv[0].split(' ')[0] : '—';

  const histEl = document.getElementById('profileHistoryList');
  if (!analyses.length) {
    histEl.innerHTML = '<p style="font-family:\'Crimson Pro\',serif;font-style:italic;color:var(--text-mute);font-size:0.9rem;padding:8px 0">No scans yet.</p>';
  } else {
    histEl.innerHTML = analyses.slice(0,5).map(a => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">
        <div>
          <div style="font-family:'Cinzel',serif;font-size:0.7rem;letter-spacing:1px;color:var(--text)">${a.divisionLabel}</div>
          <div style="font-family:'Crimson Pro',serif;font-size:0.82rem;color:var(--text-mute);font-style:italic">${a.date}</div>
        </div>
        <div style="font-family:'Cinzel Decorative',serif;font-size:1.6rem;color:var(--text)">${a.score}</div>
      </div>`).join('');
  }
}

async function uploadAvatar(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async e => {
    const resized = await resizeImage(e.target.result, 300);
    S.user.data.profile = S.user.data.profile || {};
    S.user.data.profile.avatar = resized;
    await saveUserData(S.user.data);
    renderProfile();
    renderHome();
  };
  reader.readAsDataURL(file);
}

// ── NUTRITION HELPERS ─────────────────────────────────────────────────────────
function todayKey() {
  return new Date().toISOString().slice(0,10);
}

function getTodayLog() {
  const logs = S.user?.data?.nutrition?.logs || {};
  if (!logs[todayKey()]) logs[todayKey()] = { entries: [], water: 0 };
  return logs[todayKey()];
}

function getMealTotals(entries) {
  return entries.reduce((t, e) => ({
    calories: t.calories + (parseInt(e.calories)||0),
    protein:  t.protein  + (parseInt(e.protein)||0),
    carbs:    t.carbs    + (parseInt(e.carbs)||0),
    fat:      t.fat      + (parseInt(e.fat)||0)
  }), { calories:0, protein:0, carbs:0, fat:0 });
}

// ── NUTRITION TODAY ───────────────────────────────────────────────────────────
function renderNutriToday() {
  if (!S.user) return;
  const goals   = S.user.data.nutrition?.goals || {};
  const log     = getTodayLog();
  const totals  = getMealTotals(log.entries || []);
  const water   = log.water || 0;
  const wGoal   = goals.water || 128;

  document.getElementById('todayCalConsumed').textContent = totals.calories;
  document.getElementById('todayCalGoal').textContent     = goals.calories || '—';
  document.getElementById('calProgressBar').style.width   = goals.calories ? Math.min(100,(totals.calories/goals.calories)*100)+'%' : '0';

  const setMacro = (id, val, goal, barId, fillColor) => {
    document.getElementById(id+'Val').textContent  = val;
    document.getElementById(id+'Goal').textContent = goal || '—';
    document.getElementById(barId).style.width     = goal ? Math.min(100,(val/goal)*100)+'%' : '0';
  };
  setMacro('macroProtein', totals.protein, goals.protein, 'macroProteinBar');
  setMacro('macroCarbs',   totals.carbs,   goals.carbs,   'macroCarbsBar');
  setMacro('macroFat',     totals.fat,     goals.fat,     'macroFatBar');

  document.getElementById('waterOzDisplay').textContent  = water;
  document.getElementById('waterGoalDisplay').textContent = wGoal;
  document.getElementById('waterProgressBar').style.width = Math.min(100,(water/wGoal)*100)+'%';

  // Also update home stats
  document.getElementById('hStatCalories').textContent = totals.calories || '0';
  document.getElementById('hStatWater').textContent    = water || '0';
}

// ── WATER ─────────────────────────────────────────────────────────────────────
async function logWater(oz) {
  const log = getTodayLog();
  log.water = Math.max(0, (log.water||0) + oz);
  S.user.data.nutrition.logs[todayKey()] = log;
  await saveUserData(S.user.data);
  renderNutriToday();
}

// ── MEAL LOG ──────────────────────────────────────────────────────────────────
function renderMealsList() {
  const log     = getTodayLog();
  const entries = log.entries || [];
  const el      = document.getElementById('mealsList');
  if (!entries.length) {
    el.innerHTML = '<p style="font-family:\'Crimson Pro\',serif;font-style:italic;color:var(--text-mute);font-size:0.9rem;padding:8px 0">No meals logged today.</p>';
    return;
  }
  el.innerHTML = entries.map((e,i) => `
    <div class="rcard" style="margin-bottom:10px;padding:16px 20px">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <div>
          <div style="font-family:'Cinzel',serif;font-size:0.72rem;letter-spacing:1px;color:var(--text);margin-bottom:4px">${e.name}</div>
          <div style="font-family:'Crimson Pro',serif;font-size:0.85rem;color:var(--text-dim)">${e.calories} kcal &nbsp;·&nbsp; P:${e.protein}g &nbsp;·&nbsp; C:${e.carbs}g &nbsp;·&nbsp; F:${e.fat}g</div>
        </div>
        <button onclick="deleteMealEntry(${i})" style="background:none;border:none;color:var(--text-mute);cursor:pointer;font-size:1rem;padding:0 0 0 12px">✕</button>
      </div>
    </div>`).join('');
}

function openAddMeal(type) {
  document.getElementById('addMealForm').style.display  = type==='manual' ? 'block' : 'none';
  document.getElementById('scanMealForm').style.display = type==='photo'  ? 'block' : 'none';
  if (type==='manual') { ['mealName','mealCal','mealPro','mealCarbs','mealFat'].forEach(id=>{ const el=document.getElementById(id); if(el)el.value=''; }); }
}
function closeAddMeal()  { document.getElementById('addMealForm').style.display='none'; }
function closeScanMeal() {
  document.getElementById('scanMealForm').style.display='none';
  document.getElementById('mealPhotoPreview').style.display='none';
  document.getElementById('mealScanResult').style.display='none';
  S._mealPhotoData = null;
}

async function saveMealEntry(overrideData) {
  const entry = overrideData || {
    name:     document.getElementById('mealName')?.value.trim() || 'Unnamed',
    calories: parseInt(document.getElementById('mealCal')?.value)  || 0,
    protein:  parseInt(document.getElementById('mealPro')?.value)  || 0,
    carbs:    parseInt(document.getElementById('mealCarbs')?.value) || 0,
    fat:      parseInt(document.getElementById('mealFat')?.value)   || 0,
  };
  const log = getTodayLog();
  log.entries = log.entries || [];
  log.entries.push({ ...entry, id: Date.now(), time: new Date().toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit'}) });
  S.user.data.nutrition.logs[todayKey()] = log;
  await saveUserData(S.user.data);
  closeAddMeal(); closeScanMeal();
  renderMealsList(); renderNutriToday(); renderHome();
}

async function deleteMealEntry(idx) {
  const log = getTodayLog();
  log.entries.splice(idx, 1);
  S.user.data.nutrition.logs[todayKey()] = log;
  await saveUserData(S.user.data);
  renderMealsList(); renderNutriToday(); renderHome();
}

// ── MEAL PHOTO SCAN ───────────────────────────────────────────────────────────
function loadMealPhoto(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const img = document.getElementById('mealPhotoPreview');
    img.src = e.target.result; img.style.display='block';
    resizeImage(e.target.result, 800).then(r => { S._mealPhotoData = r; });
  };
  reader.readAsDataURL(file);
}

async function analyzeMealPhoto() {
  if (!S._mealPhotoData) { alert('Please upload a photo first.'); return; }
  const btn = document.getElementById('scanMealBtn');
  btn.disabled=true; btn.textContent='Analyzing…';
  const resultEl = document.getElementById('mealScanResult');
  resultEl.style.display='none';
  try {
    const mediaType = S._mealPhotoData.split(';')[0].split(':')[1];
    const b64       = S._mealPhotoData.split(',')[1];
    const body = await callClaude({
      system: `You are a precise nutrition estimator. Analyze the food photo and estimate the nutritional content. Respond ONLY with this exact JSON:
{"name":"<meal name>","calories":<number>,"protein":<grams>,"carbs":<grams>,"fat":<grams>,"notes":"<1 sentence about assumptions/portion size>"}`,
      messages: [{ role:'user', content:[
        { type:'image', source:{ type:'base64', media_type:mediaType, data:b64 }},
        { type:'text', text:'Estimate the calories and macros for this meal.' }
      ]}],
      max_tokens: 300
    });
    const raw    = body.content[0].text.trim();
    const parsed = JSON.parse(raw.match(/\{[\s\S]*\}/)[0]);
    resultEl.style.display='block';
    resultEl.innerHTML = `<div class="rcard" style="margin-bottom:0;border-color:var(--border-gold)">
      <div class="rcard-label">AI Estimate</div>
      <div style="font-family:'Cinzel',serif;font-size:0.85rem;letter-spacing:1px;color:var(--text);margin-bottom:8px">${parsed.name}</div>
      <div style="font-family:'Crimson Pro',serif;font-size:0.95rem;color:var(--text-dim);margin-bottom:10px">${parsed.calories} kcal &nbsp;·&nbsp; P:${parsed.protein}g &nbsp;·&nbsp; C:${parsed.carbs}g &nbsp;·&nbsp; F:${parsed.fat}g</div>
      <p style="font-family:'Crimson Pro',serif;font-size:0.82rem;color:var(--text-mute);font-style:italic;margin-bottom:14px">${parsed.notes}</p>
      <button class="btn btn-primary" onclick="saveMealEntry(${JSON.stringify(JSON.stringify(parsed)).slice(1,-1)})" style="width:100%">Log This Meal →</button>
    </div>`;
    // Fix: attach data directly to avoid JSON escaping issues
    resultEl.querySelector('.btn-primary').onclick = () => saveMealEntry(parsed);
  } catch(e) {
    resultEl.style.display='block';
    resultEl.innerHTML = `<p style="color:var(--error);font-family:'Crimson Pro',serif">Error: ${e.message}</p>`;
  }
  btn.disabled=false; btn.textContent='Analyze Meal →';
}

// ── TDEE CALCULATOR ───────────────────────────────────────────────────────────
function calculateTDEE() {
  const age      = parseInt(document.getElementById('calcAge')?.value);
  const weightLb = parseFloat(document.getElementById('calcWeight')?.value);
  const heightIn = parseFloat(document.getElementById('calcHeight')?.value);
  const activity = parseFloat(document.getElementById('calcActivity')?.value) || 1.55;
  const goal     = document.getElementById('calcGoal')?.value || 'maintain';
  if (!age || !weightLb || !heightIn) { alert('Please fill in all fields.'); return; }

  const kg = weightLb * 0.453592;
  const cm = heightIn * 2.54;
  const bmr  = (10 * kg) + (6.25 * cm) - (5 * age) + 5; // Mifflin-St Jeor (men)
  const tdee = bmr * activity;
  const goalAdj = { cut:-500, maintain:0, 'lean-bulk':250, bulk:500 }[goal] || 0;
  const calories = Math.round(tdee + goalAdj);

  // Bodybuilder macro split
  const protein = Math.round(weightLb * 1.0);        // 1g/lb BW
  const fat     = Math.round(weightLb * 0.4);         // 0.4g/lb BW
  const fatCals = fat * 9;
  const proCals = protein * 4;
  const carbs   = Math.round((calories - proCals - fatCals) / 4);

  const resultsEl = document.getElementById('calcResults');
  const gridEl    = document.getElementById('calcResultsGrid');
  resultsEl.style.display = 'block';
  gridEl.innerHTML = [
    ['TDEE (maintenance)', Math.round(tdee) + ' kcal'],
    ['Target Calories', calories + ' kcal'],
    ['Protein', protein + 'g  (1g/lb BW)'],
    ['Carbs',   Math.max(0,carbs) + 'g'],
    ['Fat',     fat + 'g  (0.4g/lb BW)'],
    ['Water',   '128 oz (1 gallon)'],
  ].map(([k,v]) => `<div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border)">
    <span style="font-family:'Cinzel',serif;font-size:0.65rem;letter-spacing:2px;text-transform:uppercase;color:var(--text-dim)">${k}</span>
    <span style="font-family:'Cinzel Decorative',serif;font-size:0.85rem;color:var(--gold)">${v}</span>
  </div>`).join('');

  // Store for saving
  resultsEl.dataset.calories = calories;
  resultsEl.dataset.protein  = protein;
  resultsEl.dataset.carbs    = Math.max(0,carbs);
  resultsEl.dataset.fat      = fat;
}

async function saveCalcGoals() {
  const el = document.getElementById('calcResults');
  if (!el || el.style.display==='none') return;
  S.user.data.nutrition = S.user.data.nutrition || { goals:{}, logs:{} };
  S.user.data.nutrition.goals = {
    calories: parseInt(el.dataset.calories)||0,
    protein:  parseInt(el.dataset.protein)||0,
    carbs:    parseInt(el.dataset.carbs)||0,
    fat:      parseInt(el.dataset.fat)||0,
    water:    128
  };
  await saveUserData(S.user.data);
  showNutriTab('today');
  renderNutriToday();
}

// ── NUTRITION TABS ────────────────────────────────────────────────────────────
function showNutriTab(tab) {
  ['today','log','calc','history'].forEach(t => {
    const panel = document.getElementById('ntab'+t.charAt(0).toUpperCase()+t.slice(1));
    const btn   = document.getElementById('ntabBtn'+t.charAt(0).toUpperCase()+t.slice(1));
    if (panel) panel.classList.toggle('active', t===tab);
    if (btn)   btn.classList.toggle('active',   t===tab);
  });
  if (tab==='today')   renderNutriToday();
  if (tab==='log')     renderMealsList();
  if (tab==='history') renderNutriHistory();
}

function renderNutriHistory() {
  const logs  = S.user?.data?.nutrition?.logs || {};
  const goals = S.user?.data?.nutrition?.goals || {};
  const days  = 7;
  const labels = [], calories = [];
  for (let i=days-1; i>=0; i--) {
    const d   = new Date(); d.setDate(d.getDate()-i);
    const key = d.toISOString().slice(0,10);
    labels.push(d.toLocaleDateString('en-US',{month:'short',day:'numeric'}));
    const entries = logs[key]?.entries || [];
    calories.push(getMealTotals(entries).calories);
  }
  requestAnimationFrame(() => {
    const ctx = document.getElementById('nutriHistoryChart');
    if (!ctx || !window.Chart) return;
    if (ctx._chartInstance) ctx._chartInstance.destroy();
    ctx._chartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Calories',
          data: calories,
          backgroundColor: 'rgba(200,168,75,0.25)',
          borderColor: '#c8a84b',
          borderWidth: 1.5,
          borderRadius: 4
        }, goals.calories ? {
          label: 'Goal',
          data: Array(days).fill(goals.calories),
          type: 'line',
          borderColor: 'rgba(200,168,75,0.5)',
          borderDash: [4,4],
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false
        } : null].filter(Boolean)
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          y: { min:0, ticks:{ color:'#888', font:{family:'Cinzel, serif',size:10} }, grid:{ color:'rgba(255,255,255,0.05)' } },
          x: { ticks:{ color:'#888', font:{family:'Cinzel, serif',size:10} }, grid:{ color:'rgba(255,255,255,0.05)' } }
        },
        plugins: {
          legend:{ display:false },
          tooltip:{ backgroundColor:'#0e0e0e', borderColor:'rgba(200,168,75,0.3)', borderWidth:1, titleColor:'#c8a84b', bodyColor:'#ede8dc', titleFont:{family:'Cinzel, serif',size:11}, bodyFont:{family:"'Crimson Pro', serif",size:13} }
        }
      }
    });
  });
}
