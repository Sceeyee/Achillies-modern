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
    const init = { analyses: [], savedApiKey: null };
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
  document.getElementById('navBar').classList.remove('visible');
  document.getElementById('authScreen').classList.add('active');
  document.getElementById('appScreen').classList.remove('active');
  document.getElementById('loginUser').value='';
  document.getElementById('loginPass').value='';
  clearAuthError();
}

function enterApp() {
  document.getElementById('authScreen').classList.remove('active');
  document.getElementById('appScreen').classList.add('active');
  document.getElementById('navBar').classList.add('visible');
  document.getElementById('navUsername').textContent = S.user.username.toUpperCase();
  // API key row: hidden by default in HTML, only show for local dev
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
  if (!checked) { S.showDate=null; S.showName=''; }
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
      body: JSON.stringify({ system, messages, max_tokens, model: 'claude-sonnet-4-6' })
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
      ? `\n\nSHOW DATE CONTEXT: This athlete has a show named "${S.showName}" in ${days} days. Include targeted show-prep advice in show_advice.`
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
  "show_advice": ${days!==null ? '"<targeted advice for ' + days + ' days out — what to focus on, what not to change, motivation>"' : 'null'}
}`;

    const body = await callClaude({
      system: systemPrompt,
      messages: [{ role:'user', content:[
        ...imageBlocks,
        { type:'text', text:`Analyze under ${div.label} standards and return the JSON report.` }
      ]}],
      max_tokens: 1800
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
      ${report.show_advice ? `<p style="font-family:'Crimson Pro',serif;font-style:italic;color:var(--text-dim);font-size:0.95rem;margin-top:12px;line-height:1.7">${report.show_advice}</p>` : ''}
    </div>`;
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
  // Clear strength fields and hide section
  ['sBodyweight','sBench','sSquat','sDeadlift'].forEach(id=>{ const el=document.getElementById(id); if(el) el.value=''; });
  const strengthSec = document.getElementById('strengthSection');
  if (strengthSec) strengthSec.style.display = 'none';
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
