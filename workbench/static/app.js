/* Entra Migration Workbench: single-page UI. No framework, no external resources.
   All collected text is written with textContent, never as HTML. */
(function () {
  'use strict';

  var S = { view: 'boot', platforms: [], projects: [], project: null, tab: 'overview', source: null, analysis: null,
            filter: { sev: '', wave: '', q: '' }, inv: 'policies', open: {}, timer: null };

  // ---- helpers -------------------------------------------------------------------------------
  function h(tag, attrs) {
    var el = document.createElement(tag), i, k, c;
    attrs = attrs || {};
    for (k in attrs) {
      if (attrs[k] == null || attrs[k] === false) continue;
      if (k === 'class') el.className = attrs[k];
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), attrs[k]);
      else if (k === 'value') el.value = attrs[k];
      else if (k === 'checked' || k === 'disabled' || k === 'selected') el[k] = !!attrs[k];
      else el.setAttribute(k, attrs[k] === true ? '' : attrs[k]);
    }
    for (i = 2; i < arguments.length; i++) {
      c = arguments[i];
      if (c == null || c === false) continue;
      if (Array.isArray(c)) c.forEach(function (x) { if (x != null && x !== false) el.appendChild(x.nodeType ? x : document.createTextNode(String(x))); });
      else el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  function toast(msg, err) {
    var t = h('div', { class: err ? 'err' : '' }, msg), box = document.getElementById('toast');
    while (box.children.length >= 3) box.firstChild.remove();
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, err ? 7000 : 3000);
  }
  function api(method, path, body, raw) {
    var opt = { method: method, headers: { 'X-Workbench': '1' }, credentials: 'same-origin' };
    if (body instanceof FormData) opt.body = body;
    else if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    return fetch(path, opt).then(function (r) {
      if (r.status === 401 && path !== '/api/login') { S.view = 'login'; render(); throw new Error('Signed out'); }
      if (raw && r.ok) return r;
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    });
  }
  function fail(e) { if (e && e.message !== 'Signed out') toast(e.message || String(e), true); }
  function when(iso) { return iso ? String(iso).replace('T', ' ').replace(/(\.\d+)?(Z|\+00:00)$/, '') : ''; }
  function chip(text, cls) { return h('span', { class: 'chip ' + (cls || '') }, text); }
  function field(label, input, help) { return h('label', { class: 'field' }, h('span', {}, label), input, help ? h('small', {}, help) : null); }
  function dialog(title, body, actions) {
    var ov = h('div', { class: 'overlay', onclick: function (e) { if (e.target === ov) ov.remove(); } },
      h('div', { class: 'dialog', role: 'dialog', 'aria-label': title },
        h('header', {}, h('h2', { class: 'grow' }, title), h('button', { class: 'btn ghost', onclick: function () { ov.remove(); } }, 'Close')),
        body, h('footer', {}, actions || [])));
    document.body.appendChild(ov);
    var first = ov.querySelector('input, select, textarea');
    if (first) first.focus();
    return ov;
  }
  function table(cols, rows, opts) {
    opts = opts || {};
    if (!rows || !rows.length) return h('div', { class: 'empty' }, opts.empty || 'Nothing here.');
    var body = h('tbody');
    rows.forEach(function (r, idx) {
      var tr = h('tr', { class: opts.onrow ? 'click' : '', onclick: opts.onrow ? function () { opts.onrow(r, idx); } : null },
        cols.map(function (c) { return h('td', { class: (c.num ? 'num ' : '') + (c.wrap ? 'wrap' : '') }, c.cell ? c.cell(r) : (r[c.key] == null ? '' : String(r[c.key]))); }));
      body.appendChild(tr);
      if (opts.detail) { var d = opts.detail(r, idx); if (d) body.appendChild(h('tr', { class: 'detail' }, h('td', { colspan: cols.length }, d))); }
    });
    return h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, cols.map(function (c) { return h('th', { class: c.num ? 'num' : '' }, c.title); }))), body));
  }
  function download(path) {
    api('GET', path, undefined, true).then(function (r) {
      var name = (/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '') || [])[1] || 'download';
      return r.blob().then(function (b) {
        var a = h('a', { href: URL.createObjectURL(b), download: name });
        document.body.appendChild(a); a.click(); a.remove();
      });
    }).catch(fail);
  }

  function packed(f) {
    if (typeof CompressionStream === 'undefined' || /\.gz$/.test(f.name) || f.size < 262144) return Promise.resolve(f);
    return new Response(f.stream().pipeThrough(new CompressionStream('gzip'))).blob().then(function (b) { return new File([b], f.name + '.gz', { type: 'application/gzip' }); });
  }

  // ---- boot and session ----------------------------------------------------------------------
  function boot() {
    api('GET', '/api/state').then(function (st) {
      S.version = st.version;
      if (!st.initialised) { S.view = 'setup'; render(); }
      else if (!st.signedIn) { S.view = 'login'; render(); }
      else enter();
    }).catch(fail);
  }
  function enter() {
    Promise.all([api('GET', '/api/platforms'), api('GET', '/api/projects')]).then(function (r) {
      S.platforms = r[0]; S.projects = r[1]; S.view = 'home'; S.project = null; render();
    }).catch(fail);
  }
  function viewAuth(setup) {
    var pass = h('input', { type: 'password', autocomplete: setup ? 'new-password' : 'current-password' });
    var pass2 = h('input', { type: 'password', autocomplete: 'new-password' });
    var code = h('input', { type: 'text', autocomplete: 'off' });
    function go(e) {
      e.preventDefault();
      if (setup && pass.value !== pass2.value) return toast('The two passphrases differ', true);
      api('POST', setup ? '/api/setup' : '/api/login', setup ? { setupCode: code.value, passphrase: pass.value } : { passphrase: pass.value }).then(enter).catch(fail);
    }
    return h('div', { class: 'gate-screen' }, h('form', { class: 'card stack', onsubmit: go },
      h('div', {}, h('h1', {}, 'Entra Migration ', h('span', {}, 'Workbench')),
        h('div', { class: 'muted' }, setup ? 'First start: choose the shared passphrase.' : 'Enter the shared passphrase to unlock.')),
      setup ? field('Setup code', code, 'Printed in the container log at first start.') : null,
      field('Passphrase', pass, setup ? 'At least 12 characters. It encrypts every project. There is no recovery if it is lost.' : null),
      setup ? field('Repeat passphrase', pass2) : null,
      h('button', { class: 'btn primary', type: 'submit' }, setup ? 'Set passphrase and start' : 'Unlock')));
  }

  // ---- shell ---------------------------------------------------------------------------------
  function bar() {
    return h('div', { class: 'bar' },
      h('button', { class: 'brand', onclick: enter }, 'Entra Migration ', h('span', {}, 'Workbench')),
      S.project ? h('span', { class: 'crumb' }, '/ ' + S.project.name) : null,
      h('span', { class: 'grow' }),
      h('span', { class: 'crumb small' }, 'v' + (S.version || '')),
      h('button', { class: 'link', onclick: changePass }, 'Passphrase'),
      h('button', { class: 'link', onclick: function () { api('POST', '/api/lock').then(function () { S.view = 'login'; render(); }).catch(fail); } }, 'Lock'),
      h('button', { class: 'link', onclick: function () { api('POST', '/api/logout').then(function () { S.view = 'login'; render(); }).catch(fail); } }, 'Sign out'));
  }
  function changePass() {
    var cur = h('input', { type: 'password' }), nw = h('input', { type: 'password' });
    var d = dialog('Change passphrase', h('div', { class: 'stack' }, field('Current passphrase', cur), field('New passphrase', nw, 'Every project key is re-wrapped. Data is not re-encrypted.')),
      [h('button', { class: 'btn primary', onclick: function () {
        api('POST', '/api/passphrase', { current: cur.value, new: nw.value }).then(function () { d.remove(); toast('Passphrase changed'); }).catch(fail); } }, 'Change')]);
  }
  function render() {
    clearTimeout(S.timer);
    var root = document.getElementById('app');
    root.textContent = '';
    if (S.view === 'boot') return;
    if (S.view === 'setup' || S.view === 'login') return root.appendChild(viewAuth(S.view === 'setup'));
    root.appendChild(bar());
    root.appendChild(h('main', {}, S.view === 'home' ? viewHome() : viewProject()));
  }

  // ---- home ----------------------------------------------------------------------------------
  function viewHome() {
    var cards = S.projects.map(function (p) {
      var blockers = p.analyses.reduce(function (n, a) { return n + (a.blockers || 0); }, 0);
      return h('button', { class: 'card pcard', onclick: function () { openProject(p.id); } },
        h('div', { class: 'row' }, h('h2', { class: 'grow' }, p.name), p.running ? h('span', { class: 'chip run' }, h('span', { class: 'spinner' }), ' collecting') : null),
        h('div', { class: 'muted' }, p.client || 'No client name'),
        h('div', { class: 'chips', style: null }, p.platforms.map(function (x) { return chip(labelOf(x), 'accent'); }),
          p.hasTarget ? chip('Entra target') : chip('no target yet')),
        h('div', { class: 'row small muted' }, 'Next gate: ' + p.nextGate, h('span', { class: 'grow' }),
          p.analyses.length ? chip(blockers + ' blockers', blockers ? 'Blocker' : 'ok') : chip('not analysed')));
    });
    cards.forEach(function (c) { c.querySelector('.chips').style.margin = '10px 0'; });
    return h('div', { class: 'stack' },
      h('div', { class: 'row' }, h('h1', { class: 'grow' }, 'Projects'), h('button', { class: 'btn primary', onclick: newProject }, 'New project')),
      S.projects.length ? h('div', { class: 'grid' }, cards)
        : h('div', { class: 'card empty' }, 'No project yet. A project holds the source platforms of one client, its target tenant, snapshots and decisions. Each project is encrypted with its own key.'));
  }
  function labelOf(platform) { var p = S.platforms.filter(function (x) { return x.platform === platform; })[0]; return p ? p.label : platform; }
  function newProject() {
    var name = h('input', { type: 'text' }), client = h('input', { type: 'text' }), desc = h('input', { type: 'text' });
    var d = dialog('New project', h('div', { class: 'stack' }, field('Project name', name), field('Client', client), field('Note', desc)),
      [h('button', { class: 'btn primary', onclick: function () {
        api('POST', '/api/projects', { name: name.value, client: client.value, description: desc.value }).then(function (p) { d.remove(); S.tab = 'connectors'; openProject(p.id); }).catch(fail); } }, 'Create')]);
  }

  // ---- project -------------------------------------------------------------------------------
  function openProject(id, keep) {
    api('GET', '/api/projects/' + id).then(function (p) {
      S.project = p; S.view = 'project';
      if (!keep) { S.open = {}; }
      var sources = p.connectors.filter(function (c) { return c.role === 'source'; });
      if (!S.source || !sources.some(function (c) { return c.id === S.source; })) S.source = (sources.filter(function (c) { return c.analysedAt; })[0] || sources[0] || {}).id || null;
      return loadAnalysis();
    }).then(render).catch(fail);
  }
  function loadAnalysis() {
    S.analysis = null;
    var c = S.project.connectors.filter(function (x) { return x.id === S.source; })[0];
    if (!c || !c.analysedAt) return Promise.resolve();
    return api('GET', '/api/projects/' + S.project.id + '/analysis/' + S.source).then(function (a) { S.analysis = a; });
  }
  function refresh() { openProject(S.project.id, true); }
  function kick(runs) {
    (Array.isArray(runs) ? runs : [runs]).forEach(function (r) {
      if (r && r.id && r.status === 'queued') api('POST', '/api/runs/' + r.id + '/execute').catch(function (e) { if (e && e.message !== 'Signed out') toast('Collection: ' + e.message, true); });
    });
  }
  function active() { return S.project.runs.some(function (r) { return r.status === 'queued' || r.status === 'running'; }); }
  function poll() {
    clearTimeout(S.timer);
    if (S.view !== 'project' || !active()) return;
    S.timer = setTimeout(function () {
      api('GET', '/api/projects/' + S.project.id + '/runs').then(function (runs) {
        var was = active();
        S.project.runs = runs;
        if (was && !active()) { toast('Collection finished'); refresh(); }
        else { if (S.tab === 'runs' || S.tab === 'connectors' || S.tab === 'overview') render(); else poll(); }
      }).catch(fail);
    }, 1500);
  }
  function sources() { return S.project.connectors.filter(function (c) { return c.role === 'source'; }); }
  function target() { return S.project.connectors.filter(function (c) { return c.role === 'target'; })[0]; }

  function viewProject() {
    var p = S.project, a = S.analysis;
    var next = (p.gateDefinitions.filter(function (g) { return ['Passed', 'Passed with conditions'].indexOf(p.gates[g.id].status) < 0; })[0] || {}).id;
    var tabs = [['overview', 'Overview'], ['connectors', 'Connectors'], ['runs', 'Runs'], ['findings', 'Findings', a && a.findings.length], ['apps', 'Applications', a && a.apps.length],
                ['waves', 'Waves'], ['inventory', 'Inventory'], ['manual', 'Manual checks', a && a.tables.manualChecks.filter(function (m) { return !m.done; }).length], ['settings', 'Settings']];
    var src = sources();
    var needsSource = ['findings', 'apps', 'waves', 'inventory', 'manual'].indexOf(S.tab) >= 0;
    var out = h('div', {},
      h('div', { class: 'phead' }, h('div', { class: 'grow' }, h('h1', {}, p.name), h('div', { class: 'muted' }, (p.client || 'No client name') + (p.description ? ' · ' + p.description : ''))),
        h('button', { class: 'btn', onclick: function () { api('POST', '/api/projects/' + p.id + '/collect').then(function (runs) { kick(runs); toast('Collection started'); S.tab = 'runs'; refresh(); }).catch(fail); }, disabled: !p.connectors.length || active() }, 'Collect all'),
        h('button', { class: 'btn', onclick: function () { download('/api/projects/' + p.id + '/evidence'); }, disabled: !p.runs.some(function (r) { return r.status === 'done'; }) }, 'Evidence pack')),
      h('div', { class: 'gates' }, p.gateDefinitions.map(function (g) {
        var st = p.gates[g.id];
        return h('button', { class: 'gate ' + st.status.replace(/ /g, '-') + (g.id === next ? ' next' : ''), title: g.criterion, onclick: function () { editGate(g); } },
          h('b', {}, g.id + ' · ' + g.phase), h('span', {}, st.status + (st.date ? ' ' + st.date : '')));
      })),
      h('div', { class: 'tabs', role: 'tablist' }, tabs.map(function (t) {
        return h('button', { class: 'tab' + (S.tab === t[0] ? ' on' : ''), role: 'tab', onclick: function () { S.tab = t[0]; render(); } }, t[1], t[2] ? h('span', { class: 'n' }, t[2]) : null);
      })),
      needsSource && src.length > 1 ? h('div', { class: 'row', style: null }, h('span', { class: 'muted' }, 'Source'), h('div', { class: 'seg' }, src.map(function (c) {
        return h('button', { class: c.id === S.source ? 'on' : '', onclick: function () { S.source = c.id; loadAnalysis().then(render).catch(fail); } }, c.name);
      }))) : null);
    var seg = out.querySelector('.row > .seg'); if (seg) seg.parentNode.style.marginBottom = '14px';
    var body = { overview: tabOverview, connectors: tabConnectors, runs: tabRuns, findings: tabFindings, apps: tabApps, waves: tabWaves, inventory: tabInventory, manual: tabManual, settings: tabSettings }[S.tab];
    out.appendChild(needsSource && !a ? h('div', { class: 'card empty' }, src.length ? 'Not analysed yet. Run a collection on this source.' : 'Add a source connector and run a collection.') : body());
    poll();
    return out;
  }
  function editGate(g) {
    var st = S.project.gates[g.id];
    var status = h('select', {}, ['Open', 'Passed', 'Passed with conditions', 'Stopped'].map(function (x) { return h('option', { selected: x === st.status }, x); }));
    var by = h('input', { type: 'text', value: st.signedBy }), date = h('input', { type: 'date', value: st.date }), note = h('input', { type: 'text', value: st.note });
    var d = dialog(g.id + ' · ' + g.phase, h('div', { class: 'stack' }, h('div', { class: 'note' }, 'Criterion: ' + g.criterion),
      h('div', { class: 'form-grid' }, field('Status', status), field('Signed by', by), field('Date', date), h('div', { class: 'wide' }, field('Conditions or note', note)))),
      [h('button', { class: 'btn primary', onclick: function () {
        var patch = { gates: {} }; patch.gates[g.id] = { status: status.value, signedBy: by.value, date: date.value, note: note.value };
        api('PATCH', '/api/projects/' + S.project.id, patch).then(function () { d.remove(); refresh(); }).catch(fail); } }, 'Save')]);
  }

  // ---- overview ------------------------------------------------------------------------------
  function tabOverview() {
    var p = S.project, src = sources(), t = target();
    if (!p.connectors.length) return h('div', { class: 'card empty' }, 'Start under Connectors: add the source platform(s) and the target tenant, then collect.');
    var a = S.analysis, parts = [];
    if (a) {
      var s = a.summary, st = a.state;
      parts.push(h('div', { class: 'card stack' },
        h('div', { class: 'row' }, h('div', { class: 'state-badge', title: 'Starting state' }, st.state),
          h('div', { class: 'grow' }, h('h2', {}, s.platform + ' · ' + s.org), h('div', { class: 'muted' }, 'Collected ' + when(s.collectedAt) + ' UTC' + (st.mixed ? ' · mixed estate' : ''))),
          h('button', { class: 'btn', onclick: function () { download('/api/projects/' + p.id + '/export/' + S.source + '/xlsx'); } }, 'Workbook'),
          h('button', { class: 'btn', onclick: function () { download('/api/projects/' + p.id + '/export/' + S.source + '/md'); } }, 'Report')),
        h('div', {}, st.description),
        h('div', { class: 'stats' },
          stat(s.blockers, 'Blockers', 'Blocker'), stat(s.high, 'High findings'), stat(s.appsToMigrate, 'Apps to migrate'), stat(s.appsToRetire, 'Proposed to retire'),
          stat(s.activeUsers == null ? 'n/a' : s.activeUsers, 'Active users'), stat(s.localPasswordUsers == null ? 'n/a' : s.localPasswordUsers, 'Platform-only passwords'),
          stat(s.effortDays, s.effortCalibrated ? 'App effort, days' : 'App effort, days (placeholder)')),
        h('div', {}, h('h3', {}, 'Evidence'), h('ul', {}, st.evidence.map(function (e) { return h('li', {}, e); }))),
        a.drift && (a.drift.added.length || a.drift.removed.length) ? h('div', { class: 'note warn' }, 'Changed since the snapshot of ' + when(a.drift.comparedWith) + ': ' +
          (a.drift.added.length ? 'new apps ' + a.drift.added.join(', ') + '. ' : '') + (a.drift.removed.length ? 'Removed: ' + a.drift.removed.join(', ') + '.' : '')) : null,
        s.collectionErrors ? h('div', { class: 'note warn' }, s.collectionErrors + ' collection step(s) failed. The report is silent on those areas, not clean. See the COL-01 findings.') : null,
        !s.usageKnown ? h('div', { class: 'note warn' }, 'No usage data: no app can be proposed for retirement.') : null));
      var tg = a.target;
      parts.push(h('div', { class: 'card stack' }, h('h2', {}, 'Target tenant'),
        tg.collected ? h('dl', { class: 'kv' },
          h('dt', {}, 'Tenant'), h('dd', {}, tg.tenant || ''), h('dt', {}, 'Collected'), h('dd', {}, when(tg.collectedAt) + ' UTC'),
          h('dt', {}, 'Directory sync'), h('dd', {}, tg.syncEnabled ? 'Enabled' : 'Not enabled'),
          h('dt', {}, 'Federated domains'), h('dd', {}, (tg.federatedDomains || []).join(', ') || 'None'),
          h('dt', {}, 'Users'), h('dd', {}, tg.users == null ? 'not read' : tg.users),
          h('dt', {}, 'Identity matching'), h('dd', {}, a.identity.matching ? a.identity.matching.byUpn + ' by UPN, ' + a.identity.matching.byMail + ' by mail, ' + a.identity.matching.ambiguous + ' ambiguous, ' + a.identity.matching.unmatched + ' unmatched' : 'n/a'),
          h('dt', {}, 'Conditional Access'), h('dd', {}, tg.conditionalAccess ? tg.conditionalAccess.enabled + ' enabled, ' + tg.conditionalAccess.reportOnly + ' report-only, ' + tg.conditionalAccess.disabled + ' disabled' : 'Not readable (optional permission)'),
          h('dt', {}, 'Enterprise apps'), h('dd', {}, tg.enterpriseApps == null ? 'not read' : tg.enterpriseApps))
        : h('div', { class: 'note warn' }, t ? 'The target is configured but not collected yet.' : 'No target tenant configured. Identity matching, gallery matching and federation evidence are missing.')));
    } else {
      parts.push(h('div', { class: 'card empty' }, src.length ? 'No analysis yet. Use "Collect all".' : 'Add a source connector.'));
    }
    if (src.length > 1) parts.unshift(h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Source'), h('div', { class: 'seg' }, src.map(function (c) {
      return h('button', { class: c.id === S.source ? 'on' : '', onclick: function () { S.source = c.id; loadAnalysis().then(render).catch(fail); } }, c.name); }))));
    return h('div', { class: 'stack' }, parts);
  }
  function stat(v, label, cls) { return h('div', { class: 'stat ' + (cls && v ? cls : '') }, h('b', {}, v == null ? '' : v), h('span', {}, label)); }

  // ---- connectors ----------------------------------------------------------------------------
  function tabConnectors() {
    var p = S.project;
    function card(c) {
      var live = p.runs.filter(function (r) { return r.connector === c.id && (r.status === 'queued' || r.status === 'running'); })[0];
      var def = S.platforms.filter(function (x) { return x.platform === c.platform; })[0];
      var lr = c.lastRun;
      return h('div', { class: 'card stack' },
        h('div', { class: 'row' }, h('div', { class: 'grow' }, h('h2', {}, c.name), h('div', { class: 'muted small' }, c.label + ' · ' + (c.role === 'target' ? 'target' : 'source'))),
          live ? h('span', { class: 'chip run' }, h('span', { class: 'spinner' }), ' ' + (live.step || live.status)) : lr ? chip(lr.status + ' ' + when(lr.finished || lr.started), lr.status === 'done' ? 'ok' : 'High') : chip('never collected')),
        def.acceptsFiles ? h('div', { class: 'stack' }, h('div', { class: 'small muted' }, 'Audit log files (' + c.files.length + ')'),
          c.files.map(function (f) { return h('div', { class: 'row small' }, h('span', { class: 'grow mono' }, f.name + ' · ' + Math.round(f.size / 1024) + ' kB'),
            h('button', { class: 'btn ghost', onclick: function () { api('DELETE', '/api/projects/' + p.id + '/connectors/' + c.id + '/files/' + f.id).then(refresh).catch(fail); } }, 'Remove')); }),
          h('input', { type: 'file', multiple: true, 'aria-label': 'Upload audit log files', onchange: function (e) {
            var files = Array.prototype.slice.call(e.target.files);
            files.reduce(function (chain, f) { return chain.then(function () { return packed(f).then(function (file) { var fd = new FormData(); fd.append('file', file, file.name); return api('POST', '/api/projects/' + p.id + '/connectors/' + c.id + '/files', fd); }); }); }, Promise.resolve())
              .then(function () { toast(files.length + ' file(s) stored encrypted'); refresh(); }).catch(fail); } })) : null,
        h('div', { class: 'row' },
          h('button', { class: 'btn', onclick: function (e) { e.target.disabled = true; api('POST', '/api/projects/' + p.id + '/connectors/' + c.id + '/test').then(function (r) { toast(r.detail, !r.ok); }).catch(fail).then(function () { e.target.disabled = false; }); } }, 'Test'),
          h('button', { class: 'btn primary', disabled: !!live, onclick: function () { api('POST', '/api/projects/' + p.id + '/connectors/' + c.id + '/collect').then(function (run) { kick(run); toast('Collection started'); refresh(); }).catch(fail); } }, 'Collect'),
          live ? h('button', { class: 'btn', onclick: function () { api('POST', '/api/runs/' + live.id + '/cancel').then(function () { toast('Cancelling'); }).catch(fail); } }, 'Cancel') : null,
          h('span', { class: 'grow' }),
          h('button', { class: 'btn ghost', onclick: function () { connectorForm(def, c); } }, 'Edit'),
          h('button', { class: 'btn ghost', onclick: function () {
            var d = dialog('Remove connector', h('div', {}, 'Removes "' + c.name + '" with its snapshots, analysis and tracking. This cannot be undone.'),
              [h('button', { class: 'btn danger', onclick: function () { api('DELETE', '/api/projects/' + p.id + '/connectors/' + c.id).then(function () { d.remove(); refresh(); }).catch(fail); } }, 'Remove')]); } }, 'Remove')));
    }
    var t = target();
    return h('div', { class: 'stack' },
      h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Source platforms'), h('button', { class: 'btn', onclick: function () { pickPlatform('source'); } }, 'Add source')),
      sources().length ? h('div', { class: 'grid wide' }, sources().map(card)) : h('div', { class: 'card empty' }, 'No source yet. Add Okta, Keycloak, PingFederate, PingOne or OneLogin. A project can hold several, for example PingFederate and PingOne of the same client.'),
      h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Target tenant'), t ? null : h('button', { class: 'btn', onclick: function () { pickPlatform('target'); } }, 'Add target')),
      t ? h('div', { class: 'grid wide' }, card(t)) : h('div', { class: 'card empty' }, 'No target yet. The Entra connector reads users, domains, the application gallery and existing enterprise apps.'),
      h('div', { class: 'note' }, 'Collectors only read. Secrets in the collected configuration are replaced by [REDACTED] before anything is stored. Connector credentials and snapshots are encrypted with this project\'s key.'));
  }
  function pickPlatform(role) {
    var list = S.platforms.filter(function (x) { return x.role === role; });
    if (list.length === 1) return connectorForm(list[0]);
    var d = dialog('Add source', h('div', { class: 'platform-pick' }, list.map(function (x) {
      return h('button', { class: 'btn', onclick: function () { d.remove(); connectorForm(x); } }, h('b', {}, x.label), h('span', { class: 'small muted' }, 'read-only collector')); })));
  }
  function connectorForm(def, existing) {
    var inputs = {}, cfg = existing ? existing.config : {};
    var name = h('input', { type: 'text', value: existing ? existing.name : def.label });
    var grid = h('div', { class: 'form-grid' }, h('div', { class: 'wide' }, field('Name in this project', name)));
    function sync() {
      var mode = inputs.authMode ? inputs.authMode.value : null;
      def.fields.forEach(function (f) { if (f.group) inputs[f.name].closest('label').style.display = (!mode || f.group === mode) ? '' : 'none'; });
    }
    def.fields.forEach(function (f) {
      var cur = cfg[f.name], el, wrap;
      var isSecret = f.kind === 'secret' || f.kind === 'textarea-secret';
      if (f.kind === 'bool') {
        el = h('input', { type: 'checkbox', checked: cur == null ? f.default : cur });
        wrap = h('label', { class: 'check' }, el, h('span', {}, h('b', {}, f.label), f.help ? h('small', { class: 'muted' }, ' ' + f.help) : null));
      } else {
        if (f.kind === 'select') el = h('select', { onchange: sync }, f.options.map(function (o) { return h('option', { value: o[0], selected: (cur == null ? f.default : cur) === o[0] }, o[1]); }));
        else if (f.kind === 'textarea-secret') el = h('textarea', { placeholder: cur && cur.set ? 'Stored. Leave empty to keep.' : '-----BEGIN PRIVATE KEY-----', autocomplete: 'off', spellcheck: 'false' });
        else if (f.kind === 'secret') el = h('input', { type: 'password', placeholder: cur && cur.set ? 'Stored. Leave empty to keep.' : '', autocomplete: 'new-password' });
        else el = h('input', { type: f.kind === 'number' ? 'number' : 'text', value: isSecret ? '' : (cur == null ? (f.default == null ? '' : f.default) : cur), autocomplete: 'off' });
        wrap = field(f.label + (f.required ? ' *' : ''), el, f.help);
        if (f.kind === 'textarea-secret') wrap.className += ' wide';
      }
      inputs[f.name] = el;
      grid.appendChild(wrap);
    });
    sync();
    var d = dialog((existing ? 'Edit ' : 'Add ') + def.label, h('div', { class: 'stack' }, h('div', { class: 'note' }, h('b', {}, 'Access needed. '), def.permissions), grid),
      [h('button', { class: 'btn primary', onclick: function () {
        var config = {};
        def.fields.forEach(function (f) {
          var el = inputs[f.name];
          config[f.name] = f.kind === 'bool' ? el.checked : (el.value === '' ? null : el.value);
        });
        var req = existing ? api('PUT', '/api/projects/' + S.project.id + '/connectors/' + existing.id, { name: name.value, config: config })
                           : api('POST', '/api/projects/' + S.project.id + '/connectors', { platform: def.platform, name: name.value, config: config });
        req.then(function () { d.remove(); toast('Saved, encrypted'); refresh(); }).catch(fail); } }, 'Save')]);
  }

  // ---- runs ----------------------------------------------------------------------------------
  function tabRuns() {
    var names = {}; S.project.connectors.forEach(function (c) { names[c.id] = c.name; });
    return h('div', { class: 'card pad0' }, table([
      { title: 'Started (UTC)', cell: function (r) { return when(r.started); } },
      { title: 'Connector', cell: function (r) { return h('div', {}, names[r.connector] || '(removed)', h('div', { class: 'sub' }, labelOf(r.platform))); } },
      { title: 'Status', cell: function (r) {
        var liveRun = r.status === 'queued' || r.status === 'running';
        return liveRun ? h('span', { class: 'chip run' }, h('span', { class: 'spinner' }), ' ' + (r.step || r.status) + ' · step ' + r.stepsDone) : chip(r.status, r.status === 'done' ? 'ok' : 'High'); } },
      { title: 'Requests', num: true, cell: function (r) { return r.manifest ? r.manifest.requests : ''; } },
      { title: 'Seconds', num: true, cell: function (r) { return r.manifest ? r.manifest.durationSeconds : ''; } },
      { title: 'Redacted', num: true, cell: function (r) { return r.manifest ? r.manifest.redactedValues : ''; } },
      { title: 'Result', wrap: true, cell: function (r) {
        if (r.error) return h('span', {}, r.error);
        if (!r.manifest) return '';
        var m = r.manifest, items = Object.keys(m.counts).filter(function (k) { return m.counts[k] != null; }).length;
        return h('div', {}, items + ' areas read' + (m.errors.length ? ', ' + m.errors.length + ' failed: ' + m.errors.map(function (e) { return e.step; }).join(', ') : '') +
          (m.notAvailable.length ? '; not available: ' + m.notAvailable.map(function (e) { return e.step; }).join(', ') : ''), h('div', { class: 'sub mono' }, m.source)); } }
    ], S.project.runs, { empty: 'No run yet.' }));
  }

  // ---- findings ------------------------------------------------------------------------------
  function tabFindings() {
    var a = S.analysis, sev = S.filter.sev;
    var rows = a.findings.filter(function (f) { return !sev || f.severity === sev; });
    return h('div', { class: 'stack' },
      h('div', { class: 'row' }, h('div', { class: 'seg' }, ['', 'Blocker', 'High', 'Medium', 'Info'].map(function (x) {
        var n = x ? a.findings.filter(function (f) { return f.severity === x; }).length : a.findings.length;
        return h('button', { class: sev === x ? 'on' : '', onclick: function () { S.filter.sev = x; render(); } }, (x || 'All') + ' ' + n); })),
        h('span', { class: 'grow' }), h('button', { class: 'btn', onclick: function () { download('/api/projects/' + S.project.id + '/export/' + S.source + '/md'); } }, 'Findings report')),
      h('div', { class: 'card pad0' }, table([
        { title: 'ID', cell: function (f) { return h('span', { class: 'mono' }, f.id); } },
        { title: 'Severity', cell: function (f) { return chip(f.severity, f.severity); } },
        { title: 'Finding', wrap: true, cell: function (f) { return h('div', {}, h('b', {}, f.title), h('div', { class: 'sub' }, f.evidence)); } },
        { title: 'Count', num: true, key: 'count' },
        { title: 'Recommendation', wrap: true, key: 'recommendation' },
        { title: 'Phase', key: 'phase' }], rows)));
  }

  // ---- applications --------------------------------------------------------------------------
  function tabApps() {
    var a = S.analysis, f = S.filter, q = f.q.toLowerCase();
    var rows = a.apps.filter(function (x) { return (!f.wave || x.wave === f.wave) && (!q || (x.label + ' ' + x.pattern + ' ' + x.flags.join(' ')).toLowerCase().indexOf(q) >= 0); });
    var search = h('input', { type: 'text', placeholder: 'Filter by name, pattern or flag', value: f.q, 'aria-label': 'Filter applications', oninput: function (e) { S.filter.q = e.target.value; clearTimeout(search._t); search._t = setTimeout(function () { render(); var s = document.querySelector('input[aria-label="Filter applications"]'); if (s) { s.focus(); s.setSelectionRange(s.value.length, s.value.length); } }, 250); } });
    search.style.maxWidth = '300px';
    return h('div', { class: 'stack' },
      h('div', { class: 'row' }, h('div', { class: 'seg' }, [''].concat(a.waves.map(function (w) { return w.wave; })).map(function (w) {
        return h('button', { class: f.wave === w ? 'on' : '', onclick: function () { S.filter.wave = w; render(); } }, w ? 'Wave ' + w : 'All'); })), search,
        h('span', { class: 'grow' }), h('button', { class: 'btn', onclick: function () { download('/api/projects/' + S.project.id + '/export/' + S.source + '/xlsx'); } }, 'Workbook')),
      h('div', { class: 'card pad0' }, table([
        { title: 'Wave', cell: function (x) { return chip(x.wave, x.wave === 'R' ? '' : 'accent'); } },
        { title: 'Application', cell: function (x) { return h('div', {}, h('b', {}, x.label), x.critical ? h('span', {}, ' ', chip('critical', 'High')) : null, h('div', { class: 'sub' }, x.pattern + (x.kind && x.kind !== x.pattern ? ' · ' + x.kind : ''))); } },
        { title: 'Class', cell: function (x) { return chip(x.migrationClass, x.migrationClass === 'Gap' ? 'Blocker' : x.migrationClass === 'Rebuild' ? 'Medium' : x.migrationClass === 'Generate' ? 'ok' : ''); } },
        { title: 'Tier', cell: function (x) { return x.tier ? x.tier + ' (' + x.score + ')' : ''; } },
        { title: 'Sign-ins', num: true, cell: function (x) { return x.signIns == null ? '' : x.signIns; } },
        { title: 'Users', num: true, cell: function (x) { return x.distinctUsers == null ? '' : x.distinctUsers; } },
        { title: 'Flags', cell: function (x) { return h('div', { class: 'chips' }, x.flags.map(function (fl) { return chip(fl, 'Info'); })); } },
        { title: 'Owner', cell: function (x) { return x.owner || h('span', { class: 'muted' }, x.ownerHint ? '(' + x.ownerHint + ')' : ''); } },
        { title: 'Status', cell: function (x) { return chip(x.trackStatus, x.trackStatus === 'Validated' || x.trackStatus === 'Retired' ? 'ok' : x.trackStatus === 'Blocked' ? 'Blocker' : ''); } }
      ], rows, { empty: 'No application matches.', onrow: function (x) { S.open[x.appId] = !S.open[x.appId]; render(); }, detail: function (x) { return S.open[x.appId] ? appDetail(x) : null; } })));
  }
  function appDetail(x) {
    var a = S.analysis;
    var owner = h('input', { type: 'text', value: x.owner, placeholder: x.ownerHint || '' });
    var status = h('select', {}, a.trackStatuses.map(function (s) { return h('option', { selected: s === x.trackStatus }, s); }));
    var wave = h('select', {}, [['', 'Proposed (' + x.proposedWave + ')'], ['1', '1'], ['2', '2'], ['3', '3'], ['4', '4'], ['5', '5'], ['6', '6'], ['7', '7'], ['R', 'R: retire']].map(function (o) {
      return h('option', { value: o[0], selected: (x.wave !== x.proposedWave ? x.wave : '') === o[0] }, o[1]); }));
    var note = h('input', { type: 'text', value: x.trackNote });
    return h('div', { class: 'stack', onclick: function (e) { e.stopPropagation(); } },
      h('dl', { class: 'kv' },
        h('dt', {}, 'Score'), h('dd', {}, x.scoreReasons + (x.effortDays != null ? ' → ' + x.effortDays + ' days' : '')),
        h('dt', {}, 'Gallery'), h('dd', {}, x.galleryMatch + (x.galleryTemplate ? ': ' + x.galleryTemplate : '')),
        x.policy ? h('dt', {}, 'Policy') : null, x.policy ? h('dd', {}, x.policy) : null,
        x.retireReason ? h('dt', {}, 'Retire') : null, x.retireReason ? h('dd', {}, x.retireReason) : null,
        h('dt', {}, 'Details'), h('dd', {}, 'provisioning ' + x.provisioning + ' · claim expressions ' + x.complexClaims + ' · group claims ' + x.groupClaims + (x.customNameId ? ' · custom NameID' : '') + (x.encryptedAssertion ? ' · encrypted assertion' : '') +
          (x.assignedUsers != null ? ' · assigned ' + x.assignedUsers + (x.directAssignments != null ? ' (' + x.directAssignments + ' direct)' : '') : '')),
        x.notes ? h('dt', {}, 'Notes') : null, x.notes ? h('dd', {}, x.notes) : null,
        h('dt', {}, 'Source ID'), h('dd', { class: 'mono' }, x.appId)),
      h('div', { class: 'form-grid' }, field('Owner (confirmed)', owner), field('Status', status), field('Wave', wave), field('Note', note)),
      h('div', {}, h('button', { class: 'btn primary', onclick: function () {
        api('PUT', '/api/projects/' + S.project.id + '/tracking/' + S.source, { appId: x.appId, owner: owner.value, status: status.value, wave: wave.value, note: note.value })
          .then(function () { toast('Saved'); return loadAnalysis(); }).then(render).catch(fail); } }, 'Save')));
  }

  // ---- waves ---------------------------------------------------------------------------------
  function tabWaves() {
    var a = S.analysis, max = Math.max.apply(null, a.waves.map(function (w) { return w.apps; }).concat([1]));
    return h('div', { class: 'stack' },
      a.summary.effortCalibrated ? null : h('div', { class: 'note warn' }, 'Effort days use placeholder values per tier. Calibrate them under Settings before quoting.'),
      h('div', { class: 'card pad0' }, table([
        { title: 'Wave', cell: function (w) { return chip(w.wave, w.wave === 'R' ? '' : 'accent'); } },
        { title: 'Content', key: 'name' },
        { title: 'Apps', num: true, key: 'apps' },
        { title: 'Low / medium / high', cell: function (w) {
          var t = h('div', { class: 'bartrack', title: w.low + ' low, ' + w.medium + ' medium, ' + w.high + ' high' });
          [['low', w.low], ['med', w.medium], ['hi', w.high]].forEach(function (p) { var i = h('i', { class: p[0] }); i.style.width = (100 * p[1] / max) + '%'; t.appendChild(i); });
          return h('div', {}, t, h('div', { class: 'sub' }, w.low + ' / ' + w.medium + ' / ' + w.high)); } },
        { title: 'Critical', num: true, key: 'critical' },
        { title: 'Effort, days', num: true, key: 'effortDays' },
        { title: 'Closed', num: true, cell: function (w) { return w.done + ' of ' + w.apps; } }
      ], a.waves, { onrow: function (w) { S.filter.wave = w.wave; S.tab = 'apps'; render(); } })),
      h('div', { class: 'note' }, 'Order inside a wave: low score first; critical apps never first. Wave 7 (APIs and their clients) is planned from the Inventory > APIs table. Click a wave to see its applications.'));
  }

  // ---- inventory -----------------------------------------------------------------------------
  function tabInventory() {
    var a = S.analysis, t = a.tables, idn = a.identity;
    var defs = [['policies', 'Policies', t.policies.length], ['mfaMethods', 'MFA methods', t.mfaMethods.length], ['identities', 'Identities', null], ['groupRules', 'Group rules', t.groupRules.length],
                ['automations', 'Automations', t.automations.length], ['apis', 'APIs', t.apis.length], ['federation', 'Federation', t.federation.length], ['userStores', 'User stores', t.userStores.length], ['zones', 'Zones', t.zones.length]];
    var body;
    if (S.inv === 'policies') {
      body = h('div', { class: 'stack' }, h('div', { class: 'note' }, 'This is the parity checklist. Every row gets a Conditional Access equivalent or a recorded decision to drop it. It is signed at G2.'),
        h('div', { class: 'card pad0' }, table([
          { title: 'Policy / rule', wrap: true, cell: function (r) { return h('div', {}, h('b', {}, r.policy), r.status !== 'ACTIVE' ? h('span', {}, ' ', chip('inactive')) : null, h('div', { class: 'sub' }, r.policyType + (r.rule ? ' · ' + r.rule : ''))); } },
          { title: 'Conditions', wrap: true, key: 'conditions' },
          { title: 'Authentication', cell: function (r) { var weak = ['No MFA', '1FA', 'MFA only if enrolled'].indexOf(r.authentication) >= 0 && r.access !== 'DENY'; return h('div', {}, r.access === 'DENY' ? chip('DENY', 'Blocker') : null, r.authentication ? chip(r.authentication, weak ? 'High' : '') : null, r.session ? h('div', { class: 'sub' }, r.session) : null); } },
          { title: 'Conditional Access building blocks', wrap: true, cell: function (r) { return h('div', {}, r.conditionalAccessBuildingBlocks, r.reviewNote ? h('div', { class: 'sub' }, r.reviewNote) : null); } },
          { title: 'Parity', cell: function (r) {
            var sel = h('select', { 'aria-label': 'Parity decision', onchange: function () { saveCheck('policy', [r.policyType, r.policy, r.rule].join('|'), { parity: sel.value }); r.parity = sel.value; } },
              a.parityValues.map(function (v) { return h('option', { value: v, selected: v === r.parity }, v || 'Not decided'); }));
            var dec = h('input', { type: 'text', value: r.decision, placeholder: 'Decision or Entra policy name', 'aria-label': 'Decision', onchange: function () { saveCheck('policy', [r.policyType, r.policy, r.rule].join('|'), { decision: dec.value }); } });
            dec.style.marginTop = '4px'; sel.style.minWidth = '130px';
            return h('div', {}, sel, dec); } }
        ], t.policies, { empty: 'No policy read from this platform.' })));
    } else if (S.inv === 'identities') {
      body = h('div', { class: 'stack' },
        idn.known ? h('div', { class: 'stats' }, stat(idn.total, 'Users'), stat(idn.active, 'Active'), stat(idn.localPasswordActive, 'Platform-only passwords'),
          stat(idn.staleActive == null ? 'n/a' : idn.staleActive, 'Stale, ' + idn.staleDays + ' days'), stat(idn.neverSignedInActive == null ? 'n/a' : idn.neverSignedInActive, 'Never signed in'))
          : h('div', { class: 'note' }, idn.note),
        idn.known ? h('div', { class: 'card' }, h('h3', {}, 'Active users by source'), h('div', { class: 'chips' }, Object.keys(idn.activeBySource).map(function (k) { return chip(k + ' ' + idn.activeBySource[k]); })), idn.note ? h('p', { class: 'muted small' }, idn.note) : null) : null,
        a.factorSummary ? h('div', { class: 'card' }, h('h3', {}, 'Enrolled factors'), h('div', {}, a.factorSummary.usersChecked + ' users checked: ' + a.factorSummary.usersWithoutFactor + ' without any factor, ' + a.factorSummary.usersWithPhishingResistantFactor + ' with a phishing-resistant factor.')) : null,
        h('div', { class: 'card pad0' }, h('div', { class: 'row' }, h('h3', {}, 'Users without a clear Entra match (' + a.unmatched.length + ')')),
          table([{ title: 'Login', key: 'login' }, { title: 'Mail', key: 'email' }, { title: 'Status', key: 'status' }, { title: 'Source', key: 'source' }, { title: 'Reason', key: 'reason' }], a.unmatched.slice(0, 300),
            { empty: a.identity.matching ? 'Every user has a match.' : 'Collect the target tenant to match identities.' })));
      body.querySelector('.card.pad0 > .row').style.padding = '12px 14px 0';
    } else {
      var cols = { mfaMethods: [['method', 'Method'], ['status', 'Status'], ['entraTarget', 'Entra target'], ['migrationClass', 'Class']],
        groupRules: [['rule', 'Rule'], ['status', 'Status'], ['expression', 'Expression'], ['target', 'Target'], ['translation', 'Translation'], ['suggestedDynamicMembershipRule', 'Suggested dynamic rule'], ['reviewNote', 'Note']],
        automations: [['kind', 'Kind'], ['name', 'Name'], ['status', 'Status'], ['detail', 'Detail'], ['owner', 'Owner'], ['migrationClass', 'Class'], ['entraTarget', 'Entra target']],
        apis: [['name', 'Name'], ['status', 'Status'], ['detail', 'Detail'], ['migrationClass', 'Class'], ['note', 'Note']],
        federation: [['name', 'Name'], ['type', 'Type'], ['status', 'Status'], ['detail', 'Detail']],
        userStores: [['name', 'Name'], ['type', 'Type'], ['detail', 'Detail'], ['entraTarget', 'Entra target'], ['migrationClass', 'Class']],
        zones: [['zone', 'Zone'], ['type', 'Type'], ['usage', 'Usage'], ['status', 'Status'], ['entries', 'Entries'], ['usedByRules', 'Used by rules'], ['entraTarget', 'Entra target']] }[S.inv];
      body = h('div', { class: 'card pad0' }, table(cols.map(function (c) {
        return { title: c[1], wrap: true, cell: function (r) { return c[0] === 'migrationClass' ? chip(r[c[0]], r[c[0]] === 'Gap' ? 'Blocker' : r[c[0]] === 'Rebuild' ? 'Medium' : '') : (r[c[0]] == null ? '' : String(r[c[0]])); } }; }), t[S.inv], { empty: 'Nothing of this kind on this platform.' }));
    }
    return h('div', { class: 'stack' }, h('div', { class: 'seg' }, defs.map(function (d) {
      return h('button', { class: S.inv === d[0] ? 'on' : '', onclick: function () { S.inv = d[0]; render(); } }, d[1] + (d[2] != null ? ' ' + d[2] : '')); })), body);
  }
  function saveCheck(kind, id, patch) {
    patch.kind = kind; patch.id = id;
    return api('PUT', '/api/projects/' + S.project.id + '/checks/' + S.source, patch).then(function () { toast('Saved'); }).catch(fail);
  }

  // ---- manual checks -------------------------------------------------------------------------
  function tabManual() {
    var rows = S.analysis.tables.manualChecks;
    return h('div', { class: 'stack' }, h('div', { class: 'note' }, 'The platform API does not expose these. Capture them by hand before G1; the parity check is incomplete without them.'),
      rows.map(function (m) {
        var ans = h('textarea', { 'aria-label': 'Answer for ' + m.item, placeholder: 'What was found, with a pointer to the evidence' }); ans.value = m.answer || ''; ans.style.fontFamily = 'inherit'; ans.style.fontSize = '13px';
        var done = h('input', { type: 'checkbox', checked: m.done });
        return h('div', { class: 'card stack' }, h('label', { class: 'check' }, done, h('span', {}, h('b', {}, m.item), h('div', { class: 'muted small' }, m.why + ' Where: ' + m.where))), ans,
          h('div', {}, h('button', { class: 'btn', onclick: function () { saveCheck('manual', m.item, { done: done.checked, answer: ans.value }).then(function () { m.done = done.checked; m.answer = ans.value; render(); }); } }, 'Save')));
      }));
  }

  // ---- settings ------------------------------------------------------------------------------
  function tabSettings() {
    var p = S.project;
    var name = h('input', { type: 'text', value: p.name }), client = h('input', { type: 'text', value: p.client }), desc = h('input', { type: 'text', value: p.description });
    var scoring = h('textarea', { spellcheck: 'false', 'aria-label': 'Scoring overrides' }); scoring.value = JSON.stringify(p.scoring || {}, null, 2); scoring.style.minHeight = '140px';
    var defaults = h('textarea', { readonly: true, 'aria-label': 'Default scoring' }); defaults.value = JSON.stringify(p.scoringDefaults, null, 2); defaults.style.minHeight = '140px';
    var auditBox = h('div', { class: 'card pad0' }, h('div', { class: 'empty' }, 'Loading'));
    api('GET', '/api/projects/' + p.id + '/audit').then(function (rows) {
      auditBox.textContent = '';
      auditBox.appendChild(table([{ title: 'Time (UTC)', cell: function (r) { return when(r.ts); } }, { title: 'Action', key: 'action' }, { title: 'Detail', key: 'detail', wrap: true }], rows));
    }).catch(fail);
    return h('div', { class: 'stack' },
      h('div', { class: 'card stack' }, h('h2', {}, 'Project'), h('div', { class: 'form-grid' }, field('Name', name), field('Client', client), h('div', { class: 'wide' }, field('Note', desc))),
        h('div', {}, h('button', { class: 'btn primary', onclick: function () { api('PATCH', '/api/projects/' + p.id, { name: name.value, client: client.value, description: desc.value }).then(function () { toast('Saved'); refresh(); }).catch(fail); } }, 'Save'))),
      h('div', { class: 'card stack' }, h('h2', {}, 'Scoring and effort model'), h('div', { class: 'muted' }, 'Overrides for this project, as JSON with the same keys as the defaults. Saving re-runs the analysis. Set effortDays.calibrated to true once the day values come from real engagements.'),
        h('div', { class: 'form-grid' }, field('Overrides', scoring), field('Defaults (read-only)', defaults)),
        h('div', {}, h('button', { class: 'btn primary', onclick: function () {
          var val; try { val = JSON.parse(scoring.value || '{}'); } catch (e) { return toast('Not valid JSON', true); }
          api('PATCH', '/api/projects/' + p.id, { scoring: val }).then(function () { toast('Saved and re-analysed'); refresh(); }).catch(fail); } }, 'Save and re-analyse'))),
      h('h2', {}, 'Audit trail'), auditBox,
      h('div', { class: 'card stack' }, h('h2', {}, 'Delete project'), h('div', { class: 'muted' }, 'Deletes connectors, credentials, snapshots, analyses and decisions, and destroys the project key.'),
        h('div', {}, h('button', { class: 'btn danger', onclick: function () {
          var conf = h('input', { type: 'text' });
          var d = dialog('Delete project', h('div', { class: 'stack' }, h('div', {}, 'Type the project name "' + p.name + '" to confirm.'), conf),
            [h('button', { class: 'btn danger', onclick: function () { api('DELETE', '/api/projects/' + p.id, { confirm: conf.value }).then(function () { d.remove(); toast('Project deleted'); enter(); }).catch(fail); } }, 'Delete for good')]); } }, 'Delete project'))));
  }

  boot();
})();
