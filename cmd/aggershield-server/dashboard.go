package main

// dashboardHTML is the server-rendered admin panel. No JS framework — plain
// HTML + inline CSS, with POST forms for generate/revoke.
const dashboardHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AggerShield — Control Panel</title>
<style>
:root{--bg:#0f1115;--card:#181b22;--line:#272b34;--fg:#e6e8ec;--mut:#9aa3b2;--ok:#2ecc71;--bad:#e74c3c;--accent:#4ea1ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:20px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code{background:#0b0d11;border:1px solid var(--line);border-radius:6px;padding:2px 6px;font-family:ui-monospace,monospace}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.pill.ok{background:rgba(46,204,113,.15);color:var(--ok)}.pill.bad{background:rgba(231,76,60,.15);color:var(--bad)}
.pill.stale{background:rgba(241,196,15,.15);color:#f1c40f}
input,button{font:inherit}input{background:#0b0d11;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:7px 9px}
button{background:var(--accent);border:0;color:#04101f;font-weight:700;border-radius:6px;padding:7px 14px;cursor:pointer}
button.danger{background:transparent;border:1px solid var(--bad);color:var(--bad);font-weight:600}
form.inline{display:inline}.row-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.keybox{background:rgba(78,161,255,.1);border:1px solid var(--accent);border-radius:8px;padding:14px;margin-bottom:16px}
.mut{color:var(--mut)}.mono{font-family:ui-monospace,monospace}
</style></head>
<body><div class="wrap">
<form method="post" action="/admin/logout" style="float:right"><button class="danger" type="submit">Log out</button></form>
<h1>🛡️ AggerShield — Control Panel</h1>
<div class="sub">License keys, live agents, and where your protection is running. · {{.Now}}</div>

{{if .NewKey}}
<div class="keybox">
  <strong>New key for "{{.NewKeyName}}"</strong> — copy it now, it is shown only once:
  <div style="margin-top:8px"><code class="mono">{{.NewKey}}</code></div>
  <div class="mut" style="margin-top:8px">Give this key + the client script to the user. Configure their agent with
  <code>license.key</code> = this value.</div>
</div>
{{end}}

<div class="card">
  <strong>Issue a new key</strong>
  <form method="post" action="/admin/keys" class="row-form" style="margin-top:10px">
    <input name="name" placeholder="Customer / service name" required>
    <input name="note" placeholder="Note (optional)">
    <button type="submit">Generate key</button>
  </form>
</div>

<div class="card">
  <table>
    <thead><tr>
      <th>Name</th><th>Key ID</th><th>Status</th><th>Agent</th>
      <th>Protecting</th><th>Source IP</th><th>Last seen</th><th>Requests / Bans</th><th>Policy</th><th></th>
    </tr></thead>
    <tbody>
    {{range .Rows}}
      <tr>
        <td><strong>{{.Key.Name}}</strong>{{if .Key.Note}}<div class="mut">{{.Key.Note}}</div>{{end}}</td>
        <td class="mono mut">{{.Key.ID}}</td>
        <td>{{if .Key.Revoked}}<span class="pill bad">revoked</span>{{else}}<span class="pill ok">active</span>{{end}}</td>
        <td>{{if .Agent}}{{.Agent.Hostname}}<div class="mut mono">v{{.Agent.Version}}</div>{{else}}<span class="mut">— never connected</span>{{end}}</td>
        <td>{{if .Agent}}{{.Agent.Protecting}}{{end}}</td>
        <td class="mono">{{if .Agent}}{{.Agent.SourceIP}}{{end}}</td>
        <td>{{if .Agent}}{{if .Stale}}<span class="pill stale">{{since .Agent.LastSeen}}</span>{{else}}<span class="pill ok">{{since .Agent.LastSeen}}</span>{{end}}{{end}}</td>
        <td class="mono">{{stat .Agent "total_requests"}} / {{stat .Agent "bans_issued"}}</td>
        <td>
          <details>
            <summary class="mut">v{{.PolicyVersion}} · edit</summary>
            <form method="post" action="/admin/keys/policy" style="margin-top:8px">
              <input type="hidden" name="id" value="{{.Key.ID}}">
              <textarea name="policy" rows="8" cols="38" placeholder='{"dry_run":true}' class="mono"
                style="display:block;background:#0b0d11;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:8px;width:22rem">{{.PolicyJSON}}</textarea>
              <button type="submit" style="margin-top:6px">Push policy</button>
            </form>
          </details>
        </td>
        <td>{{if not .Key.Revoked}}
          <form class="inline" method="post" action="/admin/keys/revoke" onsubmit="return confirm('Revoke this key? The agent will stop serving.')">
            <input type="hidden" name="id" value="{{.Key.ID}}">
            <button class="danger" type="submit">Revoke</button>
          </form>
        {{end}}</td>
      </tr>
    {{else}}
      <tr><td colspan="10" class="mut">No keys yet — issue one above.</td></tr>
    {{end}}
    </tbody>
  </table>
</div>

<div class="card">
  <strong>Audit log</strong> <span class="mut">(20 most recent admin actions)</span>
  <table style="margin-top:10px">
    <thead><tr><th>Time (UTC)</th><th>Action</th><th>Target</th><th>Source IP</th></tr></thead>
    <tbody>
    {{range .Audit}}
      <tr>
        <td class="mono mut">{{.Time.Format "2006-01-02 15:04:05"}}</td>
        <td class="mono">{{.Action}}</td>
        <td>{{.Target}}</td>
        <td class="mono">{{.SourceIP}}</td>
      </tr>
    {{else}}
      <tr><td colspan="4" class="mut">No admin actions recorded yet.</td></tr>
    {{end}}
    </tbody>
  </table>
</div>
</div></body></html>`

// loginHTML is the admin login page (posts the token to set a session cookie).
const loginHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AggerShield — Sign in</title>
<style>
body{margin:0;background:#0f1115;color:#e6e8ec;font:14px/1.5 system-ui,sans-serif;
  display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{background:#181b22;border:1px solid #272b34;border-radius:12px;padding:28px;width:20rem}
h1{font-size:18px;margin:0 0 4px}.mut{color:#9aa3b2;font-size:13px;margin-bottom:18px}
input{width:100%;box-sizing:border-box;background:#0b0d11;border:1px solid #272b34;color:#e6e8ec;
  border-radius:8px;padding:10px;margin-bottom:12px}
button{width:100%;background:#4ea1ff;border:0;color:#04101f;font-weight:700;border-radius:8px;padding:10px;cursor:pointer}
</style></head>
<body><form class="box" method="post" action="/admin/login">
  <h1>🛡️ AggerShield</h1>
  <div class="mut">Enter the admin token to sign in.</div>
  <input type="password" name="token" placeholder="Admin token" autofocus required>
  <button type="submit">Sign in</button>
</form></body></html>`
