// Minimal server-rendered HTML. Every interpolated value goes through esc().

export function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title)}</title>
<style>
  :root { color-scheme: light dark; --bg:#f7f7f8; --card:#fff; --fg:#1f2328; --muted:#59636e; --accent:#1f6feb; --border:#d1d9e0; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0d1117; --card:#161b22; --fg:#e6edf3; --muted:#9198a1; --accent:#4493f8; --border:#30363d; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px;
         background:var(--bg); color:var(--fg); font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
  main { width:100%; max-width:380px; background:var(--card); border:1px solid var(--border); border-radius:12px; padding:32px 28px; text-align:center; }
  h1 { font-size:1.25rem; margin:0 0 8px; }
  p { color:var(--muted); margin:0 0 24px; }
  a.button { display:block; padding:10px 16px; border-radius:8px; background:var(--accent); color:#fff; text-decoration:none; font-weight:600; }
  a.button:focus-visible { outline:3px solid var(--fg); outline-offset:2px; }
  a.secondary { display:inline-block; margin-top:16px; color:var(--accent); }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

export function loginPage(startHref: string, providerName: string, notice?: string): string {
  return layout(
    'Sign in',
    `<h1>Sign in</h1>
<p>${notice ? esc(notice) : 'Use your work account to continue.'}</p>
<a class="button" href="${esc(startHref)}">Sign in with ${esc(providerName)}</a>`,
  );
}

export function errorPage(heading: string, message: string, retryHref = '/sso/login'): string {
  return layout(
    heading,
    `<h1>${esc(heading)}</h1>
<p>${esc(message)}</p>
<a class="secondary" href="${esc(retryHref)}">Back to sign in</a>`,
  );
}
