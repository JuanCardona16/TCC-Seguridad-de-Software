//! Vistas HTML. Sin motor de plantillas a propósito: el escape de salida queda
//! explícito en cada punto de interpolación, que es justo lo que este trabajo
//! necesita demostrar (A03: XSS por salida sin sanitizar en v1).

use axum::response::Html;

use crate::session::SessionUser;
use crate::state::Mode;

const STYLE: &str = r#"
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#30363d;--txt:#e6edf3;--muted:#8b949e;--acc:#58a6ff;--bad:#f85149;--warn:#d29922;--ok:#3fb950}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--txt)}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:980px;margin:0 auto;padding:0 20px 60px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);margin-bottom:26px}
header.top .wrap{padding:14px 20px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.brand{font-weight:700;letter-spacing:.3px}
.brand small{color:var(--muted);font-weight:400;margin-left:8px}
nav{display:flex;gap:14px;flex-wrap:wrap;margin-left:auto;font-size:14px}
nav .who{color:var(--muted)}
.banner{padding:10px 20px;font:600 13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.2px}
.banner.bad{background:#3d1114;color:#ffb3ae;border-bottom:1px solid var(--bad)}
.banner.ok{background:#0f2f1b;color:#9ae6b4;border-bottom:1px solid var(--ok)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:18px}
h1{font-size:22px;margin:0 0 14px}h2{font-size:17px;margin:22px 0 10px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.6px}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 5px}
input,textarea,select{width:100%;padding:9px 11px;background:#0b0f14;border:1px solid var(--line);border-radius:7px;color:var(--txt);font:inherit}
input[type=file]{padding:7px}
button{margin-top:16px;padding:10px 18px;border:0;border-radius:7px;background:var(--acc);color:#04121f;font:600 14px/1 inherit;cursor:pointer}
button.ghost{background:transparent;color:var(--acc);border:1px solid var(--line)}
.tag{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.4px;text-transform:uppercase}
.tag.confidencial{background:#4a1d1f;color:#ffb3ae}
.tag.sensible{background:#4a3410;color:#f5d78e}
.tag.publico,.tag.interno{background:#1b2b40;color:#a3c9f7}
.err{background:#3d1114;border:1px solid var(--bad);color:#ffb3ae;padding:10px 13px;border-radius:7px;margin-bottom:14px;font-size:14px}
.note{color:var(--muted);font-size:13px}
pre{background:#0b0f14;border:1px solid var(--line);border-radius:8px;padding:14px;overflow:auto;font-size:13px;line-height:1.5;white-space:pre-wrap}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;background:#0b0f14;padding:1px 5px;border-radius:4px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.kv{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px}
.kv b{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px}
footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px;margin-top:36px}
.secret{font-family:ui-monospace,monospace;font-size:20px;letter-spacing:3px;color:var(--ok)}
"#;

pub struct DocRow {
    pub id: i64,
    pub title: String,
    pub filename: String,
    pub owner: String,
    pub classification: String,
    pub size_bytes: i64,
}

pub fn esc(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Único punto de decisión del escape de salida.
/// v1 devuelve el valor crudo (XSS); v2 lo escapa (mitigación).
pub fn interp(mode: Mode, value: &str) -> String {
    match mode {
        Mode::Vulnerable => value.to_string(),
        Mode::Hardened => esc(value),
    }
}

pub fn page(mode: Mode, title: &str, user: Option<&SessionUser>, body: &str) -> Html<String> {
    let banner = if mode.is_hardened() {
        r#"<div class="banner ok">MODO ENDURECIDO · Argon2id · AES-256-GCM · sesión firmada · RBAC verificado en servidor · CSP</div>"#
    } else {
        r#"<div class="banner bad">MODO VULNERABLE · laboratorio local (127.0.0.1) · los defectos son intencionales</div>"#
    };

    let nav = match user {
        None => r#"<nav><a href="/login">Ingresar</a></nav>"#.to_string(),
        Some(u) => {
            let admin_link = if u.is_admin() {
                r#"<a href="/admin/users">Usuarios</a><a href="/admin/audit">Auditoría</a>"#
            } else {
                ""
            };
            format!(
                r#"<nav><a href="/dashboard">Panel</a><a href="/search">Buscar</a><a href="/docs">Subir</a><a href="/account/2fa">2FA</a>{admin_link}<span class="who">{}</span><form method="post" action="/logout" style="display:inline"><button class="ghost" style="margin:0;padding:2px 10px;font-size:12px">Salir</button></form></nav>"#,
                esc(&u.username)
            )
        }
    };

    Html(format!(
        r#"<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · MiniGestor Documental</title>
<style>{STYLE}</style>
</head>
<body>
{banner}
<header class="top"><div class="wrap"><span class="brand">MiniGestor<small>Documental · laboratorio de seguridad</small></span>{nav}</div></header>
<main class="wrap">
{body}
<footer>MiniGestor Documental · TCC Seguridad Informática 2026-2 · datos simulados, sin información real · modo: {label}</footer>
</main>
</body>
</html>"#,
        title = esc(title),
        label = mode.label(),
    ))
}

pub fn login_page(mode: Mode, error: Option<&str>, username: &str) -> Html<String> {
    let error_html = match error {
        Some(msg) => format!(r#"<div class="err">{}</div>"#, esc(msg)),
        None => String::new(),
    };
    let totp_field = if mode.is_hardened() {
        r#"<label for="code">Código 2FA (solo si tu cuenta lo tiene activo)</label>
           <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456">"#
    } else {
        ""
    };

    let body = format!(
        r#"<div class="card" style="max-width:420px;margin:0 auto">
<h1>Ingresar</h1>
{error_html}
<form method="post" action="/login">
<label for="username">Usuario</label><input id="username" name="username" value="{username}" autocomplete="username" required>
<label for="password">Contraseña</label><input id="password" name="password" type="password" autocomplete="current-password" required>
{totp_field}
<button type="submit">Entrar</button>
</form>
<p class="note" style="margin-top:18px">Credenciales demo del laboratorio: <code>admin / admin123</code> · <code>alice / alice123</code> · <code>bob / bob123</code></p>
</div>"#,
        username = esc(username),
    );
    page(mode, "Ingresar", None, &body)
}

pub fn dashboard_page(
    mode: Mode,
    user: &SessionUser,
    docs: &[DocRow],
    show_owner: bool,
) -> Html<String> {
    let mut rows = String::new();
    if docs.is_empty() {
        rows.push_str(r#"<tr><td colspan="5" class="note">Todavía no hay documentos.</td></tr>"#);
    }
    for doc in docs {
        let owner_cell = if show_owner {
            format!("<td>{}</td>", esc(&doc.owner))
        } else {
            String::new()
        };
        rows.push_str(&format!(
            r#"<tr><td><a href="/docs/{id}">{title}</a></td>{owner_cell}<td><span class="tag {cls}">{cls}</span></td><td>{size} B</td><td><a href="/docs/{id}/download">Descargar</a></td></tr>"#,
            id = doc.id,
            // v1 interpola el título sin escapar: XSS almacenado.
            title = interp(mode, &doc.title),
            cls = esc(&doc.classification),
            size = doc.size_bytes,
        ));
    }

    let owner_header = if show_owner { "<th>Dueño</th>" } else { "" };
    let body = format!(
        r#"<div class="card">
<h1>Panel de {who}</h1>
<p class="note">Rol: <code>{role}</code> · documentos visibles: {count}</p>
<table><thead><tr><th>Documento</th>{owner_header}<th>Clasificación</th><th>Tamaño</th><th></th></tr></thead><tbody>{rows}</tbody></table>
<p style="margin-top:18px"><a href="/docs">Subir un documento</a> · <a href="/search">Buscar</a></p>
</div>"#,
        who = esc(&user.username),
        role = esc(&user.role),
        count = docs.len(),
    );
    page(mode, "Panel", Some(user), &body)
}

pub fn search_page(mode: Mode, user: &SessionUser, query: &str, docs: &[DocRow]) -> Html<String> {
    let mut rows = String::new();
    for doc in docs {
        rows.push_str(&format!(
            r#"<tr><td><a href="/docs/{id}">{title}</a></td><td>{owner}</td><td>{filename}</td></tr>"#,
            id = doc.id,
            title = interp(mode, &doc.title),
            owner = esc(&doc.owner),
            filename = interp(mode, &doc.filename),
        ));
    }
    if docs.is_empty() {
        rows.push_str(r#"<tr><td colspan="3" class="note">Sin resultados.</td></tr>"#);
    }

    let body = format!(
        r#"<div class="card">
<h1>Buscar documentos</h1>
<form method="get" action="/search">
<label for="q">Término</label>
<input id="q" name="q" value="{q}" placeholder="contrato, política, historia...">
<button type="submit">Buscar</button>
</form>
<p class="note">Resultados para: <b>{echo}</b> · {count} coincidencia(s)</p>
<table><thead><tr><th>Título</th><th>Dueño</th><th>Archivo</th></tr></thead><tbody>{rows}</tbody></table>
</div>"#,
        // v1 refleja el término sin escapar: XSS reflejado.
        q = interp(mode, query),
        echo = interp(mode, query),
        count = docs.len(),
    );
    page(mode, "Buscar", Some(user), &body)
}

pub fn upload_page(mode: Mode, user: &SessionUser, message: Option<&str>) -> Html<String> {
    let message_html = match message {
        Some(msg) => format!(r#"<div class="err">{}</div>"#, esc(msg)),
        None => String::new(),
    };
    let body = format!(
        r#"<div class="card">
<h1>Subir documento</h1>
{message_html}
<form method="post" action="/docs" enctype="multipart/form-data">
<label for="title">Título</label><input id="title" name="title" required maxlength="200">
<label for="file">Archivo</label><input id="file" name="file" type="file" required>
<button type="submit">Subir</button>
</form>
<p class="note">{policy}</p>
</div>"#,
        policy = if mode.is_hardened() {
            "Modo endurecido: se valida extensión y tamaño, el nombre real se descarta y el contenido se guarda cifrado con AES-256-GCM."
        } else {
            "Modo vulnerable: se acepta cualquier archivo y se guarda con el nombre que envía el cliente."
        }
    );
    page(mode, "Subir", Some(user), &body)
}

pub fn doc_page(
    mode: Mode,
    user: &SessionUser,
    doc: &DocRow,
    content_preview: &str,
) -> Html<String> {
    let body = format!(
        r#"<div class="card">
<h1>{title}</h1>
<div class="grid">
<div class="kv"><b>Dueño</b>{owner}</div>
<div class="kv"><b>Archivo</b>{filename}</div>
<div class="kv"><b>Clasificación</b><span class="tag {cls}">{cls}</span></div>
<div class="kv"><b>Tamaño</b>{size} B</div>
</div>
<h2>Contenido</h2>
<pre>{preview}</pre>
<p><a href="/docs/{id}/download">Descargar original</a> · <a href="/dashboard">Volver al panel</a></p>
</div>"#,
        title = interp(mode, &doc.title),
        owner = esc(&doc.owner),
        filename = interp(mode, &doc.filename),
        cls = esc(&doc.classification),
        size = doc.size_bytes,
        id = doc.id,
        preview = esc(content_preview),
    );
    page(mode, &doc.title, Some(user), &body)
}

pub fn notice_page(mode: Mode, user: Option<&SessionUser>, title: &str, message: &str) -> Html<String> {
    let body = format!(
        r#"<div class="card"><h1>{title}</h1><p>{message}</p><p style="margin-top:18px"><a href="/dashboard">Ir al panel</a> · <a href="/login">Ingresar</a></p></div>"#,
        title = esc(title),
        message = esc(message),
    );
    page(mode, title, user, &body)
}

pub fn users_page(mode: Mode, user: &SessionUser, rows: &[(String, String, i64, i64)]) -> Html<String> {
    let mut body_rows = String::new();
    for (username, role, docs, failed) in rows {
        body_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(username),
            esc(role),
            docs,
            failed
        ));
    }
    let body = format!(
        r#"<div class="card">
<h1>Usuarios</h1>
<table><thead><tr><th>Usuario</th><th>Rol</th><th>Documentos</th><th>Intentos fallidos</th></tr></thead><tbody>{body_rows}</tbody></table>
</div>"#
    );
    page(mode, "Usuarios", Some(user), &body)
}

pub fn audit_page(mode: Mode, user: &SessionUser, rows: &[(String, String, String, String, String)]) -> Html<String> {
    let mut body_rows = String::new();
    for (ts, actor, action, target, outcome) in rows {
        body_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(ts),
            esc(actor),
            esc(action),
            esc(target),
            esc(outcome)
        ));
    }
    if rows.is_empty() {
        body_rows.push_str(r#"<tr><td colspan="5" class="note">Sin eventos todavía.</td></tr>"#);
    }
    let body = format!(
        r#"<div class="card">
<h1>Auditoría</h1>
<p class="note">Últimos 50 eventos registrados por la aplicación.</p>
<table><thead><tr><th>Fecha</th><th>Actor</th><th>Acción</th><th>Objetivo</th><th>Resultado</th></tr></thead><tbody>{body_rows}</tbody></table>
</div>"#
    );
    page(mode, "Auditoría", Some(user), &body)
}

pub fn twofa_page(
    mode: Mode,
    user: &SessionUser,
    enabled: bool,
    secret: Option<&str>,
    current_code: Option<u32>,
) -> Html<String> {
    let body = if !mode.is_hardened() {
        r#"<div class="card"><h1>Segundo factor</h1><p class="note">El modo vulnerable no implementa 2FA. Cambiá a modo endurecido para verlo.</p></div>"#.to_string()
    } else {
        let secret_block = match secret {
            Some(s) => format!(
                r#"<h2>Tu secreto TOTP</h2>
<p class="note">Base32 (equivalente al QR de enrolamiento). En un despliegue real se muestra una sola vez.</p>
<p class="secret">{}</p>
<p class="note">Código válido ahora: <b>{}</b> (cambia cada 30 s, RFC 6238)</p>"#,
                esc(s),
                current_code.map(|c| format!("{:06}", c)).unwrap_or_else(|| "------".to_string())
            ),
            None => String::new(),
        };
        let action = if enabled { "Desactivar" } else { "Activar" };
        format!(
            r#"<div class="card">
<h1>Segundo factor (TOTP)</h1>
<p class="note">Estado: <b>{state}</b></p>
{secret_block}
<form method="post" action="/account/2fa"><button type="submit">{action}</button></form>
</div>"#,
            state = if enabled { "activo" } else { "inactivo" },
        )
    };
    page(mode, "Segundo factor", Some(user), &body)
}
