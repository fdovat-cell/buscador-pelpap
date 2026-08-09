// Protege TODO el sitio (HTML + carpeta fotos/) con una contraseña.
// Usa una cookie de sesion firmada con HMAC-SHA256, igual que el admin
// de Pelsas Papeleria. No se puede saltear editando el HTML/JS del
// navegador porque la verificacion pasa por este server-side function.
//
// Configuracion necesaria en Cloudflare Pages (una sola vez):
//   Settings -> Environment variables -> Add variable (marcar como "Secret")
//     PASSWORD    = la contraseña que vos elijas
//     SECRET_KEY  = una cadena random larga, solo para firmar la cookie
//                   (no es la contraseña, no hace falta que la recuerdes,
//                   solo tiene que ser larga y quedar guardada ahi)

async function hmacSha256Hex(key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function paginaLogin(error) {
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Acceso - Buscador</title>
<style>
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #16181d;
    color: #e6e8ec;
    font-family: -apple-system, 'Segoe UI', Roboto, Arial, sans-serif;
  }
  form {
    background: #1e2128;
    border: 1px solid #333744;
    border-radius: 10px;
    padding: 28px 26px;
    width: 100%;
    max-width: 300px;
  }
  h1 { font-size: 16px; margin: 0 0 18px; font-weight: 600; }
  input {
    width: 100%;
    background: #23262e;
    border: 1px solid #333744;
    color: #e6e8ec;
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 14px;
    box-sizing: border-box;
  }
  input:focus { outline: none; border-color: #2c6ea3; }
  button {
    width: 100%;
    margin-top: 12px;
    background: #2c6ea3;
    border: 1px solid #4fb0ff;
    color: #fff;
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 14px;
    cursor: pointer;
  }
  button:hover { background: #4fb0ff; }
  .error { color: #e0a63e; font-size: 13px; margin-top: 10px; }
</style>
</head>
<body>
  <form method="POST" action="/login">
    <h1>Ingresá la contraseña</h1>
    <input type="password" name="password" autofocus required>
    <button type="submit">Entrar</button>
    ${error ? `<div class="error">${error}</div>` : ""}
  </form>
</body>
</html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  const SECRET = env.SECRET_KEY;
  const PASSWORD = env.PASSWORD;

  // Login: recibe la contraseña por POST
  if (url.pathname === "/login" && request.method === "POST") {
    const form = await request.formData();
    const intento = (form.get("password") || "").toString();

    if (intento === PASSWORD) {
      const firma = await hmacSha256Hex(SECRET, "autorizado");
      const headers = new Headers();
      headers.append(
        "Set-Cookie",
        `session=${firma}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`
      );
      headers.append("Location", "/");
      return new Response(null, { status: 302, headers });
    }

    return new Response(paginaLogin("Contraseña incorrecta"), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=UTF-8" },
    });
  }

  // Cualquier otro request: valida la cookie de sesion
  const cookieFirma = getCookie(request, "session");
  const firmaEsperada = await hmacSha256Hex(SECRET, "autorizado");

  if (cookieFirma === firmaEsperada) {
    return next(); // autorizado, sigue a la pagina/foto pedida
  }

  return new Response(paginaLogin(""), {
    status: 401,
    headers: { "Content-Type": "text/html; charset=UTF-8" },
  });
}
