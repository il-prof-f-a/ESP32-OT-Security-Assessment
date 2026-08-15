/* auto-generated from login.html */
#pragma once
static const char* LOGIN_HTML_GEN = R"HTML(
<!doctype html>
<html>
    <head><meta charset='utf-8'><title>Login - ESP32 OT Security</title>
<style>
body{font-family:system-ui;background:#f6f6f6;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
form{background:#fff;padding:1.2rem;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.1);margin-bottom:1rem}
input{display:block;margin:.5rem 0;padding:.6rem;border:1px solid #ccc;border-radius:8px;width:16rem}
.btn{background:#0a7;color:#fff;border:none;padding:.6rem 1rem;border-radius:8px;cursor:pointer;width:100%}
.debug{background:#333;color:#0f0;padding:1rem;border-radius:8px;font-family:monospace;white-space:pre-wrap;max-width:600px;font-size:12px}
</style>
</head>
<body>
    <form method=POST action=/login>
    <h3>🔐 Login</h3>
    <input type=password name=p placeholder='Password admin'>
    <button class=btn>Entra</button>
    </form>
</body>
</html>
)HTML";

// Compile-time size constant (actual content length)
static constexpr size_t LOGIN_HTML_GEN_SIZE = 931;
