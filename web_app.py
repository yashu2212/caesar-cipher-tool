# web_app.py
from flask import Flask, request, render_template_string, send_file, url_for
import os, tempfile
from werkzeug.utils import secure_filename
from core import (
    caesar_shift, caesar_decrypt, caesar_bruteforce, caesar_auto,
    vigenere_encrypt, vigenere_decrypt, atbash, rot13, b64_encode, b64_decode,
    aes_encrypt_text, aes_decrypt_text, aes_encrypt_file, aes_decrypt_file,
    universal_decode_candidates, common_word_score, english_score
)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.secret_key = os.urandom(24)

DEMO_IMAGE_PATH = "/mnt/data/e2fe3d5a-d818-4072-8674-de311546d7ee.png"

TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cipher Suite — Mega</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
:root{ --accent:#1565d8; --muted:#f1f5f9; }
body { background: var(--muted); transition: background .25s ease; padding-bottom:40px; }
.sidebar { width:220px; position:fixed; left:0; top:0; bottom:0; background:white; box-shadow:2px 0 8px rgba(0,0,0,0.06); padding:18px; }
.content { margin-left:240px; padding:20px; }
.logo { height:64px; width:100%; object-fit:cover; border-radius:6px; }
.card-anim { transition: transform .22s cubic-bezier(.2,.8,.2,1), box-shadow .22s; }
.card-anim:hover { transform: translateY(-6px); box-shadow:0 10px 30px rgba(0,0,0,0.09); }
.fade-in { animation: fadeIn .35s ease; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(6px);} to { opacity:1; transform:none; } }
.result-box { white-space: pre-wrap; font-family: monospace; background:#eaf6ff; padding:12px; border-radius:6px; }
.small-muted { color:#556; font-size:0.9rem; }
.top-control { position:fixed; right:18px; top:12px; z-index:1000; }
</style>
</head>
<body>
  <div class="sidebar">
    <h5>🔐 Cipher Suite</h5>
    <img src="{{ demo_image }}" class="logo mb-3" alt="demo">
    <nav class="nav flex-column">
      <a class="nav-link" href="/">Encode</a>
      <a class="nav-link" href="/decode">Decode</a>
      <a class="nav-link" href="/bruteforce">Brute Force</a>
      <a class="nav-link" href="/vigenere">Vigenère</a>
      <a class="nav-link" href="/base64">Base64</a>
      <a class="nav-link" href="/aes">AES Text</a>
      <a class="nav-link" href="/files">Files</a>
      <a class="nav-link" href="/universal">Universal Decoder</a>
    </nav>
    <div class="small-muted mt-3">Tip: leave shift empty to auto-detect (use Brute Force or Universal)</div>
  </div>

  <div class="top-control">
    <button class="btn btn-sm btn-primary" onclick="document.body.classList.toggle('bg-dark'); document.body.classList.toggle('text-white')">Toggle Dark</button>
  </div>

  <div class="content">
    <div class="card card-anim fade-in p-4">
      <h3>{{ title }}</h3>
      <div class="mt-3">
        {{ body|safe }}
      </div>
    </div>

    {% if result %}
    <div class="card mt-3 p-3 card-anim">
      <h5>Result</h5>
      <div class="result-box">{{ result }}</div>
    </div>
    {% endif %}
  </div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

def render_page(title: str, body_html: str, result: str=None):
    return render_template_string(TEMPLATE, title=title, body=body_html, result=result, demo_image=DEMO_IMAGE_PATH)

# Routes (same as before, cleaned)
@app.route("/", methods=["GET","POST"])
def encode():
    result = None
    body = """
    <form method="post">
      <label class="form-label">Enter Text</label>
      <textarea name="text" class="form-control" rows="4">{{ request.form.get('text','') }}</textarea>
      <label class="form-label mt-2">Shift (for Caesar, optional)</label>
      <input name="shift" class="form-control" placeholder="e.g. 13" value="{{ request.form.get('shift','') }}">
      <label class="form-label mt-2">Vigenère key (optional)</label>
      <input name="key" class="form-control" placeholder="key for Vigenère">
      <div class="mt-3">
        <button class="btn btn-primary" name="action" value="caesar_enc">Caesar Encode</button>
        <button class="btn btn-secondary" name="action" value="vigenere_enc">Vigenère Encode</button>
      </div>
    </form>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        action = request.form.get("action","")
        if action == "caesar_enc":
            try:
                s = int(request.form.get("shift","0") or 0)
            except:
                s = 0
            result = caesar_shift(text, s)
        elif action == "vigenere_enc":
            key = request.form.get("key","")
            if not key:
                result = "Vigenère key missing"
            else:
                result = vigenere_encrypt(text, key)
    return render_page("Encode Text", body, result)

@app.route("/decode", methods=["GET","POST"])
def decode():
    result = None
    body = """
    <form method="post">
      <label>Enter Text</label>
      <textarea name="text" class="form-control" rows="4">{{ request.form.get('text','') }}</textarea>
      <label class="form-label mt-2">Shift (for Caesar, optional)</label>
      <input name="shift" class="form-control" placeholder="leave empty to use brute/universal">
      <label class="form-label mt-2">Vigenère key (for Vigenère decode)</label>
      <input name="vkey" class="form-control" placeholder="key for Vigenère">
      <div class="mt-3">
        <button class="btn btn-primary" name="action" value="caesar_dec">Caesar Decode</button>
        <button class="btn btn-secondary" name="action" value="vigenere_dec">Vigenère Decode</button>
        <button class="btn btn-outline-secondary" name="action" value="rot13">ROT13</button>
      </div>
    </form>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        action = request.form.get("action","")
        if action == "caesar_dec":
            s_raw = request.form.get("shift","").strip()
            if s_raw == "":
                s, candidate = caesar_auto(text)
                result = f"Auto shift {s} -> {candidate}"
            else:
                try:
                    s = int(s_raw)
                    result = caesar_decrypt(text, s)
                except:
                    result = "Invalid shift"
        elif action == "vigenere_dec":
            key = request.form.get("vkey","")
            if not key:
                result = "Vigenère key required"
            else:
                result = vigenere_decrypt(text, key)
        elif action == "rot13":
            result = rot13(text)
    return render_page("Decode Text", body, result)

@app.route("/bruteforce", methods=["GET","POST"])
def bruteforce():
    result = None
    body = """
    <form method="post">
      <label>Enter Ciphertext</label>
      <textarea name="text" class="form-control" rows="4">{{ request.form.get('text','') }}</textarea>
      <div class="mt-3">
        <button class="btn btn-primary">Run Brute Force</button>
      </div>
    </form>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        brute = caesar_bruteforce(text)
        lines = []
        scored = [(s, brute[s], common_word_score(brute[s])) for s in brute]
        scored.sort(key=lambda x: (-x[2], x[0]))
        for s,c,sc in scored:
            lines.append(f"Shift {s}: {c}    (score {sc})")
        result = "\n".join(lines)
    return render_page("Brute Force", body, result)

@app.route("/vigenere", methods=["GET","POST"])
def vigenere_page():
    result = None
    body = """
    <form method="post">
      <label>Text</label>
      <textarea name="text" class="form-control" rows="3">{{ request.form.get('text','') }}</textarea>
      <label>Key</label>
      <input name="key" class="form-control" value="{{ request.form.get('key','') }}">
      <div class="mt-3">
        <button class="btn btn-primary" name="action" value="enc">Encrypt</button>
        <button class="btn btn-secondary" name="action" value="dec">Decrypt</button>
      </div>
    </form>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        key = request.form.get("key","")
        action = request.form.get("action","")
        if not key:
            result = "Key is required"
        else:
            result = vigenere_encrypt(text, key) if action == "enc" else vigenere_decrypt(text, key)
    return render_page("Vigenère Cipher", body, result)

@app.route("/base64", methods=["GET","POST"])
def base64_page():
    result = None
    body = """
    <form method="post">
      <label>Text / Base64</label>
      <textarea name="text" class="form-control" rows="3">{{ request.form.get('text','') }}</textarea>
      <div class="mt-3">
        <button class="btn btn-primary" name="action" value="enc">Encode</button>
        <button class="btn btn-secondary" name="action" value="dec">Decode</button>
      </div>
    </form>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        action = request.form.get("action","")
        if action == "enc":
            result = b64_encode(text)
        else:
            dec = b64_decode(text)
            result = dec if dec is not None else "Invalid base64"
    return render_page("Base64", body, result)

@app.route("/aes", methods=["GET","POST"])
def aes_page():
    result = None
    body = """
    <form method="post">
      <label>Text</label>
      <textarea name="text" class="form-control" rows="3">{{ request.form.get('text','') }}</textarea>
      <label>Password</label>
      <input name="pwd" class="form-control">
      <div class="mt-3">
        <button class="btn btn-primary" name="action" value="enc">Encrypt</button>
        <button class="btn btn-warning" name="action" value="dec">Decrypt</button>
      </div>
    </form>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        pwd = request.form.get("pwd","")
        action = request.form.get("action","")
        if not pwd:
            result = "Password required"
        else:
            if action == "enc":
                result = aes_encrypt_text(text, pwd)
            else:
                dec = aes_decrypt_text(text, pwd)
                result = dec if dec is not None else "Decryption failed (invalid key/payload)"
    return render_page("AES Text (password)", body, result)

@app.route("/files", methods=["GET","POST"])
def files():
    result = None
    body = """
    <form method="post" enctype="multipart/form-data">
      <label>Choose file</label>
      <input type="file" name="file" class="form-control">
      <label>Password</label>
      <input name="pwd" class="form-control">
      <div class="mt-3">
        <button class="btn btn-primary" name="action" value="enc">Encrypt File</button>
        <button class="btn btn-warning" name="action" value="dec">Decrypt File</button>
      </div>
    </form>
    """
    if request.method == "POST":
        f = request.files.get("file")
        pwd = request.form.get("pwd","")
        action = request.form.get("action","")
        if not f:
            result = "No file uploaded"
        elif not pwd:
            result = "Password required"
        else:
            fname = secure_filename(f.filename)
            inpath = os.path.join(app.config['UPLOAD_FOLDER'], f"mc_{os.getpid()}_{fname}")
            f.save(inpath)
            try:
                if action == "enc":
                    out = aes_encrypt_file(inpath, pwd)
                    result = f"Encrypted → {out}"
                else:
                    out = aes_decrypt_file(inpath, pwd)
                    result = f"Decrypted → {out}"
            except Exception as e:
                result = f"Error: {e}"
    return render_page("File Tools", body, result)

@app.route("/universal", methods=["GET","POST"])
def universal():
    result = None
    body = """
    <form method="post">
      <label>Enter Cipher / Text (Universal Decoder will try many methods)</label>
      <textarea name="text" class="form-control" rows="4">{{ request.form.get('text','') }}</textarea>
      <div class="mt-3">
        <button class="btn btn-primary">Run Universal Decoder</button>
      </div>
    </form>
    <div class="mt-2 small-muted">It will try: base64, hex, binary, url-decode, ROT13, atbash, Caesar brute force and rank candidates.</div>
    """
    if request.method == "POST":
        text = request.form.get("text","")
        cand = universal_decode_candidates(text, top_n=8)
        lines = []
        for method, txt, score in cand:
            lines.append(f"[{method}] (score {score})\n{txt}\n{'-'*40}")
        result = "\n".join(lines)
    return render_page("Universal Decoder", body, result)

if __name__ == "__main__":
    print("Running Cipher Suite on http://127.0.0.1:5000")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=False,
        use_reloader=False
    )

