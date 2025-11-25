# web_app.py
from flask import Flask, request, render_template_string, send_file, url_for
import os, tempfile
from werkzeug.utils import secure_filename
from core import (
    caesar_shift, caesar_decrypt, caesar_bruteforce, caesar_auto,
    vigenere_encrypt, vigenere_decrypt, atbash, rot13,
    b64_encode, b64_decode,
    aes_encrypt_text, aes_decrypt_text,
    aes_encrypt_file, aes_decrypt_file,
    universal_decode_candidates, common_word_score
)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.secret_key = os.urandom(24)

# Clean UI template — NO LOGO, NO example text
TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Caesar Cipher Tool</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

<style>
:root { --accent:#1565d8; --muted:#f1f5f9; }
body { background: var(--muted); transition: 0.3s ease; padding-bottom:40px; }
.sidebar {
  width:220px; position:fixed; left:0; top:0; bottom:0;
  background:white; box-shadow:2px 0 8px rgba(0,0,0,0.06);
  padding:18px;
}
.content { margin-left:240px; padding:20px; }
.nav-link { font-size:16px; padding:6px 0; }
.card-anim { transition:0.25s; }
.card-anim:hover { transform:translateY(-4px); box-shadow:0 6px 20px rgba(0,0,0,0.1); }
.result-box {
  white-space:pre-wrap; font-family:monospace;
  background:#eaf6ff; padding:12px; border-radius:6px;
}
.top-control { position:fixed; right:18px; top:12px; z-index:1000; }
.dark-mode { background:#111 !important; color:white; }
.dark-mode .sidebar { background:#1a1a1a; color:white; }
.dark-mode .card { background:#222; color:white; }
.dark-mode .result-box { background:#333; color:white; }
</style>

</head>
<body>

<script>
function toggleDark(){
    document.body.classList.toggle("dark-mode");
    localStorage.setItem("dark", document.body.classList.contains("dark-mode"));
}
window.onload = () => {
    if(localStorage.getItem("dark") === "true"){
        document.body.classList.add("dark-mode");
    }
};
</script>

<div class="sidebar">
    <h5>🔐 Caesar Cipher Tool</h5>
    <nav class="nav flex-column mt-3">
      <a class="nav-link" href="/">Encode</a>
      <a class="nav-link" href="/decode">Decode</a>
      <a class="nav-link" href="/bruteforce">Brute Force</a>
      <a class="nav-link" href="/vigenere">Vigenère</a>
      <a class="nav-link" href="/base64">Base64</a>
      <a class="nav-link" href="/aes">AES Text</a>
      <a class="nav-link" href="/files">Files</a>
      <a class="nav-link" href="/universal">Universal Decoder</a>
    </nav>
</div>

<div class="top-control">
  <button class="btn btn-sm btn-primary" onclick="toggleDark()">Toggle Dark</button>
</div>

<div class="content">
  <div class="card card-anim p-4">
    <h3>{{ title }}</h3>
    <div class="mt-3">{{ body|safe }}</div>
  </div>

  {% if result %}
  <div class="card mt-3 p-3 card-anim">
    <h5>Result</h5>
    <div class="result-box">{{ result }}</div>
  </div>
  {% endif %}
</div>

</body>
</html>
"""

def render_page(title, body_html, result=None):
    return render_template_string(TEMPLATE, title=title, body=body_html, result=result)

# --------------------------------------------------------------------------
# ROUTES
# --------------------------------------------------------------------------

@app.route("/", methods=["GET","POST"])
def encode():
    result = None
    body = """
    <form method="post">

      <label class="form-label">Enter Text</label>
      <textarea name="text" class="form-control" rows="4"></textarea>

      <label class="form-label mt-3">Shift (optional)</label>
      <input name="shift" class="form-control">

      <label class="form-label mt-3">Vigenère Key (optional)</label>
      <input name="key" class="form-control">

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
            shift = request.form.get("shift","0")
            shift = int(shift) if shift.isdigit() else 0
            result = caesar_shift(text, shift)

        elif action == "vigenere_enc":
            key = request.form.get("key","")
            if not key:
                result = "Vigenère key needed"
            else:
                result = vigenere_encrypt(text, key)

    return render_page("Encode Text", body, result)


@app.route("/decode", methods=["GET","POST"])
def decode():
    result = None
    body = """
    <form method="post">

      <label>Enter Text</label>
      <textarea name="text" class="form-control" rows="4"></textarea>

      <label class="form-label mt-3">Shift (optional)</label>
      <input name="shift" class="form-control">

      <label class="form-label mt-3">Vigenère Key</label>
      <input name="vkey" class="form-control">

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
            sh = request.form.get("shift","")
            if sh.strip()=="":
                s, c = caesar_auto(text)
                result = f"Auto-shift {s} → {c}"
            else:
                try: result = caesar_decrypt(text, int(sh))
                except: result = "Invalid shift"

        elif action == "vigenere_dec":
            key = request.form.get("vkey","")
            result = vigenere_decrypt(text, key) if key else "Vigenère key required"

        elif action == "rot13":
            result = rot13(text)

    return render_page("Decode Text", body, result)


@app.route("/bruteforce", methods=["GET","POST"])
def brute():
    result = None
    body = """
    <form method="post">
      <label>Enter Ciphertext</label>
      <textarea name="text" class="form-control" rows="4"></textarea>
      <button class="btn btn-primary mt-3">Run Brute Force</button>
    </form>
    """

    if request.method == "POST":
        text = request.form.get("text","")
        bf = caesar_bruteforce(text)

        scored = [(s, bf[s], common_word_score(bf[s])) for s in bf]
        scored.sort(key=lambda x: -x[2])

        result = "\n".join([f"Shift {s}: {txt}" for s,txt,_ in scored])

    return render_page("Brute Force", body, result)


@app.route("/vigenere", methods=["GET","POST"])
def vig():
    result = None
    body = """
    <form method="post">
      <label>Text</label>
      <textarea name="text" class="form-control" rows="3"></textarea>

      <label class="mt-3">Key</label>
      <input name="key" class="form-control">

      <button class="btn btn-primary mt-3" name="action" value="enc">Encrypt</button>
      <button class="btn btn-secondary mt-3" name="action" value="dec">Decrypt</button>
    </form>
    """

    if request.method == "POST":
        text = request.form.get("text","")
        key = request.form.get("key","")
        action = request.form.get("action","")

        if action=="enc": result = vigenere_encrypt(text, key)
        else: result = vigenere_decrypt(text, key)

    return render_page("Vigenère Cipher", body, result)


@app.route("/base64", methods=["GET","POST"])
def base64_page():
    result = None
    body = """
    <form method="post">
      <label>Text / Base64</label>
      <textarea name="text" class="form-control" rows="3"></textarea>

      <button class="btn btn-primary mt-3" name="action" value="enc">Encode</button>
      <button class="btn btn-secondary mt-3" name="action" value="dec">Decode</button>
    </form>
    """

    if request.method == "POST":
        txt = request.form.get("text","")
        if request.form.get("action")=="enc":
            result = b64_encode(txt)
        else:
            out = b64_decode(txt)
            result = out if out else "Invalid base64"

    return render_page("Base64 Tools", body, result)


@app.route("/aes", methods=["GET","POST"])
def aes():
    result = None
    body = """
    <form method="post">
      <label>Text</label>
      <textarea name="text" class="form-control"></textarea>

      <label class="mt-3">Password</label>
      <input name="pwd" class="form-control">

      <button class="btn btn-primary mt-3" name="action" value="enc">Encrypt</button>
      <button class="btn btn-warning mt-3" name="action" value="dec">Decrypt</button>
    </form>
    """

    if request.method == "POST":
        txt = request.form.get("text","")
        pwd = request.form.get("pwd","")
        act = request.form.get("action","")

        if not pwd: result="Password required"
        else:
            if act=="enc": result = aes_encrypt_text(txt, pwd)
            else:
                dec = aes_decrypt_text(txt, pwd)
                result = dec if dec else "Invalid password/payload"

    return render_page("AES Encryption", body, result)


@app.route("/files", methods=["GET","POST"])
def files():
    result = None
    body = """
    <form method="post" enctype="multipart/form-data">
      <label>Select File</label>
      <input type="file" name="file" class="form-control">

      <label class="mt-3">Password</label>
      <input name="pwd" class="form-control">

      <button class="btn btn-primary mt-3" name="action" value="enc">Encrypt File</button>
      <button class="btn btn-warning mt-3" name="action" value="dec">Decrypt File</button>
    </form>
    """

    if request.method == "POST":
        f = request.files.get("file")
        pwd = request.form.get("pwd","")
        act = request.form.get("action","")

        if not f: result="No file"
        elif not pwd: result="Password required"
        else:
            filename = secure_filename(f.filename)
            inpath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            f.save(inpath)

            try:
                if act=="enc": out=aes_encrypt_file(inpath,pwd)
                else: out=aes_decrypt_file(inpath,pwd)
                result=f"Output file: {out}"
            except Exception as e:
                result=f"Error: {e}"

    return render_page("File Tools", body, result)


@app.route("/universal", methods=["GET","POST"])
def uni():
    result = None
    body = """
    <form method="post">
      <label>Enter Cipher</label>
      <textarea name="text" class="form-control" rows="4"></textarea>

      <button class="btn btn-primary mt-3">Run Universal Decoder</button>
    </form>
    """

    if request.method == "POST":
        text = request.form.get("text","")
        cand = universal_decode_candidates(text, top_n=8)

        result = "\n\n".join([f"[{m}] {t}" for m,t,_ in cand])

    return render_page("Universal Decoder", body, result)


if __name__ == "__main__":
    print("Running Caesar Cipher Tool on http://127.0.0.1:5000")
    app.run(debug=False, use_reloader=False, host="127.0.0.1", port=5000)
