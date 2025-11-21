"""
Caesar Cipher - Combined Advanced Tool
Features:
- Brute force all 25 shifts
- Frequency analysis (chi-squared score)
- ROT13 auto-detection
- Tkinter GUI for interactive use
- Optional lightweight Flask web UI you can run locally

Save this file as caesar_tool.py and run with Python 3.8+.
"""

import threading
import string
import math
import sys

# ---------- Core functionality ----------
ALPHABET = string.ascii_lowercase

ENGLISH_FREQ = {
    'a': 0.08167,'b': 0.01492,'c': 0.02782,'d': 0.04253,'e': 0.12702,
    'f': 0.02228,'g': 0.02015,'h': 0.06094,'i': 0.06966,'j': 0.00153,
    'k': 0.00772,'l': 0.04025,'m': 0.02406,'n': 0.06749,'o': 0.07507,
    'p': 0.01929,'q': 0.00095,'r': 0.05987,'s': 0.06327,'t': 0.09056,
    'u': 0.02758,'v': 0.00978,'w': 0.02360,'x': 0.00150,'y': 0.01974,'z': 0.00074
}

COMMON_WORDS = ['the','be','to','of','and','a','in','that','have','I','is','it','for','not','on','with','as','you','do','at']


def caesar_shift(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            lower = ch.islower()
            base = ord('a') if ch.islower() else ord('A')
            offset = (ord(ch) - base - shift) % 26
            result.append(chr(base + offset))
        else:
            result.append(ch)
    return ''.join(result)


def caesar_bruteforce(text):
    results = {}
    for s in range(0, 26):
        results[s] = caesar_shift(text, s)
    return results


# ---------- Frequency Analysis -----------

def letter_frequency(text):
    counts = {c:0 for c in ALPHABET}
    total = 0
    for ch in text.lower():
        if ch in counts:
            counts[ch] += 1
            total += 1
    return counts, total


def chi_squared_score(text):
    counts, total = letter_frequency(text)
    if total == 0:
        return float('inf')
    chi2 = 0.0
    for ch in ALPHABET:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * total
        chi2 += ((observed - expected) ** 2) / (expected + 1e-6)
    return chi2


def common_word_score(text):
    lower = text.lower()
    count = 0
    for w in COMMON_WORDS:
        count += lower.count(' ' + w + ' ')
        if lower.startswith(w + ' '):
            count += 1
        if lower.endswith(' ' + w):
            count += 1
    return count


# ---------- ROT13 detection ----------

def rot13_transform(text):
    trans = str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')
    return text.translate(trans)


def is_rot13(text):
    candidate = rot13_transform(text)
    cw = common_word_score(candidate)
    chi = chi_squared_score(candidate)
    if cw >= 1:
        return True, candidate
    if chi < 200:
        return True, candidate
    return False, candidate


# ---------- Suggestions ----------

def suggest_shifts(text, top_n=3):
    candidates = caesar_bruteforce(text)
    scored = []
    for s, cand in candidates.items():
        chi = chi_squared_score(cand)
        cw = common_word_score(cand)
        scored.append((s, chi, -cw, cand))
    scored.sort(key=lambda x: (x[1], x[2]))
    return scored[:top_n]


def print_all_shifts(text):
    res = caesar_bruteforce(text)
    for s in range(0, 26):
        print(f"Shift {s:2d}: {res[s]}")


# ---------- Tkinter GUI ----------
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
except Exception:
    tk = None


def run_tkinter_gui():
    if tk is None:
        print("Tkinter is not available on this system.")
        return

    root = tk.Tk()
    root.title('Caesar Cipher - Brute Force Tool (Advanced)')
    root.geometry('800x600')

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill='x')

    ttk.Label(frame, text='Ciphertext:').pack(anchor='w')
    txt_input = scrolledtext.ScrolledText(frame, height=4)
    txt_input.pack(fill='x')

    def on_analyze():
        text = txt_input.get('1.0', 'end').strip()
        if not text:
            messagebox.showinfo('Info','Please enter ciphertext first.')
            return
        for i in tree.get_children():
            tree.delete(i)
        candidates = caesar_bruteforce(text)
        scored = []
        for s, cand in candidates.items():
            chi = chi_squared_score(cand)
            cw = common_word_score(cand)
            scored.append((s, cand, chi, cw))
        scored.sort(key=lambda x: (x[2], -x[3]))
        for s, cand, chi, cw in scored:
            tree.insert('', 'end', values=(s, f"{cand[:80]}", f"{chi:.1f}", cw))

        rot13_flag, rot13_candidate = is_rot13(text)
        if rot13_flag:
            lbl_rot13.config(text='ROT13 likely — candidate shown above', foreground='green')
        else:
            lbl_rot13.config(text='ROT13 not detected', foreground='black')

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(fill='x', pady=6)
    ttk.Button(btn_frame, text='Analyze (Brute + Scoring)', command=on_analyze).pack(side='left')

    lbl_rot13 = ttk.Label(frame, text='ROT13 not checked yet')
    lbl_rot13.pack(anchor='w')

    columns = ('Shift','Candidate (truncated)','Chi2','CommonWords')
    tree = ttk.Treeview(root, columns=columns, show='headings')
    for c in columns:
        tree.heading(c, text=c)
        tree.column(c, width=200 if c!='Shift' else 60)
    tree.pack(fill='both', expand=True, padx=10, pady=10)

    def on_double_click(event):
        item = tree.selection()
        if not item: return
        vals = tree.item(item[0])['values']
        shift = int(vals[0])
        full = caesar_bruteforce(txt_input.get('1.0','end').strip())[shift]
        root.clipboard_clear()
        root.clipboard_append(full)
        messagebox.showinfo('Copied','Full candidate copied to clipboard')

    tree.bind('<Double-1>', on_double_click)

    footer = ttk.Frame(root, padding=6)
    footer.pack(fill='x')
    ttk.Label(footer, text='Double-click a row to copy full candidate to clipboard.').pack(side='left')

    root.mainloop()


# ---------- Optional Flask web UI ----------
WEB_APP_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <title>Caesar Brute-force Tool</title>
  <style>body{font-family:Arial;margin:20px}textarea{width:100%;height:120px}</style>
</head>
<body>
  <h2>Caesar Brute-force Tool</h2>
  <form method='post'>
    <textarea name='ciphertext' placeholder='Paste ciphertext here...'>{{ciphertext}}</textarea><br>
    <input type='submit' value='Analyze'>
  </form>
  {% if results %}
  <h3>Results</h3>
  <table border=1 cellpadding=6>
    <tr><th>Shift</th><th>Candidate</th><th>Chi2</th><th>CommonWords</th></tr>
    {% for r in results %}
    <tr><td>{{r.shift}}</td><td>{{r.candidate}}</td><td>{{r.chi:.1f}}</td><td>{{r.cw}}</td></tr>
    {% endfor %}
  </table>
  {% endif %}
</body>
</html>
"""


def run_flask_app(port=5000):
    try:
        from flask import Flask, request, render_template_string
    except Exception:
        print('Flask not installed. Install with: pip install flask')
        return

    app = Flask('caesar_tool')

    @app.route('/', methods=['GET','POST'])
    def index():
        ciphertext = ''
        results = None
        if request.method == 'POST':
            ciphertext = request.form.get('ciphertext','')
            candidates = caesar_bruteforce(ciphertext)
            scored = []
            for s, cand in candidates.items():
                chi = chi_squared_score(cand)
                cw = common_word_score(cand)
                scored.append({'shift':s,'candidate':cand,'chi':chi,'cw':cw})
            scored.sort(key=lambda x: (x['chi'], -x['cw']))
            results = scored[:26]
        return render_template_string(WEB_APP_TEMPLATE, ciphertext=ciphertext, results=results)

    print(f'Running Flask web app on http://127.0.0.1:{port}')
    app.run(port=port)


# ---------- Main Entrypoint ----------
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--gui':
        run_tkinter_gui()
    elif len(sys.argv) > 1 and sys.argv[1] == '--web':
        run_flask_app()
    else:
        print('Caesar Cipher - Combined Tool')
        print('Options:')
        print('  1) Enter ciphertext interactively and show all shifts')
        print('  2) --gui    Run Tkinter GUI')
        print('  3) --web    Run local Flask web UI (requires flask)')
        print("\nEnter ciphertext (or type /gui or /web):")

        inp = input().strip()
        if inp in ['/gui', '--gui']:
            run_tkinter_gui()
            sys.exit(0)
        if inp in ['/web', '--web']:
            run_flask_app()
            sys.exit(0)

        text = inp
        if not text:
            print('No ciphertext provided — exiting.')
            sys.exit(0)

        rot13_flag, rot13_candidate = is_rot13(text)
        if rot13_flag:
            print("\nROT13 detected! Candidate plaintext:")
            print(rot13_candidate)
            print("\n(Also showing all shifts below)\n")

        print("\nTop suggestions (by chi-squared + common-words):")
        suggestions = suggest_shifts(text, top_n=5)
        for s, chi, neg_cw, cand in suggestions:
            print(f"Shift {s:2d} — chi2={chi:.1f} — commonWords={-neg_cw} -> {cand}")

        print("\nAll shifts:")
        print_all_shifts(text)
