# gui_app.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from core import (
    caesar_shift, caesar_decrypt, caesar_bruteforce, caesar_auto,
    vigenere_encrypt, vigenere_decrypt, atbash, rot13, b64_encode, b64_decode,
    sha256, md5, aes_encrypt_text, aes_decrypt_text, aes_encrypt_file, aes_decrypt_file
)

try:
    import pyperclip
    PYPERCLIP = True
except:
    PYPERCLIP = False

root = tk.Tk()
root.title("Mega Cipher Suite (GUI)")
root.geometry("1000x700")

nb = ttk.Notebook(root)
nb.pack(fill='both', expand=True)

# Output area at bottom
out_frame = ttk.Frame(root)
out_frame.pack(fill='both', expand=True, padx=8, pady=8)
ttk.Label(out_frame, text="Output").pack(anchor='w')
txt_out = tk.Text(out_frame, height=12)
txt_out.pack(fill='both', expand=True)

def set_output(text:str):
    txt_out.delete('1.0', tk.END)
    txt_out.insert(tk.END, text)

def copy_output():
    txt = txt_out.get('1.0', tk.END).strip()
    if PYPERCLIP:
        pyperclip.copy(txt)
        messagebox.showinfo("Copied", "Output copied to clipboard")
    else:
        root.clipboard_clear(); root.clipboard_append(txt); messagebox.showinfo("Copied", "Output copied (fallback)")

def save_output():
    txt = txt_out.get('1.0', tk.END)
    if not txt.strip():
        messagebox.showwarning("Empty", "Nothing to save")
        return
    p = filedialog.asksaveasfilename(defaultextension=".txt")
    if p:
        with open(p, "w", encoding="utf-8") as f:
            f.write(txt)
        messagebox.showinfo("Saved", f"Saved to {p}")

ttk.Button(out_frame, text="Copy Output", command=copy_output).pack(side='left', padx=6, pady=6)
ttk.Button(out_frame, text="Save Output", command=save_output).pack(side='left', padx=6, pady=6)

# ---------------- Caesar tab ----------------
tab_caesar = ttk.Frame(nb); nb.add(tab_caesar, text="Caesar")
ttk.Label(tab_caesar, text="Text").pack(anchor='w', padx=8, pady=(8,0))
txt_caesar = tk.Text(tab_caesar, height=6); txt_caesar.pack(fill='x', padx=8)
frm = ttk.Frame(tab_caesar); frm.pack(fill='x', padx=8, pady=6)
ttk.Label(frm, text="Shift (optional for decrypt)").pack(side='left')
e_shift = ttk.Entry(frm, width=8); e_shift.pack(side='left', padx=6)
def caesar_encrypt():
    t = txt_caesar.get('1.0', tk.END).strip()
    s = e_shift.get().strip()
    if not s:
        messagebox.showwarning("Need shift", "Shift required for encryption")
        return
    try: s = int(s)
    except: messagebox.showerror("Error","Shift must be integer"); return
    set_output(caesar_shift(t, s))
def caesar_decrypt_action():
    t = txt_caesar.get('1.0', tk.END).strip()
    s = e_shift.get().strip()
    if not s:
        s_best, out = caesar_auto(t)
        set_output(f"Auto shift {s_best} ->\n{out}")
    else:
        try: s = int(s)
        except: messagebox.showerror("Error","Shift must be integer"); return
        set_output(caesar_decrypt(t, s))
ttk.Button(frm, text="Encrypt", command=caesar_encrypt).pack(side='left', padx=6)
ttk.Button(frm, text="Decrypt / Auto", command=caesar_decrypt_action).pack(side='left')

# ---------------- Vigenere ----------------
tab_v = ttk.Frame(nb); nb.add(tab_v, text="Vigenère")
ttk.Label(tab_v, text="Text").pack(anchor='w', padx=8, pady=(8,0))
txt_v = tk.Text(tab_v, height=6); txt_v.pack(fill='x', padx=8)
frm2 = ttk.Frame(tab_v); frm2.pack(fill='x', padx=8, pady=6)
ttk.Label(frm2, text="Key").pack(side='left')
e_vkey = ttk.Entry(frm2, width=24); e_vkey.pack(side='left', padx=6)
def vigenere_enc_action():
    t = txt_v.get('1.0', tk.END).strip(); k = e_vkey.get().strip()
    if not k:
        messagebox.showwarning("Missing key","Vigenère key required")
        return
    set_output(vigenere_encrypt(t, k))
def vigenere_dec_action():
    t = txt_v.get('1.0', tk.END).strip(); k = e_vkey.get().strip()
    if not k:
        messagebox.showwarning("Missing key","Vigenère key required")
        return
    set_output(vigenere_decrypt(t, k))
ttk.Button(frm2, text="Encrypt", command=vigenere_enc_action).pack(side='left', padx=6)
ttk.Button(frm2, text="Decrypt", command=vigenere_dec_action).pack(side='left')

# ---------------- Atbash / ROT13 / Base64 ----------------
tab_misc = ttk.Frame(nb); nb.add(tab_misc, text="Atbash/ROT13/Base64")
ttk.Label(tab_misc, text="Text").pack(anchor='w', padx=8, pady=(8,0))
txt_misc = tk.Text(tab_misc, height=6); txt_misc.pack(fill='x', padx=8)
f3 = ttk.Frame(tab_misc); f3.pack(fill='x', padx=8, pady=6)
ttk.Button(f3, text="Atbash", command=lambda: set_output(atbash(txt_misc.get('1.0', tk.END).strip()))).pack(side='left', padx=6)
ttk.Button(f3, text="ROT13", command=lambda: set_output(rot13(txt_misc.get('1.0', tk.END).strip()))).pack(side='left', padx=6)
ttk.Button(f3, text="Base64 Encode", command=lambda: set_output(b64_encode(txt_misc.get('1.0', tk.END).strip()))).pack(side='left', padx=6)
ttk.Button(f3, text="Base64 Decode", command=lambda: set_output(b64_decode(txt_misc.get('1.0', tk.END).strip() or ""))).pack(side='left', padx=6)

# ---------------- AES (text) ----------------
tab_aes = ttk.Frame(nb); nb.add(tab_aes, text="AES (Password)")
ttk.Label(tab_aes, text="Text").pack(anchor='w', padx=8, pady=(8,0))
txt_aes = tk.Text(tab_aes, height=6); txt_aes.pack(fill='x', padx=8)
frm4 = ttk.Frame(tab_aes); frm4.pack(fill='x', padx=8, pady=6)
ttk.Label(frm4, text="Password").pack(side='left')
e_aes_pwd = ttk.Entry(frm4, width=40, show="*"); e_aes_pwd.pack(side='left', padx=6)
def aes_enc_action():
    t = txt_aes.get('1.0', tk.END).strip(); pwd = e_aes_pwd.get().strip()
    if not pwd: messagebox.showwarning("Password required","Enter password"); return
    set_output(aes_encrypt_text(t, pwd))
def aes_dec_action():
    t = txt_aes.get('1.0', tk.END).strip(); pwd = e_aes_pwd.get().strip()
    if not pwd: messagebox.showwarning("Password required","Enter password"); return
    set_output(aes_decrypt_text(t, pwd) or "Decryption failed")
ttk.Button(frm4, text="Encrypt", command=aes_enc_action).pack(side='left', padx=6)
ttk.Button(frm4, text="Decrypt", command=aes_dec_action).pack(side='left', padx=6)

# ---------------- File encrypt/decrypt ----------------
tab_files = ttk.Frame(nb); nb.add(tab_files, text="File Encrypt/Decrypt")
frm_file = ttk.Frame(tab_files); frm_file.pack(fill='x', padx=8, pady=8)
ttk.Button(frm_file, text="Choose file", command=lambda: select_file()).pack(side='left', padx=6)
file_label = ttk.Label(frm_file, text="No file chosen"); file_label.pack(side='left', padx=6)
ttk.Label(frm_file, text="Password").pack(side='left', padx=8)
e_file_pwd = ttk.Entry(frm_file, width=30, show="*"); e_file_pwd.pack(side='left', padx=6)
def select_file():
    p = filedialog.askopenfilename()
    if p:
        file_label.config(text=os.path.basename(p))
        file_label.filepath = p
def file_encrypt_action():
    p = getattr(file_label, "filepath", None)
    pwd = e_file_pwd.get().strip()
    if not p: messagebox.showwarning("File", "Choose a file"); return
    if not pwd: messagebox.showwarning("Password","Enter password"); return
    out = aes_encrypt_file(p, pwd)
    set_output(f"Encrypted to: {out}")
def file_decrypt_action():
    p = getattr(file_label, "filepath", None)
    pwd = e_file_pwd.get().strip()
    if not p: messagebox.showwarning("File", "Choose a file"); return
    if not pwd: messagebox.showwarning("Password","Enter password"); return
    try:
        out = aes_decrypt_file(p, pwd)
        set_output(f"Decrypted to: {out}")
    except Exception as e:
        messagebox.showerror("Error", str(e))
ttk.Button(frm_file, text="Encrypt File", command=file_encrypt_action).pack(side='left', padx=6)
ttk.Button(frm_file, text="Decrypt File", command=file_decrypt_action).pack(side='left', padx=6)

# ---------------- Tools (hash) ----------------
tab_tools = ttk.Frame(nb); nb.add(tab_tools, text="Hash")
ttk.Label(tab_tools, text="Text").pack(anchor='w', padx=8, pady=(8,0))
txt_tools = tk.Text(tab_tools, height=6); txt_tools.pack(fill='x', padx=8)
frm_tools = ttk.Frame(tab_tools); frm_tools.pack(fill='x', padx=8, pady=6)
def do_sha(): set_output(sha256(txt_tools.get('1.0', tk.END).strip()))
def do_md5(): set_output(md5(txt_tools.get('1.0', tk.END).strip()))
ttk.Button(frm_tools, text="SHA256", command=do_sha).pack(side='left', padx=6)
ttk.Button(frm_tools, text="MD5", command=do_md5).pack(side='left', padx=6)

root.mainloop()
