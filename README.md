# Caesar Cipher Decryptor — CLI + GUI + Web App

A full-featured cryptography tool that can **analyze, break, and decode Caesar ciphers** using:

- 🖥️ Command-line Interface  
- 🪟 Tkinter GUI  
- 🌐 Flask Web Application  
- 🔎 Frequency Analysis  
- 🧮 Chi-Squared Scoring  
- 🔄 ROT13 Auto-Detection  
- 📦 PyInstaller Executable Builder  

This project is designed for both beginners and developers who want a clean, efficient, and accurate Caesar cipher tool.

---

## ✨ Features

✔ Brute-force all 26 shifts  
✔ Frequency Analysis for better plaintext detection  
✔ Chi-squared scoring for ranking likely decryptions  
✔ Auto-detect ROT13  
✔ CLI mode for terminal usage  
✔ Tkinter GUI for desktop  
✔ Flask Web UI for browser access  
✔ Export to standalone executable  
✔ Clean, documented, readable code  

---

## 🚀 Installation

Clone the repo:

```bash
git clone https://github.com/yourusername/caesar-tool.git
cd caesar-tool
pip install -r requirements.txt
```

Run the tool:

```bash
python3 caesar_tool.py
```

---

## 🧰 Usage

### ▶ CLI Mode

```bash
python3 caesar_tool.py
```

### ▶ GUI Mode

```bash
python3 caesar_tool.py --gui
```

### ▶ Web Mode

```bash
python3 caesar_tool.py --web
```

Then open:

```
http://127.0.0.1:5000
```

---

## 🏗️ Build Executable (PyInstaller)

```bash
pyinstaller --onefile caesar_tool.py
```

Executable will be created in:

```
dist/caesar_tool
```

---

## 📝 License
This project is licensed under the MIT License — free to use, modify, and share.

---

## 🤝 Contributions
Pull requests, issues, and improvements are welcome!

---

## 📬 Contact
Feel free to reach out on LinkedIn or GitHub if you'd like to collaborate.
