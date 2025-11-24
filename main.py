# main.py
import subprocess, sys, os, signal, time

web_proc = None

def start_web():
    global web_proc
    if web_proc is None or web_proc.poll() is not None:
        print("Starting Web App...")
        # Start without stdout capture to avoid blocking
        web_proc = subprocess.Popen(
            [sys.executable, "web_app.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1)
        print("Web running at http://127.0.0.1:5000")
    else:
        print("Web already running.")

def stop_web():
    global web_proc
    if web_proc and web_proc.poll() is None:
        print("Stopping Web Server...")

        try:
            # First try graceful stop
            web_proc.terminate()
            web_proc.wait(timeout=3)
        except Exception:
            try:
                # If still alive → force kill
                web_proc.kill()
                web_proc.wait(timeout=2)
            except Exception as e:
                print("Could not kill web process:", e)

    web_proc = None
    print("Web Server Stopped.")

def start_gui():
    os.system(f"{sys.executable} gui_app.py")

def main():
    try:
        while True:
            print("\n=== Mega Cipher Suite Launcher ===")
            print("1) GUI  2) Web  3) Exit")
            c = input("Choose: ").strip()

            if c == "1":
                start_gui()

            elif c == "2":
                start_web()

            elif c == "3":
                stop_web()
                print("Exiting...")
                break

            else:
                print("Invalid choice")
    finally:
        # Safety cleanup
        stop_web()

if __name__ == "__main__":
    main()
