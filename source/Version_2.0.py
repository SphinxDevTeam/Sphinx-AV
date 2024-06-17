import hashlib
import re
import requests
import pefile
import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import threading
from PIL import Image, ImageTk
from pytm import TM, Server, Dataflow, Boundary, Actor, Element
import os
import sys

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"

def escape_regex(pattern):
    return re.escape(pattern)

def calculate_file_hash(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def check_hash_malwarebazaar(file_hash):
    response = requests.post(MALWAREBAZAAR_API_URL, data={'query': 'get_info', 'hash': file_hash})
    if response.status_code == 200:
        json_response = response.json()
        if json_response['query_status'] == 'ok':
            return True
    return False

def search_for_malicious(filename):
    dangerousnum = 0
    dangerous_patterns = {
        "keylogger": 10,
        "exec(": 1,
        "subprocess": 1,
        "eval(": 2,
        "socket": 1,
        "download": 1,
        "shell": 1,
        "popen": 1,
        "system(": 1,
        "rmdir": 1,
        "rm -rf": 2,
        "del ": 1,
        "winreg": 1,
    }
    file_hash = calculate_file_hash(filename)
    if check_hash_malwarebazaar(file_hash):
        dangerousnum += 50

    with open(filename, 'r', errors='ignore') as file:
        for line in file:
            for pattern, score in dangerous_patterns.items():
                if re.search(escape_regex(pattern), line):
                    dangerousnum += score
                    break  
 
    return dangerousnum

def analyze_exe_file(filename):
    try:
        pe = pefile.PE(filename)
        suspicious_indicators = []

        suspicious_imports = ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for func in entry.imports:
                if func.name and func.name.decode('utf-8') in suspicious_imports:
                    suspicious_indicators.append(f"Suspicious import found: {func.name.decode('utf-8')}")

        for section in pe.sections:
            if section.Name.decode().strip('\x00') == '.text' and section.SizeOfRawData == 0:
                suspicious_indicators.append(f"Suspicious section found: {section.Name.decode().strip()}")

        if suspicious_indicators:
            return "Executable file analysis: Suspicious indicators found:\n" + "\n".join(suspicious_indicators)
        else:
            return "Executable file analysis: No suspicious indicators found. The file is safe to open."

    except Exception as e:
        return f"Executable file analysis: Failed to analyze the file. Error: {e}"

def browse_file():
    filename = filedialog.askopenfilename(title="Select a file")
    if filename:
        scanning_thread = threading.Thread(target=scan_file, args=(filename,))
        scanning_thread.start()

def scan_file(filename):
    show_loading()
    try:
        dangerous_elements = search_for_malicious(filename)
        classify_file(dangerous_elements, filename)
    finally:
        hide_loading()

def classify_file(dangerous_elements, filename):
    if filename.lower().endswith('.exe'):
        exe_analysis = analyze_exe_file(filename)
        if "No suspicious indicators found" in exe_analysis:
            dangerous_elements = 0
        exe_msg.configure(text=exe_analysis, text_color="blue")
    if dangerous_elements == 0:
        msg.configure(text="No viruses detected: The file is safe to open.", text_color="green")
    else:
        msg.configure(text="If the threat score is above 10 be cautious while opening the file.", text_color="red")

    detected.configure(text=f"Malicious Elements Score: {dangerous_elements}")

    run_threat_modeling(dangerous_elements)

def run_threat_modeling(dangerous_elements):
    tm = TM("Malware Detection Model")

    internal_boundary = Boundary("Internal Network")

    user = Actor("User")
    file = Element("File")
    av_system = Server("AV System")
    av_system.inBoundary = internal_boundary  

    dataflow1 = Dataflow(user, file, "Upload File")
    dataflow2 = Dataflow(file, av_system, "Scan File for Malware")

    if hasattr(dataflow2, 'protocol'):
        dataflow2.protocol = "HTTPS"

    av_system.storesSensitiveData = True
    file.hasSensitiveData = True
    file.isEncrypted = False
    file.isMalicious = dangerous_elements > 0

    tm.elements = [user, file, av_system]
    tm.dataflows = [dataflow1, dataflow2]

    try:
        tm.process()
    except AttributeError as e:
        print(f"Caught an AttributeError: {e}")
        pass

    if file.isMalicious:
        threat_result.configure(text="Secondary detection: This file has been flagged as malicious please review the score.", text_color="red")
    else:
        threat_result.configure(text="Secondary detection: No malicious activity detected.", text_color="green")

def show_loading():
    loading_label.place(relx=0.5, rely=0.93, anchor='s')
    progress_bar.place(relx=0.5, rely=0.98, anchor='s')
    smooth_progress_bar()

def hide_loading():
    root.after_cancel(progress_bar_job)
    progress_bar.stop()
    progress_bar.place_forget()
    loading_label.place_forget()

def smooth_progress_bar():
    global progress_bar_job
    progress_bar.step(1)
    progress_bar_job = root.after(10, smooth_progress_bar)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.geometry("800x600")
root.title("Sphinx AV")

# Ensure the path to the icon file is correct
icon_path = resource_path(os.path.join('assets', 'custom_icon.ico'))
print(f"Icon path: {icon_path}")  # Debug statement to check the path
if os.path.exists(icon_path):
    root.iconbitmap(icon_path)
else:
    print("Icon file not found. Please check the path.")  # Debug message if file is not found

padding = 10

title = ctk.CTkLabel(root, text="Sphinx AV", font=("Segoe UI", 24, "bold"))
title.pack(pady=padding)

detected = ctk.CTkLabel(root, text="Malicious Elements Score: 0", font=("Segoe UI", 16))
detected.pack(pady=padding)

browse_button = ctk.CTkButton(root, text="Browse File", command=browse_file, font=("Segoe UI", 14))
browse_button.pack(pady=padding)

msg = ctk.CTkLabel(root, text="", font=("Segoe UI", 14))
msg.pack(pady=padding)

exe_msg = ctk.CTkLabel(root, text="", font=("Segoe UI", 14))
exe_msg.pack(pady=padding)

instructions = ctk.CTkLabel(root, text="Select a file to scan for malicious elements.\nThe result will indicate if the file is safe to open.", font=("Segoe UI", 12), text_color="grey")
instructions.pack(pady=padding)

threat_result = ctk.CTkLabel(root, text="", font=("Segoe UI", 14))
threat_result.pack(pady=padding)

progress_bar = ttk.Progressbar(root, mode='indeterminate', length=300, style='green.Horizontal.TProgressbar')
loading_label = ctk.CTkLabel(root, text="Scanning...", font=("Segoe UI", 18, "bold"), text_color="red")
style = ttk.Style()
style.configure('green.Horizontal.TProgressbar', troughcolor='black', background='green')

root.mainloop()
