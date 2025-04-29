import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import json
import csv
from datetime import datetime
import webbrowser

# Authors: Seid Ahmed, Philippe Baraka, Eli Hofmann
# Version: 5-16-2025
# Description: CSCI 410 - Cyberattack Threat Characterization System


def load_json_data(filepath):
    try:
        with open(filepath, 'r') as file:
            return json.load(file)
    except Exception as ex:
        messagebox.showerror("File Error", f"Failed To Load JSON: {ex}")
        return None

def identify_threats(threat_data, system_data):
    relevant = []

    if not isinstance(system_data, dict):
        return relevant
    if not isinstance(threat_data, list):
        return relevant

    os_value = system_data.get("os", "")
    if isinstance(os_value, str):
        system_os = os_value.lower()
    else:
        system_os = ""

    system_vul = system_data.get("vulnerabilities", [])
    if not isinstance(system_vul, list):
        system_vul = []

    for threat in threat_data:
        if not isinstance(threat, dict):
            continue

        for vul in threat.get("vulnerabilities", []):
            if vul in system_vul:
                relevant.append(threat)
                break
        else:
            for sys in threat.get("systems", []):
                if isinstance(sys, str) and (sys.lower() in system_os or system_os in sys.lower()):
                    relevant.append(threat)
                    break

    return relevant

def calc_risk(threats):
    score = 0
    for threat in threats:
        impact = threat.get("impact", "").lower()
        if impact == "critical":
            score += 10
        elif impact == "high":
            score += 8
        elif impact == "medium":
            score += 5
        elif impact == "low":
            score += 2
    
    if threats:
        avg = score / len(threats)
        return round(avg, 2)
    else:
        return 0

def interpret_risk(score):
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 4:
        return "Moderate"
    else:
        return "Low"

def display_results(threats):
    global output
    output.config(state="normal")
    output.delete('1.0', tk.END)

    if not threats:
        output.insert(tk.END, "No Matching Threats Found\n")
    else:
        for threat in threats:
            output.insert(tk.END, f"[THREAT FOUND] {threat['name']}\n")
            output.insert(tk.END, f"  Description : {threat['description']}\n")
            output.insert(tk.END, f"  Impact      : {threat['impact']}\n")
            output.insert(tk.END, f"  Affects     : {', '.join(threat['systems'])}\n")
            output.insert(tk.END, f"  Mitigation  : {threat['mitigation']}\n\n")
        
        risk_score = calc_risk(threats)
        output.insert(tk.END, f"System Risk Score: {risk_score}/10.0\n")

    output.config(state="disabled")

def load_threat_file():
    path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if path:
        global threat_data
        threat_data = load_json_data(path)
        if threat_data is not None:
            messagebox.showinfo("Threat Data", "Data Loaded Successfully")


def load_system_file():
    path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if path:
        global system_data
        system_data = load_json_data(path)
        if system_data is not None:
            messagebox.showinfo("System Data", "Data Loaded Successfully")

def run_analysis():
    if not threat_data or not system_data:
        messagebox.showwarning("Missing Data", "Please load both Threat and System JSON files.")
        return
    results = identify_threats(threat_data, system_data)
    display_results(results)
    if results:
        risk_score = calc_risk(results)
        risk_level = interpret_risk(risk_score)
        messagebox.showinfo("Risk Summary",
                            f"Threats Found: {len(results)}\n"
                            f"System Risk Score: {risk_score}/10.0\n"
                            f"Risk Level: {risk_level}")
    else:
        messagebox.showinfo("Risk Summary", "No threats found. System appears secure.")

    
def export_report():
    if not threat_data or not system_data:
        messagebox.showwarning("Missing Data", "Please Run Analysis First")
        return
    
    results = identify_threats(threat_data, system_data)
    
    if not results:
        messagebox.showinfo("No Data", "No Threats Found To save")
        return

    default_filename = f"report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], initialfile=default_filename)
    
    if not path:
        return
    try:
        with open(path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["Name", "Description", "Impact", "Systems", "Mitigation"])
            for threat in results:
                writer.writerow([
                    threat['name'],
                    threat['description'],
                    threat['impact'],
                    ",".join(threat['systems']),
                    threat['mitigation']
                ])
            writer.writerow([])
            risk_score = calc_risk(results)
            risk_level = interpret_risk(risk_score)
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            writer.writerow(["Summary"])
            writer.writerow(["Total Threats Found", len(results)])
            writer.writerow(["System Risk Score", f"{risk_score}/10.0"])
            writer.writerow(["Risk Level", risk_level])
            writer.writerow(["Scan Date", scan_time])
            
        messagebox.showinfo("Success", f"Report Has Been Saved To:\n{path}")
    except Exception as ex:
        messagebox.showerror("Error", f"Failed To Save File:\n{ex}")

def clear_output():
    global output
    output.config(state="normal")
    output.delete('1.0', tk.END)
    output.config(state="disabled")
    
def open_link(event):
    webbrowser.open_new("https://nvd.nist.gov/")
                
# --------------------------------------------------------------------------------------------------------------------------------------------

root = tk.Tk()
root.title("Cyberattack Threat Characterization System")
root.geometry("800x610")
root.configure(bg="lightgrey")
font = ("Courier New", 12)
font_title = ("Courier New", 24, "bold")

label = tk.Label(root, text="Cyberattack Threat Characterization System", font=font_title, bg="blue")
label.pack(pady=(15, 5))

btn_frame = tk.Frame(root, bg="lightgrey")
btn_frame.pack(pady=10)

load_threat_data_btn = tk.Button(btn_frame, text="Load Threat", width=10, font=font, command=load_threat_file, relief="raised")
load_threat_data_btn.grid(row=0, column=0, padx=10)

load_system_btn = tk.Button(btn_frame, text="Load System", width=10, font=font, command=load_system_file, relief="raised")
load_system_btn.grid(row=0, column=1, pady=10)

run_btn = tk.Button(btn_frame, text="Run Analysis", width=10, font=font, command=run_analysis, relief="raised")
run_btn.grid(row=0, column=2, padx=10)

save_btn = tk.Button(btn_frame, text="Save Report", width=10, font=font, command=export_report, relief="raised")
save_btn.grid(row=0, column=4, padx=60)

clear_btn = tk.Button(btn_frame, text="Clear Output", width=10, font=font, command=clear_output, relief="raised")
clear_btn.grid(row=0, column=5, padx=10)

output = scrolledtext.ScrolledText(root, width=90, height=20, font=font,  bg="black", fg="lime", relief="sunken", borderwidth=2)
output.pack(padx=10, pady=10)
output.config(state="disabled")

link = tk.Label(root, text="Visit the National Vulnerability Database", font=font, bg="lightgrey", fg="blue", cursor="hand2")
link.pack(pady=20)
link.bind("<Button-1>", open_link)

label2 = tk.Label(root, text="THIS SOFTWARE IS INTENDED TO BE USED FOR EDUCATIONAL PURPOSES ONLY", font=font, bg="black")
label2.pack(pady=(15, 5))

close_btn = tk.Button(root, text="Close", width=10, font=font, command=root.quit, relief="raised")
close_btn.pack(pady=15)

threat_data = None
system_data = None

root.mainloop()