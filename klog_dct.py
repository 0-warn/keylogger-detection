#!/usr/bin/env python3
import argparse
import os
import sys

import psutil

SUSPECIOUS_KEYWORDS = ["pyinput", "keyboard", "keylog", "pynput", "hook"]

LOCALHOSTS = ("127.0.0.1", "::1", "localhost")


def _is_remote(addr):
    if not addr:
        return False
    ip = addr.ip
    if not ip:
        return False
    if ip.startswith("127.") or ip == "::1" or ip == "0.0.0.0" or ip == "::":
        return False
    return True


def get_suspicious_processes():
    found = []
    self_pid = os.getpid()
    parent_pid = os.getppid()
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        if proc.info["pid"] in (self_pid, parent_pid):
            continue
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            haystack = "{} {}".format(proc.info["name"] or "", cmdline).lower()
            matched = [w for w in SUSPECIOUS_KEYWORDS if w in haystack]
            if not matched:
                continue
            connections = []
            try:
                connections = proc.net_connections()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                connections = []
            remote_addrs = []
            for c in connections:
                if c.status == psutil.CONN_ESTABLISHED and _is_remote(c.raddr):
                    remote_addrs.append((c.raddr.ip, c.raddr.port))
            found.append(
                {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "cmdline": cmdline,
                    "matched": matched,
                    "remote_addrs": remote_addrs,
                    "connections": connections,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return found


def kill_process(proc_info):
    try:
        proc = psutil.Process(proc_info["pid"])
        proc.terminate()
        proc.wait(timeout=5)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        try:
            proc.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    except psutil.TimeoutExpired:
        proc.kill()
        return True


def ask_user_kill(proc_info):
    while True:
        try:
            answer = input(
                "Kill process '{}' (PID: {})? [y/N]: ".format(proc_info["name"], proc_info["pid"])
            ).strip().lower()
        except EOFError:
            return False
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False


def scan_cli():
    found = get_suspicious_processes()
    print("Scanning running processes.....")
    if not found:
        print("[+] No suspicious process found.")
        return
    for p in found:
        net_flag = " [*] CONNECTED TO INTERNET ({})".format(
            ", ".join("{}:{}".format(*a) for a in p["remote_addrs"])
        ) if p["remote_addrs"] else ""
        print(
            "[!] Suspecious proccess found: {} (PID: {}){}{}".format(
                p["name"],
                p["pid"],
                net_flag,
                "" if p["cmdline"] else " (no cmdline)",
            )
        )
        if p["cmdline"]:
            print("    cmdline: {}".format(p["cmdline"]))
        for remote in p["remote_addrs"]:
            print("    connection -> {}:{}".format(*remote))
    print()
    for p in found:
        if ask_user_kill(p):
            if kill_process(p):
                print("[+] Killed PID {} ({})".format(p["pid"], p["name"]))
            else:
                print("[!] Failed to kill PID {} (permission denied?)".format(p["pid"]))
        else:
            print("[+] Skipped PID {} ({})".format(p["pid"], p["name"]))


def scan_gui():
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except ImportError:
        print("[!] tkinter is not available on this system, GUI cannot run.")
        sys.exit(1)

    root = tk.Tk()
    root.title("Keylogger Detector")
    root.geometry("900x500")

    columns = ("pid", "name", "cmdline", "internet")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    tree.heading("pid", text="PID")
    tree.heading("name", text="Process")
    tree.heading("cmdline", text="Command Line")
    tree.heading("internet", text="Internet Connection")
    tree.column("pid", width=70, anchor="center")
    tree.column("name", width=150)
    tree.column("cmdline", width=520)
    tree.column("internet", width=140, anchor="center")
    tree.pack(fill="both", expand=True, padx=8, pady=8)

    status = tk.StringVar(value="Ready.")
    status_label = tk.Label(root, textvariable=status, anchor="w")
    status_label.pack(fill="x", padx=8)

    current = {}

    def populate():
        for item in tree.get_children():
            tree.delete(item)
        current.clear()
        status.set("Scanning running processes.....")
        root.update_idletasks()
        for p in get_suspicious_processes():
            iid = str(p["pid"])
            current[iid] = p
            tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    p["pid"],
                    p["name"],
                    p["cmdline"],
                    "YES - {}".format(
                        ", ".join("{}:{}".format(*a) for a in p["remote_addrs"])
                    ) if p["remote_addrs"] else "no",
                ),
            )
        n = len(current)
        status.set("Scan complete. {} suspicious process{} found.".format(n, "" if n == 1 else "es"))

    def on_kill():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select a process to kill first.")
            return
        iid = sel[0]
        p = current[iid]
        if not messagebox.askyesno(
            "Confirm kill",
            "Kill process '{}' (PID: {})?".format(p["name"], p["pid"]),
        ):
            return
        if kill_process(p):
            status.set("Killed PID {} ({}).".format(p["pid"], p["name"]))
            populate()
        else:
            messagebox.showerror(
                "Failed",
                "Could not kill PID {}. Permission denied?".format(p["pid"]),
            )

    buttons = tk.Frame(root)
    buttons.pack(fill="x", padx=8, pady=(0, 8))
    tk.Button(buttons, text="Scan", command=populate, width=12).pack(side="left")
    tk.Button(buttons, text="Kill Selected", command=on_kill, width=12).pack(side="left", padx=6)
    tk.Button(buttons, text="Quit", command=root.destroy, width=12).pack(side="right")

    populate()
    root.mainloop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Keylogger detection tool")
    parser.add_argument(
        "--gui",
        action="store_true",
        help="launch the graphical interface instead of the terminal scanner",
    )
    args = parser.parse_args()
    if args.gui:
        scan_gui()
    else:
        scan_cli()
