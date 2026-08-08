#!/usr/bin/env python3
import psutil

SUSPECIOUS_KEYWORDS = ["pyinput", "keyboard", "keylog"]


def scan_processes():
    print("Scanning running process.....")
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            for word in SUSPECIOUS_KEYWORDS:
                if word in cmdline.lower():
                    print(
                        f"[!] Suspecious proccess found: {proc.info['name']} (PID: {proc.info['pid']})"
                    )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


if __name__ == "__main__":
    scan_processes()
