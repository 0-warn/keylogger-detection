# keylogger-detection
This is a keylogger detection for my internship at internvision. 

### Usage

```
./klog_dct
```

This will run the binary file which is compiled version of `klog_dct.py` and this is a very simple version.

- OpenSourced version
```
python3 klog_dct.py
```

- GUI version
```
python3 klog_dct.py --gui
```

---

- In this projects I used `psutil` which gives us a totoal control of our system like cpu, fan, process, etc. 
- Now i checked the process using `psutil` and it's process checking function (`psutil.process_iter`).
- The scanner also checks if a suspicious process has any active internet connections using `psutil.Process.net_connections` and reports the remote address it is connected to.
- If a suspicious process is found, you will be asked whether you want to stop (kill) it. Answering `y` terminates the process.

--- 
### Features

- [x] Check is the same process connecting to internet or not.
- [x] If it is suspecious then stop the process by asking user.
- [x] GUI Implementation for user usability.
