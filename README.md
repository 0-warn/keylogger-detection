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

---

- In this projects I used `psutil` which gives us a totoal control of our system like cpu, fan, process, etc. 
- Now i checked the process using `psutil` and it's process checking function (`psutil.process_iter`).

--- 
### Future upgrades (pending)

- Check is the same process connecting to internet or not.
- If it is suspecious then stop the process by asking user.
- GUI Implementation for user usability.
