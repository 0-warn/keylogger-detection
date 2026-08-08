#!/usr/bin/env python3

from pynput import keyboard


def on_press(key):
    print(f"Key Pressed: {key}")


# Started the listner
listener = keyboard.Listener(on_press=on_press)
listener.start()
listener.join()
