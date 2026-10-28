import secrets
import string
import tkinter as tk

CHARS = string.ascii_letters + string.digits + string.punctuation
LENGTH = 16


def generate():
    password = "".join(secrets.choice(CHARS) for _ in range(LENGTH))
    result.set(password)


root = tk.Tk()
root.title("Password Generator")

result = tk.StringVar()
tk.Entry(root, textvariable=result, width=30, state="readonly").pack(padx=10, pady=10)
tk.Button(root, text="Generate", command=generate).pack(pady=(0, 10))

root.mainloop()