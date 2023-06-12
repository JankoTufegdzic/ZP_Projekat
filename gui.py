import tkinter as tk
from tkinter import ttk

email = None
password = None


def goToSimulation():
    notebook.add(main_tab, text="Simulation")
    notebook.hide(login_tab)
    notebook.select(main_tab)


def onLogin():
    global email, password
    email = username_entry.get()
    password = password_entry.get()
    print(email, password)
    goToSimulation()


def backToLogin():
    notebook.add(login_tab, text="Login")
    notebook.hide(main_tab)
    notebook.select(login_tab)


# Create the main window
window = tk.Tk()
window.title("PGP simulator")
window.geometry("800x600")

# Create a Notebook widget
notebook = ttk.Notebook(window)

login_tab = tk.Frame(notebook)
notebook.add(login_tab, text="Login")


# LOGIN PAGE

def validate_entries(*args):
    if password_var.get() and username_var.get():
        login_button.config(state=tk.NORMAL)
    else:
        login_button.config(state=tk.DISABLED)

login_label = tk.Label(login_tab, text="Log in", font=("Arial", 26), foreground="red")
login_label.grid(row=0, column=0, rowspan=2, columnspan=2, pady=100)

username_label = tk.Label(login_tab, text="Email:", font=("Arial", 12))
password_label = tk.Label(login_tab, text="Password:", font=("Arial", 12))
username_label.grid(row=3, column=0, padx=10, pady=10, sticky="e")
password_label.grid(row=4, column=0, padx=10, pady=5, sticky="e")

username_var=tk.StringVar()
username_entry = tk.Entry(login_tab, font=("Arial", 12),textvariable=username_var)
password_var=tk.StringVar()
password_entry = tk.Entry(login_tab, show="*", font=("Arial", 12),textvariable=password_var)
username_entry.grid(row=3, column=1, padx=10, pady=5)
password_entry.grid(row=4, column=1, padx=10, pady=5)

username_var.trace("w", validate_entries)
password_var.trace("w", validate_entries)


login_button = tk.Button(login_tab, text="Login", command=onLogin, font=("Arial", 16, "bold"), state=tk.DISABLED)
login_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)



login_tab.columnconfigure(0, weight=1)
login_tab.columnconfigure(1, weight=1)

# END OF LOGIN PAGE

# MAIN PAGE
main_tab = tk.Frame(notebook)
back_button = tk.Button(main_tab, text="Back", command=backToLogin)
back_button.grid(row=0, column=0, sticky="nw", padx=10, pady=10)

# END OF MAIN PAGE

notebook.pack(fill="both", expand=True)

window.mainloop()
