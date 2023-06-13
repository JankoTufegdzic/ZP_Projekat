import tkinter as tk
from tkinter import ttk,messagebox

email = None
password = None


def goToSimulation():
    notebook.add(main_tab, text="Simulation")
    notebook.hide(login_tab)
    notebook.select(main_tab)


def onLogin():
    global email, password
    email = login_username_entry.get()
    password = login_password_entry.get()
    login_username_var.set("")
    login_password_var.set("")
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
    if login_password_var.get() and login_username_var.get():
        login_button.config(state=tk.NORMAL)
    else:
        login_button.config(state=tk.DISABLED)


login_label = tk.Label(login_tab, text="Log in", font=("Arial", 26), foreground="red")
login_label.grid(row=0, column=0, rowspan=2, columnspan=2, pady=100)

login_email_label = tk.Label(login_tab, text="Email:", font=("Arial", 12))
password_label = tk.Label(login_tab, text="Password:", font=("Arial", 12))
login_email_label.grid(row=3, column=0, padx=10, pady=10, sticky="e")
password_label.grid(row=4, column=0, padx=10, pady=5, sticky="e")

login_username_var = tk.StringVar()
login_username_entry = tk.Entry(login_tab, font=("Arial", 12), textvariable=login_username_var)
login_password_var = tk.StringVar()
login_password_entry = tk.Entry(login_tab, show="*", font=("Arial", 12), textvariable=login_password_var)
login_username_entry.grid(row=3, column=1, padx=10, pady=5)
login_password_entry.grid(row=4, column=1, padx=10, pady=5)

login_username_var.trace("w", validate_entries)
login_password_var.trace("w", validate_entries)

login_button = tk.Button(login_tab, text="Login", command=onLogin, font=("Arial", 16, "bold"), state=tk.DISABLED)
login_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

login_tab.columnconfigure(0, weight=1)
login_tab.columnconfigure(1, weight=1)

# END OF LOGIN PAGE

# MAIN PAGE
main_tab = tk.Frame(notebook)

main_tab.grid_rowconfigure(0, weight=1)
main_tab.grid_rowconfigure(1, weight=1)
main_tab.grid_rowconfigure(2, weight=1)
main_tab.grid_columnconfigure(0, weight=1)
main_tab.grid_columnconfigure(1, weight=1)
main_tab.grid_columnconfigure(2, weight=1)
main_tab.grid_columnconfigure(3, weight=1)

# Create three frames for each part

keyGen = tk.Frame(main_tab)

keyGen.grid(row=0, column=0, sticky="nsew")

back_button = tk.Button(keyGen, text="Back", command=backToLogin)
back_button.grid(row=0, column=0, sticky="nw", padx=10, pady=10)

keyImportExport = tk.Frame(main_tab)
keyImportExport.grid(row=1, column=0, sticky="nsew")

showRing = tk.Frame(main_tab)
showRing.grid(row=2, column=0, sticky="nsew")


# KEY GENERATING
def validate_inputs(*args):
    if email_var.get() and username_var.get():
        password_entry.config(state=tk.NORMAL)
    else:
        password_entry.config(state=tk.DISABLED)

def validate_password(*args):
    if password_var.get():
        generate_button.config(state=tk.NORMAL)
    else:
        generate_button.config(state=tk.DISABLED)

def generate():
    messagebox.showinfo('Prompt', 'This is the prompt text.')

keyGenLabel = tk.Label(keyGen, text="Generate keys", font=("Arial", 16))
keyGenLabel.grid(row=0, column=1, sticky="nw", padx=10, pady=10)

keyGenLabel = tk.Label(keyGen, text="Select key length")
keyGenLabel.grid(row=1, column=0, sticky="nw", padx=10, pady=10)

keyGenLabel = tk.Label(keyGen, text="Select algorithm")
keyGenLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)

lengths = [1024, 2048]
algorithms = ["RSA", "DSA+ElGamal"]

keyLength_var = tk.StringVar(value="1024")
keyLength = ttk.Combobox(keyGen, values=lengths, textvariable=keyLength_var, state='readonly')
keyLength.grid(row=1, column=1, sticky="nw", padx=10, pady=10)

algo_var = tk.StringVar(value="RSA")
algorithm = ttk.Combobox(keyGen, values=algorithms, textvariable=algo_var, state='readonly')
algorithm.grid(row=2, column=1, sticky="nw", padx=10, pady=10)

email_label=tk.Label(keyGen,text="Email:")
email_label.grid(row=1, column=2, sticky="nw", padx=10, pady=10)

email_var = tk.StringVar()
email_entry = tk.Entry(keyGen, textvariable=email_var)
email_entry.grid(row=1, column=3, sticky="nw", padx=10, pady=10)

username_label=tk.Label(keyGen,text="Username:")
username_label.grid(row=2, column=2, sticky="nw", padx=10, pady=10)

username_var = tk.StringVar()
username_entry = tk.Entry(keyGen, textvariable=username_var)
username_entry.grid(row=2, column=3, sticky="nw", padx=10, pady=10)


password_label=tk.Label(keyGen,text="Password:")
password_label.grid(row=1, column=4, sticky="nw", padx=10, pady=10)

password_var = tk.StringVar()
password_entry = tk.Entry(keyGen, textvariable=password_var,show="*",state="disabled")
password_entry.grid(row=1, column=5, sticky="nw", padx=10, pady=10)

generate_button=tk.Button(keyGen,text="Generate keys",state=tk.DISABLED,command=generate)
generate_button.grid(row=2,column=5,columnspan=2,sticky="nw", padx=10, pady=10)

username_var.trace("w",validate_inputs)
email_var.trace("w",validate_inputs)

password_var.trace("w",validate_password)
# END OF KEY GENERATING

# END OF MAIN PAGE

notebook.pack(fill="both", expand=True)

window.mainloop()
