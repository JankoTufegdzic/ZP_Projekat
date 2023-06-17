import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from receiveMessagePage import receiveMessageFrame
from sendMessagePage import sendMessageFrame
from viewRingsPage import viewRingsFrame

from main import generateKeys, privateRing, publicRing,loadKeyFromPemFormat,saveKeyInPemFormat,deleteKeys
from keyManipulation import getHash,decryptPrivateKey

email = None
password = None


def refreshPages():
    global viewRings, sendMessage, receiveMessage, email

    viewRings = viewRingsFrame(publicRing, privateRing, email)
    sendMessage = sendMessageFrame(publicRing, privateRing, email,password)
    receiveMessage = receiveMessageFrame(publicRing, privateRing, email, password)

    notebook.add(main_tab, text="Keys")
    notebook.add(sendMessage, text="Send Message")
    notebook.add(receiveMessage, text="Receive Message")
    notebook.add(viewRings, text="View Rings")

    backButton = tk.Button(receiveMessage, text="Log out", command=backToLogin)
    backButton.grid(row=0, column=0, sticky="nw", padx=10, pady=10)

    backButton = tk.Button(sendMessage, text="Log out", command=backToLogin)
    backButton.grid(row=0, column=0, sticky="nw", padx=10, pady=10)


def updateLists():
    privateKeysList.set('')
    privateKeysList['value'] = list(privateRing[email]) if email in privateRing.keys() else []

    publicKeysList.set('')
    publicKeysList['value'] = list(publicRing.keys())

    deletePairList.set('')
    deletePairList['value'] = list(publicRing.keys())


def goToSimulation():
    notebook.forget(login_tab)
    refreshPages()
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
    notebook.forget(main_tab)
    notebook.forget(receiveMessage)
    notebook.forget(sendMessage)
    notebook.forget(viewRings)
    notebook.select(login_tab)


window = tk.Tk()
window.title("PGP simulator")
window.geometry("800x600")

# Create a Notebook widget
notebook = ttk.Notebook(window)

login_tab = tk.Frame(notebook)
notebook.add(login_tab, text="Login")

sendMessage = sendMessageFrame(publicRing, privateRing, email,password)
receiveMessage = receiveMessageFrame(publicRing, privateRing, email, password)
viewRings = viewRingsFrame(publicRing, privateRing, email)
main_tab = tk.Frame(notebook)

notebook.add(main_tab, text="Keys")
notebook.add(sendMessage, text="Send Message")
notebook.add(receiveMessage, text="Receive Message")
notebook.add(viewRings, text="View Rings")

notebook.hide(main_tab)
notebook.hide(sendMessage)
notebook.hide(receiveMessage)
notebook.hide(viewRings)


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

back_button = tk.Button(keyGen, text="Log out", command=backToLogin)
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
    generateKeys(username_entry.get(), email_var.get(), algo_var.get(), int(keyLength_var.get()), password_var.get())

    updateLists()

    # update pages
    global sendMessage, viewRings, receiveMessage, email
    notebook.forget(sendMessage)
    notebook.forget(viewRings)
    notebook.forget(receiveMessage)

    refreshPages()

    #
    messagebox.showinfo('Prompt', 'Keys are generated.')


keyGenLabel = tk.Label(keyGen, text="Generate keys", font=("Arial", 16))
keyGenLabel.grid(row=0, column=1, sticky="nw", padx=10, pady=10)

keyGenLabel = tk.Label(keyGen, text="Select key length")
keyGenLabel.grid(row=1, column=0, sticky="nw", padx=10, pady=10)

keyGenLabel = tk.Label(keyGen, text="Select algorithm")
keyGenLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)

lengths = ["1024", "2048"]
algorithms = ["RSA", "DSA", "ElGamal"]

keyLength_var = tk.StringVar(value="1024")
keyLength = ttk.Combobox(keyGen, values=lengths, textvariable=keyLength_var, state='readonly')
keyLength.grid(row=1, column=1, sticky="nw", padx=10, pady=10)

algo_var = tk.StringVar(value="RSA")
algorithm = ttk.Combobox(keyGen, values=algorithms, textvariable=algo_var, state='readonly')
algorithm.grid(row=2, column=1, sticky="nw", padx=10, pady=10)

email_label = tk.Label(keyGen, text="Email:")
email_label.grid(row=1, column=2, sticky="nw", padx=10, pady=10)

email_var = tk.StringVar()
email_entry = tk.Entry(keyGen, textvariable=email_var)
email_entry.grid(row=1, column=3, sticky="nw", padx=10, pady=10)

username_label = tk.Label(keyGen, text="Username:")
username_label.grid(row=2, column=2, sticky="nw", padx=10, pady=10)

username_var = tk.StringVar()
username_entry = tk.Entry(keyGen, textvariable=username_var)
username_entry.grid(row=2, column=3, sticky="nw", padx=10, pady=10)

password_label = tk.Label(keyGen, text="Password:")
password_label.grid(row=1, column=4, sticky="nw", padx=10, pady=10)

password_var = tk.StringVar()
password_entry = tk.Entry(keyGen, textvariable=password_var, show="*", state="disabled")
password_entry.grid(row=1, column=5, sticky="nw", padx=10, pady=10)

generate_button = tk.Button(keyGen, text="Generate keys", state=tk.DISABLED, command=generate)
generate_button.grid(row=2, column=5, columnspan=2, sticky="nw", padx=10, pady=10)

username_var.trace("w", validate_inputs)
email_var.trace("w", validate_inputs)

password_var.trace("w", validate_password)


# END OF KEY GENERATING

# KEY IMPORT/EXPORT

def importPrivateKey():
    file_path = filedialog.askopenfilename()
    if file_path:
        print("Selected file:", file_path)
        top = tk.Toplevel()
        top.geometry("200x100")
        top.title('Enter password')

        entry_label = tk.Label(top, text='Enter password for private key ')
        entry_label.pack()

        entry_var = tk.StringVar()
        entry = tk.Entry(top, textvariable=entry_var, show="*")
        entry.pack()

        ok_button = tk.Button(top, text='OK', command=lambda: privateAddToRing(entry_var.get(), top,file_path))
        ok_button.pack(pady=10, fill="x", padx=20)


def privateAddToRing(passw, top,file):
    global privateRing, email
    top.destroy()

    loadKeyFromPemFormat(file,email,passw)


    updateLists()

    notebook.forget(sendMessage)
    notebook.forget(viewRings)
    notebook.forget(receiveMessage)
    refreshPages()

    messagebox.showinfo('Result', "Import successful")


def importPublicKey():
    global publicRing, sendMessage, viewRings, receiveMessage, email
    file_path = filedialog.askopenfilename()
    if file_path:
        print("Selected file:", file_path)

        loadKeyFromPemFormat(file_path,email)

        # Update padajuce liste
        updateLists()

        notebook.forget(sendMessage)
        notebook.forget(viewRings)
        notebook.forget(receiveMessage)
        refreshPages()
        messagebox.showinfo('Result', "Import successful")


def enablePrivate(*args):
    if privateKey_var.get():
        exportPrivateKeyButton.config(state=tk.NORMAL)
    else:
        exportPrivateKeyButton.config(state=tk.DISABLED)


def enablePublic(*args):
    if publicKey_var.get():
        exportPublicKeyButton.config(state=tk.NORMAL)
    else:
        exportPublicKeyButton.config(state=tk.DISABLED)


def exportPublic():
    file_path = filedialog.asksaveasfilename(defaultextension=".pem")
    if file_path:
        saveKeyInPemFormat(publicRing[int(publicKey_var.get())].pu,file_path,publicRing[int(publicKey_var.get())].alg)
        print("Exporting to:", file_path)


def exportPrivate():
    top = tk.Toplevel()
    top.geometry("200x100")
    top.title('Enter password')

    entry_label = tk.Label(top, text='Enter password for private key ')
    entry_label.pack()

    entry_var = tk.StringVar()
    entry = tk.Entry(top, textvariable=entry_var, show="*")
    entry.pack()

    ok_button = tk.Button(top, text='OK', command=lambda: checkPassword(entry_var.get(), top))
    ok_button.pack(pady=10, fill="x", padx=20)


def checkPassword(input_text, top):
    top.destroy()
    hp,hashedPass=getHash(input_text)
    if hp != privateRing[email][int(privateKey_var.get())].password:
        messagebox.showinfo('Result', "Wrong password!")
    else:
        file_path = filedialog.asksaveasfilename(defaultextension=".pem")
        if file_path:
            key=decryptPrivateKey(input_text,privateRing[email][int(privateKey_var.get())].pr,hp,privateRing[email][int(privateKey_var.get())].alg)
            if key is None:
                return
            saveKeyInPemFormat(key,file_path,privateRing[email][int(privateKey_var.get())].alg)
            print("Exporting to:", file_path)


importExportlabel = tk.Label(keyImportExport, text="Import/Export keys", font=("Arial", 16))
importExportlabel.grid(row=0, column=1, sticky="nw", padx=10, pady=10)

publicKeys = []
privateKeys = []


# DELETING PAIR (in import/export)
def enableDelete(*args):
    if deletePair_var.get() == "Choose id":
        deleteButton.config(state=tk.DISABLED)
    else:
        deleteButton.config(state=tk.NORMAL
                            )


def deletePair(key):
    deleteKeys(key,email)
    updateLists()
    print(f"Deleted {key}")


deletePairLabel = tk.Label(keyImportExport, text="Delete pair", font=("Arial", 16))
deletePairLabel.grid(row=0, column=5, sticky="nw", padx=10, pady=10)

choosePairLabel = tk.Label(keyImportExport, text="Choose pair", font=("Arial", 12))
choosePairLabel.grid(row=1, column=5, sticky="nw", padx=10, pady=10)

deletePair_var = tk.StringVar(value="Choose id")
deletePairList = ttk.Combobox(keyImportExport, values=publicKeys, textvariable=deletePair_var, state="readonly")
deletePairList.grid(row=2, column=5, sticky="nw", padx=10, pady=10)

deleteButton = tk.Button(keyImportExport, text="Delete pair", state=tk.DISABLED,
                         command=lambda: deletePair(int(deletePair_var.get())))
deleteButton.grid(row=3, column=5, sticky="nw", padx=10, pady=10)

deletePair_var.trace("w", enableDelete)

# END DELETING PAIR (in import/export)

separator = ttk.Separator(keyImportExport, orient="vertical")
separator.grid(row=0, column=4, sticky='ns', padx=5)

importKeysLabel = tk.Label(keyImportExport, text="Import keys", font=("Arial", 12))
exportKeysLabel = tk.Label(keyImportExport, text="Export keys", font=("Arial", 12))
importKeysLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)
exportKeysLabel.grid(row=3, column=0, sticky="nw", padx=10, pady=10)

publicImportExportlabel = tk.Label(keyImportExport, text="Public keys", font=("Arial", 12))
publicImportExportlabel.grid(row=1, column=1, sticky="nw", padx=10, pady=10)

privateImportExportlabel = tk.Label(keyImportExport, text="Private keys", font=("Arial", 12))
privateImportExportlabel.grid(row=1, column=3, sticky="nw", padx=10, pady=10)

importPublicKeyButton = tk.Button(keyImportExport, text="Import", command=importPublicKey)
importPublicKeyButton.grid(row=2, column=1, sticky="nw", padx=30, pady=10)

importPrivateKeyButton = tk.Button(keyImportExport, text="Import", command=importPrivateKey)
importPrivateKeyButton.grid(row=2, column=3, sticky="nw", padx=30, pady=10)

publicKey_var = tk.StringVar()
publicKeysList = ttk.Combobox(keyImportExport, values=publicKeys, textvariable=publicKey_var, state="readonly")
publicKeysList.grid(row=3, column=1, sticky="nw", padx=30, pady=10)

privateKey_var = tk.StringVar()
privateKeysList = ttk.Combobox(keyImportExport, values=privateKeys, textvariable=privateKey_var, state="readonly")
privateKeysList.grid(row=3, column=3, sticky="nw", padx=30, pady=10)

exportPublicKeyButton = tk.Button(keyImportExport, text="Export", state=tk.DISABLED, command=exportPublic)
exportPublicKeyButton.grid(row=4, column=1, sticky="nw", padx=30, pady=10)

exportPrivateKeyButton = tk.Button(keyImportExport, text="Export", state=tk.DISABLED, command=exportPrivate)
exportPrivateKeyButton.grid(row=4, column=3, sticky="nw", padx=30, pady=10)

privateKey_var.trace("w", enablePrivate)
publicKey_var.trace("w", enablePublic)
# END OF KEY IMPORT/EXPORT

# END OF MAIN PAGE

notebook.pack(fill="both", expand=True)

window.mainloop()
