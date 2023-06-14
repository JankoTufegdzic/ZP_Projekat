import tkinter as tk
from tkinter import ttk , messagebox,filedialog



def sendMessageFrame(publicRing,privateRing):
    def toggle_encryption_visibility():
        if encr_var.get() == 1:
            publicLabel.config(state="normal")
            encrKeyId_list.config(state="normal")
            algoLabel.config(state="normal")
            algo_list.config(state="normal")
            userLabel.config(state="normal")
            toUser_list.config(state="normal")
        else:
            encrKeyId_list.config(state="disabled")
            publicLabel.config(state="disabled")
            algoLabel.config(state="disabled")
            algo_list.config(state="disabled")
            userLabel.config(state="disabled")
            toUser_list.config(state="disabled")

    def toggle_authentication_visibility():
        if auth_var.get() == 1:
            privateLabel.config(state="normal")
            authKeyId_list.config(state="normal")
        else:
            privateLabel.config(state="disabled")
            authKeyId_list.config(state="disabled")

    def selectPrivateKey(event):
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
        if input_text != "sifra":
            messagebox.showinfo('Result', "Netacna lozinka!")
            authKeyId_var.set("Choose id")
        else:
            messagebox.showinfo('Result', "Ok!")

    def saveMessage():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
           #generate message and save file here
            print("Exporting to:", file_path)

    sendMessage = tk.Frame()

    sendMessage.columnconfigure(0, weight=1,minsize=100)
    sendMessage.columnconfigure(1, weight=0,minsize=30)
    sendMessage.columnconfigure(2, weight=1,minsize=100)
    sendMessage.columnconfigure(3, weight=1,minsize=150)



    sendMessageLabel = tk.Label(sendMessage, text="Send Message", font=("Arial", 16))
    sendMessageLabel.grid(row=0, column=1, sticky="nw", padx=10, pady=10)

    authLabel = tk.Label(sendMessage, text="Authentication", font=("Arial", 12))
    authLabel.grid(row=1, column=0, sticky="nw", padx=10, pady=10)
    encrLabel = tk.Label(sendMessage, text="Encryption", font=("Arial", 12))
    encrLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)
    zipLabel = tk.Label(sendMessage, text="ZIP", font=("Arial", 12))
    zipLabel.grid(row=3, column=0, sticky="nw", padx=10, pady=10)
    base64Label = tk.Label(sendMessage, text="Base64", font=("Arial", 12))
    base64Label.grid(row=4, column=0, sticky="nw", padx=10, pady=10)

    privateKeys = ["prvi", "drugi", "treci", "gas"]  # privremeno
    publicKeys = ["xxx", "yyy", "zzz", "piletina"]

#Authentication
    auth_var = tk.IntVar()
    authCheckbox = tk.Checkbutton(sendMessage, text="Select", variable=auth_var,
                                  command=toggle_authentication_visibility)
    authCheckbox.grid(row=1, column=1, sticky="nw", padx=10, pady=10)

    privateLabel = tk.Label(sendMessage, text="Private key ID:", font=("Arial", 10),state="disabled")
    privateLabel.grid(row=1, column=2, sticky="nw", padx=10, pady=10)


    authKeyId_var = tk.StringVar()
    authKeyId_var.set("Choose Id")
    authKeyId_list = ttk.Combobox(sendMessage, values=privateKeys, textvariable=authKeyId_var)
    authKeyId_list.grid(row=1, column=3, sticky="nw", padx=10, pady=10)
    authKeyId_list.config(state="disabled")

    authKeyId_list.bind("<<ComboboxSelected>>",selectPrivateKey)

#Encryption
    encr_var = tk.IntVar()
    encrCheckbox = tk.Checkbutton(sendMessage, text="Select", variable=encr_var, command=toggle_encryption_visibility)
    encrCheckbox.grid(row=2, column=1, sticky="nw", padx=10, pady=10)


    users=["pera","mika","laza"]

    userLabel = tk.Label(sendMessage, text="User:", font=("Arial", 10), state="disabled")
    userLabel.grid(row=2, column=2, sticky="nw", padx=10, pady=10)

    toUser_var=tk.StringVar()
    toUser_var.set(value="Choose user")
    toUser_list = ttk.OptionMenu(sendMessage, toUser_var, *users)
    toUser_list.config(state="disabled")
    toUser_list.grid(row=2, column=3, sticky="nw", padx=10, pady=10)

    publicLabel = tk.Label(sendMessage, text="Public key ID:", font=("Arial", 10), state="disabled")
    publicLabel.grid(row=3, column=2, sticky="nw", padx=10, pady=10)

    encrKeyId_var = tk.StringVar()
    encrKeyId_var.set(value="Choose id")
    encrKeyId_list = ttk.OptionMenu(sendMessage, encrKeyId_var,*publicKeys)
    encrKeyId_list.config(state="disabled")
    encrKeyId_list.grid(row=3, column=3, sticky="nw", padx=10, pady=10)


    algoLabel=tk.Label(sendMessage, text="Algorithm:", font=("Arial", 10),state="disabled")
    algoLabel.grid(row=4, column=2, sticky="nw", padx=10, pady=10)

    algorithms=["AES","3DES"]
    algo_var = tk.StringVar(value="AES")
    algo_list = ttk.OptionMenu(sendMessage, algo_var,*algorithms)
    algo_list.config(state="disabled")
    algo_list.grid(row=4, column=3, sticky="nw", padx=10, pady=10)

#ZIP
    zip_var = tk.IntVar()
    zipCheckbox = tk.Checkbutton(sendMessage, text="Select", variable=zip_var)
    zipCheckbox.grid(row=3, column=1, sticky="nw", padx=10, pady=10)

#Base64
    base64_var = tk.IntVar()
    base64Checkbox = tk.Checkbutton(sendMessage, text="Select", variable=base64_var)
    base64Checkbox.grid(row=4, column=1, sticky="nw", padx=10, pady=10)

#Text

    textLabel= tk.Label(sendMessage, text="Text:", font=("Arial", 12))
    textLabel.grid(row=5, column=0, sticky="nw", padx=10, pady=10)

    text=tk.Text(sendMessage,height=3,width=70)
    text.grid(row=5,column=1,columnspan=4,padx=20)
#Send

    sendMButton=tk.Button(sendMessage,text="Send message",command=saveMessage)
    sendMButton.grid(row=6,columnspan=6, padx=20, pady=10)

    return sendMessage
