import tkinter as tk
from tkinter import ttk , messagebox,filedialog
from main import sendMessage
from keyManipulation import getHash


def sendMessageFrame(publicRing,privateRing,email,password):
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

        passw=privateRing[email][int(authKeyId_var.get())].password
        print(passw)
        ok_button = tk.Button(top, text='OK', command=lambda: checkPassword(entry_var.get(), top,passw))
        ok_button.pack(pady=10, fill="x", padx=20)

    authPass=None
    def checkPassword(input_text, top,passw):
        global authPass
        top.destroy()
        hp,_=getHash(input_text)

        if hp != passw:
            messagebox.showinfo('Result', "Netacna lozinka!")
            authKeyId_var.set("Choose id")
        else:
            messagebox.showinfo('Result', "Ok!")
            authPass=input_text

    def saveMessage():
        global authPass
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            publicKeyAuthId=None
            publicKeyEncrId=None
            encrAlg=None
            zip=False
            b64=False
            if auth_var.get()==1:
                publicKeyAuthId=int(authKeyId_var.get())
            if encr_var.get()==1:
                publicKeyEncrId = int(encrKeyId_var.get())
                encrAlg=algo_var.get()
            if zip_var.get()==1:
                zip=True
            if base64_var.get()==1:
                b64=True
            print(publicKeyAuthId,publicKeyEncrId,encrAlg,zip,b64)

            sendMessage(email, authPass, text.get("1.0",'end-1c'), file_path, publicKeyAuthID=publicKeyAuthId, publicKeyEncrID=publicKeyEncrId, encrAlg=encrAlg,zip=zip,base64encode=b64)
           #generate message and save file here
            print("Exporting to:", file_path)
    def getForUser(id):
        lista=[]
        for  key in publicRing:
            algo = options_var.get()
            if publicRing[key].userID==id and publicRing[key].alg!="DSA" and algo.find(publicRing[key].alg)!=-1:
                lista.append(key)

        return lista

    def updatePrivate():
        if email in privateRing.keys():
            privateKeys = []
            for i in privateRing[email].keys():
                algo=options_var.get()
                if privateRing[email][i].alg != "ElGamal" and algo.find(privateRing[email][i].alg)!=-1:
                    privateKeys.append(i)
        else:
            privateKeys = []

        authKeyId_list['value']=privateKeys

    def changeAlgos(*args):

        l=getForUser(toUser_var.get())
        encrKeyId_list['values']=l #TODO:ispravka

        updatePrivate()


    def getUsers():
        return list(privateRing.keys())

    def getInitialPublic():
        return getForUser(email)




    def changeUser(*args):
        newId=toUser_var.get()
        publicKeys=getForUser(newId)
        encrKeyId_list = ttk.OptionMenu(sendMessageFrame, encrKeyId_var, *publicKeys)
        encrKeyId_list.grid(row=3, column=3, sticky="nw", padx=10, pady=10)

    sendMessageFrame = tk.Frame()

    sendMessageFrame.columnconfigure(0, weight=1,minsize=100)
    sendMessageFrame.columnconfigure(1, weight=0,minsize=30)
    sendMessageFrame.columnconfigure(2, weight=1,minsize=100)
    sendMessageFrame.columnconfigure(3, weight=1,minsize=150)

    sendMessageFrameLabel = tk.Label(sendMessageFrame, text="Send Message", font=("Arial", 16))
    sendMessageFrameLabel.grid(row=0, column=1, sticky="nw", padx=10, pady=10)


    chooseOptLabel=tk.Label(sendMessageFrame,text="Select algorithm",font=("Arial",12))
    chooseOptLabel.grid(column=2, row=0)

    options=["RSA","DSA+ElGamal"]

    options_var=tk.StringVar(value="RSA")
    chooseCombOption=ttk.OptionMenu(sendMessageFrame,options_var,"RSA",*options)
    chooseCombOption.grid(column=3,row=0)

    options_var.trace("w",changeAlgos)

    authLabel = tk.Label(sendMessageFrame, text="Authentication", font=("Arial", 12))
    authLabel.grid(row=1, column=0, sticky="nw", padx=10, pady=10)
    encrLabel = tk.Label(sendMessageFrame, text="Encryption", font=("Arial", 12))
    encrLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)
    zipLabel = tk.Label(sendMessageFrame, text="ZIP", font=("Arial", 12))
    zipLabel.grid(row=3, column=0, sticky="nw", padx=10, pady=10)
    base64Label = tk.Label(sendMessageFrame, text="Base64", font=("Arial", 12))
    base64Label.grid(row=4, column=0, sticky="nw", padx=10, pady=10)

    if email in privateRing.keys():
        privateKeys =[]
        for i in privateRing[email].keys():
            if privateRing[email][i].alg != "ElGamal":
                privateKeys.append(i)
    else:
        privateKeys=[]

    users = getUsers()
    publicKeys =getInitialPublic()

#Authentication
    auth_var = tk.IntVar()
    authCheckbox = tk.Checkbutton(sendMessageFrame, text="Select", variable=auth_var,
                                  command=toggle_authentication_visibility)
    authCheckbox.grid(row=1, column=1, sticky="nw", padx=10, pady=10)

    privateLabel = tk.Label(sendMessageFrame, text="Private key ID:", font=("Arial", 10),state="disabled")
    privateLabel.grid(row=1, column=2, sticky="nw", padx=10, pady=10)


    authKeyId_var = tk.StringVar()
    authKeyId_var.set("Choose Id")
    authKeyId_list = ttk.Combobox(sendMessageFrame, values=privateKeys, textvariable=authKeyId_var)
    authKeyId_list.grid(row=1, column=3, sticky="nw", padx=10, pady=10)
    authKeyId_list.config(state="disabled")

    authKeyId_list.bind("<<ComboboxSelected>>",selectPrivateKey)

#Encryption
    encr_var = tk.IntVar()
    encrCheckbox = tk.Checkbutton(sendMessageFrame, text="Select", variable=encr_var, command=toggle_encryption_visibility)
    encrCheckbox.grid(row=2, column=1, sticky="nw", padx=10, pady=10)


    userLabel = tk.Label(sendMessageFrame, text="User:", font=("Arial", 10), state="disabled")
    userLabel.grid(row=2, column=2, sticky="nw", padx=10, pady=10)

    toUser_var=tk.StringVar()
    toUser_list = ttk.OptionMenu(sendMessageFrame, toUser_var,email, *users)
    toUser_list.config(state="disabled")
    toUser_list.grid(row=2, column=3, sticky="nw", padx=10, pady=10)

    toUser_var.trace("w",changeUser)

    publicLabel = tk.Label(sendMessageFrame, text="Public key ID:", font=("Arial", 10), state="disabled")
    publicLabel.grid(row=3, column=2, sticky="nw", padx=10, pady=10)

    encrKeyId_var = tk.StringVar()
    encrKeyId_list = ttk.Combobox(sendMessageFrame, textvariable=encrKeyId_var,values=publicKeys)
    encrKeyId_list.config(state="disabled")
    encrKeyId_list.grid(row=3, column=3, sticky="nw", padx=10, pady=10)

    algoLabel=tk.Label(sendMessageFrame, text="Algorithm:", font=("Arial", 10),state="disabled")
    algoLabel.grid(row=4, column=2, sticky="nw", padx=10, pady=10)

    algorithms=["AES","3DES"]
    algo_var = tk.StringVar(value="AES")
    algo_list = ttk.OptionMenu(sendMessageFrame, algo_var,*algorithms)
    algo_list.config(state="disabled")
    algo_list.grid(row=4, column=3, sticky="nw", padx=10, pady=10)

#ZIP
    zip_var = tk.IntVar()
    zipCheckbox = tk.Checkbutton(sendMessageFrame, text="Select", variable=zip_var)
    zipCheckbox.grid(row=3, column=1, sticky="nw", padx=10, pady=10)

#Base64
    base64_var = tk.IntVar()
    base64Checkbox = tk.Checkbutton(sendMessageFrame, text="Select", variable=base64_var)
    base64Checkbox.grid(row=4, column=1, sticky="nw", padx=10, pady=10)

#Text

    textLabel= tk.Label(sendMessageFrame, text="Text:", font=("Arial", 12))
    textLabel.grid(row=5, column=0, sticky="nw", padx=10, pady=10)

    text=tk.Text(sendMessageFrame,height=3,width=70)
    text.grid(row=5,column=1,columnspan=4,padx=20)
#Send

    sendMButton=tk.Button(sendMessageFrame,text="Send message",command=saveMessage)
    sendMButton.grid(row=6,columnspan=6, padx=20, pady=10)

    return sendMessageFrame
