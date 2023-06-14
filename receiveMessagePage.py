import tkinter as tk
from tkinter import ttk , messagebox,filedialog

def receiveMessageFrame(publicRing,privateRing):

    def selectMessage():
        file_path = filedialog.askopenfilename()
        if file_path:
            authLabel.config(state="normal")
            encrLabel.config(state="normal")
            zipLabel.config(state="normal")
            base64Label.config(state="normal")
            textLabel.config(state="normal")
            text.config(state="normal")
            saveButton.config(state="normal")

            authLabel.config(foreground="red")
            zipLabel.config(foreground="green")
            base64Label.config(foreground="green")
            encrLabel.config(foreground="red")

            #neka if provera da li je dobar potpis pa onda:
            signatureLabel.config(text="Signature is ok!",foreground="green")

            #else
            #signatureLabel.config(text="Signature is ok!",foreground="red")

            text.insert("1.0", "Ide gas")# text poruke

    def saveMessage():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:

            with open(file_path,"w") as f:
                f.write(text.get("1.0","end-1c"))


    receiveMessage=tk.Frame()

    receiveMessage.grid_columnconfigure(0,weight=0)
    receiveMessage.grid_columnconfigure(1,weight=1)
    receiveMessage.grid_columnconfigure(2,weight=0)

    receiveMessageLabel=tk.Label(receiveMessage,text="Receive Message" ,font=("Arial",16))
    receiveMessageLabel.grid(row=0,column=1,sticky="w")

    receiveMessageButton=tk.Button(receiveMessage,text="Receive",command=selectMessage)
    receiveMessageButton.grid(row=0, column=2, sticky="e",pady=10,padx=10)

    authLabel = tk.Label(receiveMessage, text="Authentication", font=("Arial", 12),state="disabled")
    authLabel.grid(row=1, column=0, sticky="nw", padx=10, pady=10)
    encrLabel = tk.Label(receiveMessage, text="Encryption", font=("Arial", 12),state="disabled")
    encrLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)
    zipLabel = tk.Label(receiveMessage, text="ZIP", font=("Arial", 12),state="disabled")
    zipLabel.grid(row=3, column=0, sticky="nw", padx=10, pady=10)
    base64Label = tk.Label(receiveMessage, text="Base64", font=("Arial", 12),state="disabled")
    base64Label.grid(row=4, column=0, sticky="nw", padx=10, pady=10)

    signatureLabel=tk.Label(receiveMessage,font=("Arial",12))
    signatureLabel.grid(row=1, column=1, padx=10, pady=10)

    #TODO: ROW 2 I 3 COLUMN 1 SU INFORMACIJE O POTPISIVACU, NEMA MNOGO POSLA SAMO DA VIDIMO STA CEMO I KAKO!



    #text
    textLabel = tk.Label(receiveMessage, text="Text:", font=("Arial", 12),state="disabled")
    textLabel.grid(row=5, column=0, sticky="nw", padx=10, pady=10)

    text = tk.Text(receiveMessage, height=3, width=70,state="disabled")
    text.grid(row=5, column=1, padx=20)

    #save button
    saveButton=tk.Button(receiveMessage,text="Save message",command=saveMessage,state="disabled")
    saveButton.grid(row=6,column=0,columnspan=4,padx=10,pady=10)

    return receiveMessage


