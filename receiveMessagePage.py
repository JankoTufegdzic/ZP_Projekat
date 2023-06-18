import tkinter as tk
from tkinter import ttk , messagebox,filedialog
from main import  receiveMessage


def receiveMessageFrame(publicRing,privateRing,email,users):


    def selectMessage():
        file_path = filedialog.askopenfilename()
        if file_path:
            #TODO: MORA DA UNESE VREDNOST PASSWORDA!!


            b64,auth,encr,zip,error,toRecv,user = receiveMessage(email,'1',file_path)

            if error == "":
                signatureLabel.config(text="Signature is ok!", foreground="green")
            else:
                signatureLabel.config(text=error, foreground="red")
                return


            authLabel.config(state="normal")
            encrLabel.config(state="normal")
            zipLabel.config(state="normal")
            base64Label.config(state="normal")
            textLabel.config(state="normal")
            text.config(state="normal")
            saveButton.config(state="normal")

            if auth:
                authLabel.config(foreground="green")
            else:
                authLabel.config(foreground="red")

            if zip:
                zipLabel.config(foreground="green")
            else:
                zipLabel.config(foreground="red")
            if b64:
                base64Label.config(foreground="green")
            else:
                base64Label.config(foreground="red")
            if encr:
                encrLabel.config(foreground="green")
            else:
                encrLabel.config(foreground="red")


            text.insert("1.0", "Timestamp: "+str(toRecv["ts"])+"\n")
            if auth==1:

                for u in users:
                    if(u.username==user):
                        us=u

                text.insert("2.0", "User: "+ f' {us.name} "{us.username}" '+"\n")
            text.insert("3.0", "Data: "+toRecv["data"]+"\n")
            text.config(state="disabled")

    def saveMessage():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:

            with open(file_path,"w") as f:
                f.write(text.get("1.0","end-1c"))


    receiveMessageFrame=tk.Frame()

    receiveMessageFrame.grid_columnconfigure(0,weight=0)
    receiveMessageFrame.grid_columnconfigure(1,weight=1)
    receiveMessageFrame.grid_columnconfigure(2,weight=0)

    receiveMessageFrameLabel=tk.Label(receiveMessageFrame,text="Receive Message" ,font=("Arial",16))
    receiveMessageFrameLabel.grid(row=0,column=1,sticky="w")

    receiveMessageFrameButton=tk.Button(receiveMessageFrame,text="Receive",command=selectMessage)
    receiveMessageFrameButton.grid(row=0, column=2, sticky="e",pady=10,padx=10)

    authLabel = tk.Label(receiveMessageFrame, text="Authentication", font=("Arial", 12),state="disabled")
    authLabel.grid(row=1, column=0, sticky="nw", padx=10, pady=10)
    encrLabel = tk.Label(receiveMessageFrame, text="Encryption", font=("Arial", 12),state="disabled")
    encrLabel.grid(row=2, column=0, sticky="nw", padx=10, pady=10)
    zipLabel = tk.Label(receiveMessageFrame, text="ZIP", font=("Arial", 12),state="disabled")
    zipLabel.grid(row=3, column=0, sticky="nw", padx=10, pady=10)
    base64Label = tk.Label(receiveMessageFrame, text="Base64", font=("Arial", 12),state="disabled")
    base64Label.grid(row=4, column=0, sticky="nw", padx=10, pady=10)

    signatureLabel=tk.Label(receiveMessageFrame,font=("Arial",12))
    signatureLabel.grid(row=1, column=1, padx=10, pady=10)

    #text
    textLabel = tk.Label(receiveMessageFrame, text="Text:", font=("Arial", 12),state="disabled")
    textLabel.grid(row=5, column=0, sticky="nw", padx=10, pady=10)

    text = tk.Text(receiveMessageFrame, height=3, width=70,state="disabled")
    text.grid(row=5, column=1, padx=20)

    #save button
    saveButton=tk.Button(receiveMessageFrame,text="Save message",command=saveMessage,state="disabled")
    saveButton.grid(row=6,column=0,columnspan=4,padx=10,pady=10)

    return receiveMessageFrame


