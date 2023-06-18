import tkinter as tk
from tkinter import ttk , messagebox

from keyManipulation import getHash,decryptPrivateKey


def viewRingsFrame(publicRing:dict,privateRing:dict,email):
    def showInfo():
        top = tk.Toplevel()

        top.geometry("350x150")
        top.title("Enter password")

        tmpFrame=tk.Frame(top)
        entry_label = tk.Label(tmpFrame, text="Choose id:")
        entry_label.pack(side=tk.LEFT,padx=10,pady=10)

        id_var = tk.StringVar()
        combo = ttk.Combobox(tmpFrame, textvariable=id_var,values=list(privateRing[email].keys()) if email in privateRing.keys() else [],state="readonly")
        combo.pack(side=tk.LEFT,padx=10,pady=10)
        tmpFrame.pack(padx=10)


        tmpFrame2=tk.Frame(top)
        entry_label = tk.Label(tmpFrame2, text="Enter password")
        entry_label.pack(side=tk.LEFT,padx=10,pady=10)

        pass_var = tk.StringVar()
        entry = tk.Entry(tmpFrame2,textvariable=pass_var)
        entry.pack(side=tk.LEFT,padx=10,pady=10)
        tmpFrame2.pack(padx=10)

        ok_button = tk.Button(top, text='OK', command=lambda: checkPassword(pass_var.get(),int(id_var.get()), top))
        ok_button.pack(pady=10, padx=20)

        top.wait_window()

    def checkPassword(passw,id,top):
        hs,hashed=getHash(passw)
        key=decryptPrivateKey(passw,privateRing[email][id].pr,privateRing[email][id].password,privateRing[email][id].alg)
        if key is not None:
            details=""
            if privateRing[email][id].alg=="RSA":
                details="d: "+str(key.d)
            else:
                details = "x: " + str(key.x)
                
            messagebox.showinfo("Details",details)
        else:
            messagebox.showerror("Error","Wrong password!")
        top.destroy()
    viewRings=tk.Frame()

    viewRingsLabel=tk.Label(viewRings,text="View rings",font=("Arial",16))
    viewRingsLabel.pack(anchor="nw", padx=10, pady=10,fill="x")

    tmp=tk.Frame(viewRings)
    privateRingLabel = tk.Label(tmp, text="Private ring", font=("Arial", 12))
    privateRingLabel.pack(side=tk.LEFT, padx=10, pady=10)

    infoButton=tk.Button(tmp,text="More details",command=showInfo)
    infoButton.pack(side=tk.RIGHT, padx=10, pady=10)

    tmp.pack(fill="both")

    privateRingTable = tk.Text(viewRings, height=10,width=80)
    privateRingTable.pack(anchor="nw", padx=10, pady=10)

    myPrivate=privateRing.get(email)
    if myPrivate is None:
        myPrivate={}

    i=1
    for j in myPrivate.keys():
        privateRingTable.insert(f"{i}.0",f"ID: {j}\n")
        privateRingTable.insert(f"{i+1}.0", f"{myPrivate[j]}\n")
        i += 5

    privateRingTable.config(state="disabled")

    publicRingLabel = tk.Label(viewRings, text="Public ring", font=("Arial", 12))
    publicRingLabel.pack(anchor="nw", padx=10, pady=10)

    publicRingTable = tk.Text(viewRings, height=10, width=80)
    publicRingTable.pack(anchor="nw", padx=10, pady=10)

    k=1
    for j in publicRing.keys():
        publicRingTable.insert(f"{k}.0", f"ID: {j}\n")
        publicRingTable.insert(f"{k+1}.0", f"{publicRing[j]}")#samo javni kljuc pise
        k += 30

    publicRingTable.config(state="disabled")

    return viewRings




