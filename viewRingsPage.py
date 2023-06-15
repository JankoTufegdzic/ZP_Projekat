import tkinter as tk
from tkinter import ttk




def viewRingsFrame(publicRing:dict,privateRing:dict,email):

    viewRings=tk.Frame()

    viewRingsLabel=tk.Label(viewRings,text="View rings",font=("Arial",16))
    viewRingsLabel.pack(anchor="nw", padx=10, pady=10,fill="x")

    privateRingLabel = tk.Label(viewRings, text="Private ring", font=("Arial", 12))
    privateRingLabel.pack(anchor="nw", padx=10, pady=10)

    privateRingTable = tk.Text(viewRings, height=10,width=80)
    privateRingTable.config(bg="green")
    privateRingTable.pack(anchor="nw", padx=10, pady=10)

    myPrivate=privateRing.get(email)
    if myPrivate is None:
        myPrivate={}
    i=0
    for j in myPrivate.keys():
        privateRingTable.insert(f"{i}.0",f"{myPrivate[j]}\n") #samo javni kljuc pise
        i+=1

    privateRingTable.config(state="disabled")

    publicRingLabel = tk.Label(viewRings, text="Public ring", font=("Arial", 12))
    publicRingLabel.pack(anchor="nw", padx=10, pady=10)

    publicRingTable = tk.Text(viewRings, height=10, width=80)
    publicRingTable.config(bg="lightblue")
    publicRingTable.pack(anchor="nw", padx=10, pady=10)

    i=0
    for j in publicRing.keys():
        publicRingTable.insert(f"{i}.0", f"{publicRing[j]}\n")#samo javni kljuc pise
        i += 1

    publicRingTable.config(state="disabled")

    return viewRings




