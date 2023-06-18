import tkinter as tk
from tkinter import ttk




def viewRingsFrame(publicRing:dict,privateRing:dict,email):

    viewRings=tk.Frame()

    viewRingsLabel=tk.Label(viewRings,text="View rings",font=("Arial",16))
    viewRingsLabel.pack(anchor="nw", padx=10, pady=10,fill="x")

    privateRingLabel = tk.Label(viewRings, text="Private ring", font=("Arial", 12))
    privateRingLabel.pack(anchor="nw", padx=10, pady=10)

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
        k += 6

    publicRingTable.config(state="disabled")

    return viewRings




