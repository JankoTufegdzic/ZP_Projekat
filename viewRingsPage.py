import tkinter as tk
from tkinter import ttk

lista=["janko","ciganija","bratunga"]


def viewRingsFrame():

    viewRings=tk.Frame()

    viewRingsLabel=tk.Label(viewRings,text="View rings",font=("Arial",16))
    viewRingsLabel.pack(anchor="nw", padx=10, pady=10,fill="x")

    privateRingLabel = tk.Label(viewRings, text="Private ring", font=("Arial", 12))
    privateRingLabel.pack(anchor="nw", padx=10, pady=10)

    privateRing = tk.Text(viewRings, height=10,width=80)
    privateRing.config(bg="green")
    privateRing.pack(anchor="nw", padx=10, pady=10)

    for i in range(len(lista)):
        privateRing.insert(f"{i}.0",f"{lista[i]}\n")

    #bitno da se stavi ovo da ne bi moglo da se menja, pri promeni promenimo na normal, upisemo, i onda disablujemo opet
    privateRing.config(state="disabled")

    publicRingLabel = tk.Label(viewRings, text="Public ring", font=("Arial", 12))
    publicRingLabel.pack(anchor="nw", padx=10, pady=10)

    publicRing = tk.Text(viewRings, height=10, width=80)
    publicRing.config(bg="lightblue")
    publicRing.pack(anchor="nw", padx=10, pady=10)

    for i in range(30):
        publicRing.insert(f"{i}.0", "iva\n")

        # bitno da se stavi ovo da ne bi moglo da se menja, pri promeni promenimo na normal, upisemo, i onda disablujemo opet
    publicRing.config(state="disabled")

    # button=tk.Button(viewRings,text="pls",command=dodaj)
    # button.pack()
    return viewRings




