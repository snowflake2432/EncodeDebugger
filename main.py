import hashlib
import hmac
import tkinter as tk
from tkinter import ttk
import PIL.ImageTk
from PIL import Image
import base64 as b64

EncodeDe = tk.Tk()
EncodeDe.title("EncodeDebugger")
EncodeDe.resizable(0, 0)

tab = ttk.Notebook(EncodeDe)

tab1 = ttk.Frame(tab)
tab2 = ttk.Frame(tab)
tab3 = ttk.Frame(tab)

tab.add(tab1, text='Hash')
tab.add(tab2, text='Base64')
tab.grid()

# ###########################-----Hash-----#####################################
hidden = False


def toggle_entry(*args):
    global hidden
    if opt_sys.get() == "MD5 with salt":
        Salt_get.grid(row=7, column=0)
        label_a.grid(row=6, column=0)
    else:
        Salt_get.grid_remove()
        label_a.grid_remove()
    hidden = not hidden


def turn_to_hash():
    get_text = opt_sys.get()
    get_salt = Salt_get.get()
    if get_text == "MD5":
        Entry2.delete(0, "end")
        md5 = hashlib.md5(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, md5)
    elif get_text == "SHA-1":
        Entry2.delete(0, "end")
        sha1 = hashlib.sha1(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, sha1)
    elif get_text == "SHA-224":
        Entry2.delete(0, "end")
        sha224 = hashlib.sha224(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, sha224)
    elif get_text == "SHA-256":
        Entry2.delete(0, "end")
        sha256 = hashlib.sha256(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, sha256)
    elif get_text == "SHA-384":
        Entry2.delete(0, "end")
        sha384 = hashlib.sha384(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, sha384)
    elif get_text == "SHA-512":
        Entry2.delete(0, "end")
        sha512 = hashlib.sha512(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, sha512)
    elif get_text == "Blake2b":
        Entry2.delete(0, "end")
        Blake2b = hashlib.blake2b(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, Blake2b)
    elif get_text == "Blake2s":
        Entry2.delete(0, "end")
        Blake2s = hashlib.blake2s(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, Blake2s)
    elif get_text == "Shake-128":
        Entry2.delete(0, "end")
        shake_128 = hashlib.sha512(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, shake_128)
    elif get_text == "Hmac":
        Entry2.delete(0, "end")
        shake_128 = hmac.hexdigest(Entry1.get().encode(encoding='UTF-8')).hexdigest()
        Entry2.insert(tk.END, shake_128)
    elif get_text == "MD5 with salt":
        Entry2.delete(0, "end")
        hashed_password = hashlib.md5(Entry1.get().encode('utf-8') + get_salt.encode('utf-8')).hexdigest()
        Entry2.insert(tk.END, hashed_password)


photo = PIL.Image.open("logo-EncodeDebugger.png")
LOGO = PIL.ImageTk.PhotoImage(photo)
show = tk.Label(tab1, image=LOGO)
show.image = LOGO
show.grid(row=0, column=0)


def copy():
    EncodeDe.clipboard_clear()
    EncodeDe.clipboard_append(Entry2.get())


def clear():
    Entry1.delete(0, "end")
    Entry2.delete(0, "end")
    Salt_get.delete(0, "end")


String1 = tk.StringVar()
String1.set("Entry Text:")
label1 = tk.Label(tab1, textvariable=String1)
label1.grid(row=2, column=0)
Entry1 = tk.Entry(tab1)
Entry1.grid(row=3, column=0)
String2 = tk.StringVar()
String2.set("Output Text:")
label1 = tk.Label(tab1, textvariable=String2)
label1.grid(row=4, column=0)
Entry2 = tk.Entry(tab1)
Entry2.grid(row=5, column=0)
Salt = tk.StringVar()
Salt.set("Salt:")
label_a = tk.Label(tab1, textvariable=Salt)
Salt_get = tk.Entry(tab1)

Start = tk.Button(tab1, text='Start', command=turn_to_hash)
copy = tk.Button(tab1, text='Copy', command=copy)
Start.grid(row=3, column=1)
copy.grid(row=4, column=1)
clear = tk.Button(tab1, text='Clear', command=clear).grid(row=5, column=1)

OptionList = [
    "MD5",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "Shake-128",
    "Blake2b",
    "Blake2s",
    "MD5 with salt"]

opt_sys = tk.StringVar(EncodeDe)
opt_sys.set(OptionList[0])

opt = tk.OptionMenu(tab1, opt_sys, *OptionList)
opt.config(width=7)
opt.grid(column=1, row=2)

opt_sys.trace("w", toggle_entry)
###################################################################################################
############################################-Base64-###############################################

photo = PIL.Image.open("logo-EncodeDebugger-basepro.png")
LOGO = PIL.ImageTk.PhotoImage(photo)
show = tk.Label(tab2, image=LOGO)
show.image = LOGO
show.grid(row=0, column=0)


base64_entry_label = tk.StringVar()
base64_entry_label.set("Entry Text:")
base64_label = tk.Label(tab2, textvariable=String1)
base64_label.grid(row=2, column=0)
base64_ent = tk.Entry(tab2)
base64_ent.grid(row=3, column=0)
base64_out = tk.StringVar()
base64_out.set("Base64 Form:")
base64_out_lable = tk.Label(tab2, textvariable=String2)
base64_out_lable.grid(row=4, column=0)
base64_out_ent = tk.Entry(tab2)
base64_out_ent.grid(row=5, column=0)


def turn_to_base64():
    base64_out_ent.delete(0, "end")
    get_ent = base64_ent.get()
    encoded = get_ent.encode("ascii")
    base64_bytes = b64.b64encode(encoded)
    base64_string = base64_bytes.decode("ascii")
    base64_out_ent.insert(tk.END, base64_string)

#photo = tk.Button(tab2, text='Base64 photo', command=turn_to_base64)
start = tk.Button(tab2, text='Start', command=turn_to_base64)
#photo.grid(row=3, column=1)
start.grid(row=4, column=1)


EncodeDe.mainloop()
