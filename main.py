from tkinter import *
from tkinter import messagebox
import base64


window = Tk()
window.title("Secret Notes")
window.geometry("450x750")

img = PhotoImage(file="topsecret.png")
img_label = Label(window, image=img)
img_label.pack()

title_label = Label(text="Enter Your Title", font=('Arial', 10, 'bold'))
title_label.pack()

title_entry = Entry(width="35")
title_entry.focus()
title_entry.pack()

secret_label = Label(text="Enter Your Secret", font=('Arial', 10, 'bold'))
secret_label.pack()

secret_text = Text()
secret_text.config(height=19, width=40)
secret_text.pack()

master_label = Label(text="Enter Master Key", font=('Arial', 10, 'bold'))
master_label.pack()

master_entry = Entry(width="35")
master_entry.pack()

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def save_file():
    title = title_entry.get()
    secret = secret_text.get(1.0, END)
    key_entry = master_entry.get()

    if len(title) == 0 or len(secret) == 0 or len(key_entry) == 0:
        messagebox.showwarning(message="Please enter all information !")
    else:
        secret_encrypted = encode(key_entry, secret)
        text_file = open("notes.txt", mode="a")
        text_file.write(f'{title}\n{secret_encrypted}\n')
        title_entry.delete(0, END)
        secret_text.delete(1.0, END)
        master_entry.delete(0, END)
def decrypt_notes():
    msg = secret_text.get(1.0, END)
    key_entry = master_entry.get()

    if len(msg) == 0 or len(key_entry) == 0:
        messagebox.showwarning(message="Please enter all information")
    else:
        try:
            secret_decrypted = decode(key_entry, msg)
            secret_text.delete(1.0, END)
            secret_text.insert(1.0, secret_decrypted)
            master_entry.delete(0, END)
        except:
            messagebox.showwarning(message="Make sure you enter the correct information !")


save_button = Button(text="Save & Encrypt", font=('Arial', 9, 'bold'), relief=FLAT, command=save_file)
save_button.pack()

decrypt_button = Button(text="Decrypt", font=('Arial', 9, 'bold'), relief=FLAT, command=decrypt_notes)
decrypt_button.pack()

exit_button = Button(text="Exit", font=('Arial', 9, 'bold'), relief=FLAT, command=lambda: window.destroy())
exit_button.pack()

window.mainloop()