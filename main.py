from tkinter import *
from tkinter import messagebox
import base64

window = Tk()
window.title("Secret Notes")
window.minsize(width=400,height=700)
window.config(padx=10,pady=10)
FONT = ('Arial',10,'normal')
# Functions
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

def save_and_encrypt():
    title = title_entry.get()
    message = text_text.get("1.0",END)
    master = master_entry.get()
    if  len(title) == 0 or len(message) == 0 or len(master) == 0:
        messagebox.showinfo(title="Error",message="Please enter all info.")
    else:
        message_encrypted = encode(master, message)
        try:
            with open("secret-file.txt","a") as fptr:
                fptr.write(f"\n{title}\n{message_encrypted}")
        except:
            messagebox.showerror(title="Error",message="Something went wrong!!")
        finally:
            title_entry.delete(0, END)
            text_text.delete("1.0", END)
            master_entry.delete(0, END)
            messagebox.showinfo(title="Done!", message="Successful")

def decrypt():
    message_encrypted = text_text.get("1.0",END)
    master = master_entry.get()
    if len(message_encrypted) == 0 or len(master) == 0:
        messagebox.showinfo(text="Error!",message="Please enter all info!")
    else:
        try:
            message_decrypted = decode(master,message_encrypted)
            text_text.delete("1.0",END)
            text_text.insert("1.0",message_decrypted)
        except:
            messagebox.showinfo(title="Error!", message="Try again!")

# GUI
photo_image = PhotoImage(file="secret.png")
canvas = Canvas(height=200,width=200)
canvas.create_image(100,100,image=photo_image)
canvas.pack()

title_label = Label(window,text="Enter your title",width=40,pady=5,padx=5,font=FONT)
title_label.pack()
title_entry = Entry(window,width=40,font=FONT)
title_entry.pack()

text_label = Label(window,text="Enter your text",font=FONT)
text_label.pack()
text_text = Text(window,padx=10,pady=10,width=37,height=20,font=FONT)
text_text.pack()

master_label = Label(window,text="Enter your master key",pady=5,padx=5,font=FONT)
master_label.pack()
master_entry = Entry(window,width=30,font=FONT)
master_entry.pack()

save_button = Button(window,text="Save & Encrypt",command=save_and_encrypt,font=FONT)
save_button.pack()
decrypt_button = Button(window,text="Decrypt",command=decrypt,font=FONT)
decrypt_button.pack()

window.mainloop()