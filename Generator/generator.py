import tkinter as tk
import winsound
from tkinter import *

from Crypto.PublicKey import RSA
from PIL import Image, ImageTk


class App(tk.Tk):
    """GUI Class"""

    def __init__(self):
        super().__init__()
        self.configure(bg="#2e3440")
        # self.geometry('459x750')
        self.resizable(0, 0)
        self.title("HOLY_FLARE")
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
        load = Image.open("image.png")
        render = ImageTk.PhotoImage(load)
        img = Label(self, image=render, borderwidth=0, highlightthickness=0)
        img.image = render
        img.grid(column=0, row=0, sticky=tk.N)

        # heading
        heading = tk.Label(
            self, text="NEURON v1.0.1 [HOLY_FLARE]", font=("Helvetica", 13), background="#2e3440", foreground="white"
        )
        heading.grid(column=0, row=1, columnspan=2, pady=5, sticky=tk.N)

        """
        # Creates our options
        var = tk.StringVar()
        r1 = tk.Radiobutton(self, text='.txt', variable=var, value=1, background='#2e3440', foreground="white", font=('Helvetica', 13), selectcolor='#4c566a')
        r1.grid(column=0, row = 2, padx=10, pady=10, sticky=tk.W)
        r2 = tk.Radiobutton(self, text='.jpg', variable=var, value=2, background='#2e3440', foreground="white", font=('Helvetica', 13), selectcolor='#4c566a')
        r2.grid(column=0, row = 2, pady=10, sticky=tk.N)
        r3 = tk.Radiobutton(self, text='All Files', variable=var, value=3, background='#2e3440', foreground="white", font=('Helvetica', 13), selectcolor='#4c566a')
        r3.grid(column=0, row = 2, padx=25, pady=10, sticky=tk.E)
        var.set(3)
        """

        # Gen button
        login_button = tk.Button(
            self,
            text="GENERATE CRYPT STUB",
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
            text="[~] NEURON >> Generating our new master key...",
        )
        gen_label.grid(column=0, row=4, sticky=tk.W)

        # Generates RSA Encryption + Decryption keys / Public + Private keys
        key = RSA.generate(2048)

        private_key = key.export_key()
        with open("private.pem", "wb") as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open("public.pem", "wb") as f:
            f.write(public_key)

        gen2_label = tk.Label(
            self,
            background="#2e3440",
            font=("Helvetica", 13),
            foreground="white",
            text="[~] NEURON >> Keys generated, saving to files...",
        )
        gen2_label.grid(column=0, row=5, sticky=tk.W)
        gen3_label = tk.Label(
            self,
            background="#2e3440",
            font=("Helvetica", 13),
            foreground="white",
            wraplength=459,
            text="[~] NEURON >> Done! Your public key is.. 'public.pem'",
        )
        gen3_label.grid(column=0, row=6, sticky=tk.W)
        gen4_label = tk.Label(
            self,
            background="#2e3440",
            font=("Helvetica", 13),
            foreground="white",
            wraplength=459,
            text="[~] NEURON >> Done! Your private key is.. 'private.pem'",
        )
        gen4_label.grid(column=0, row=7, sticky=tk.W)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
