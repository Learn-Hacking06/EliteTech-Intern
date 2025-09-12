from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox

# ===== AES Encryption Class =====
class AESCipher:
    def __init__(self, password):
        self.password = password

    def pad(self, data):
        padding_len = AES.block_size - len(data) % AES.block_size
        return data + bytes([padding_len]) * padding_len

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            salt = get_random_bytes(16)
            iv = get_random_bytes(16)
            key = PBKDF2(self.password, salt, dkLen=32, count=1000000)
            plaintext = self.pad(plaintext)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(plaintext)
            enc_file = file_path + ".enc"
            with open(enc_file, 'wb') as f:
                f.write(salt + iv + ciphertext)
            messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as {enc_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed!\n{str(e)}")

# ===== GUI Functions =====
def browse_file():
    filename = filedialog.askopenfilename()
    file_entry.delete(0, 'end')
    file_entry.insert(0, filename)

def encrypt_action():
    file_path = file_entry.get().strip()
    password = password_entry.get().strip()
    confirm = confirm_entry.get().strip()

    if not file_path:
        messagebox.showwarning("Error", "Please select a file!")
        return
    if not password or not confirm:
        messagebox.showwarning("Error", "Please enter and confirm your password!")
        return
    if password != confirm:
        messagebox.showwarning("Error", "Passwords do not match!")
        return

    cipher = AESCipher(password)
    cipher.encrypt_file(file_path)

# ===== GUI Layout =====
root = Tk()
root.title("AES-256 File Encryptor")

# Force a bigger window so all fields and buttons are visible
root.geometry("600x300")

# Use pack with padding to prevent overlapping
Label(root, text="Select File:").pack(pady=(10, 2))
file_entry = Entry(root, width=60)
file_entry.pack(pady=(0,5))
Button(root, text="Browse", command=browse_file).pack(pady=(0,10))

Label(root, text="Enter Password:").pack(pady=(5,2))
password_entry = Entry(root, width=60, show="*")
password_entry.pack(pady=(0,10))

Label(root, text="Confirm Password:").pack(pady=(5,2))
confirm_entry = Entry(root, width=60, show="*")
confirm_entry.pack(pady=(0,15))

Button(root, text="Encrypt", command=encrypt_action, bg="green", fg="white", width=20).pack(pady=(10,20))

root.mainloop()
