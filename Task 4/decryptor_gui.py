from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox

# ===== AES Decryption Class =====
class AESCipher:
    def __init__(self, password):
        self.password = password

    def unpad(self, data):
        return data[:-data[-1]]

    def decrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                iv = f.read(16)
                ciphertext = f.read()

            key = PBKDF2(self.password, salt, dkLen=32, count=1000000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = self.unpad(cipher.decrypt(ciphertext))

            dec_file = file_path.replace(".enc", ".dec")
            with open(dec_file, 'wb') as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as {dec_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed!\n{str(e)}")

# ===== GUI Functions =====
def browse_file():
    filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    file_entry.delete(0, 'end')
    file_entry.insert(0, filename)

def decrypt_action():
    file_path = file_entry.get().strip()
    password = password_entry.get().strip()

    if not file_path:
        messagebox.showwarning("Error", "Please select a file!")
        return
    if not password:
        messagebox.showwarning("Error", "Please enter the password!")
        return

    cipher = AESCipher(password)
    cipher.decrypt_file(file_path)

# ===== GUI Layout =====
root = Tk()
root.title("AES-256 File Decryptor")
root.geometry("600x250")  # Bigger window ensures button is visible

Label(root, text="Select Encrypted File (.enc):").pack(pady=(10,5))
file_entry = Entry(root, width=60)
file_entry.pack(pady=(0,5))
Button(root, text="Browse", command=browse_file).pack(pady=(0,10))

Label(root, text="Enter Password:").pack(pady=(5,5))
password_entry = Entry(root, width=60, show="*")
password_entry.pack(pady=(0,15))

Button(root, text="Decrypt", command=decrypt_action, bg="red", fg="white", width=20).pack(pady=(10,20))

root.mainloop()
