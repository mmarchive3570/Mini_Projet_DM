import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests

API_URL = "http://192.168.1.77:8000"

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Mini Projet")
        root.geometry("420x250")
        root.configure(bg="#969696")  
        
        self.cipher_type = tk.StringVar(value="AES")

        # --- Choix du chiffrement ---
        tk.Label(root, text="Choix du chiffrement :", bg="#969696", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky='e', padx=5, pady=5)
        tk.OptionMenu(root, self.cipher_type, "AES", "RSA").grid(row=0, column=1, sticky='w', padx=5, pady=5)

        # --- Charger clé AES ---
        tk.Label(root, text="Clé AES :", bg="#969696", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky='e', padx=5, pady=5)
        tk.Button(root, text="Charger", command=self.load_aes_key, width=12).grid(row=1, column=1, sticky='w', padx=5, pady=5)

        # --- Charger clé RSA ---
        tk.Label(root, text="Clé RSA :", bg="#969696", font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky='e', padx=5, pady=5)
        tk.Button(root, text="Charger", command=self.load_rsa_keys, width=12).grid(row=2, column=1, sticky='w', padx=5, pady=5)

        # --- Boutons côte à côte ---
        btn_frame = tk.Frame(root, bg="#969696")
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)

        tk.Button(btn_frame, text="Déchiffrer", command=self.decrypt_data, width=12, bg="#8d8d8d", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(btn_frame, text="Chiffrer", command=self.encrypt_data, width=12, bg="#8d8d8d", fg="white").grid(row=0, column=1, padx=10)
        tk.Button(btn_frame, text="SHA-256", command=self.hash_sha256, width=12, bg="#8d8d8d", fg="white").grid(row=0, column=2, padx=10)

    # === Fonctions ===
    def load_aes_key(self):
        filepath = filedialog.askopenfilename(title="Choisir la clé AES")
        if filepath:
            res = requests.post(f"{API_URL}/aes/load_key", data={"filename": filepath})
            messagebox.showinfo("Chargement AES", res.json()["status"])

    def load_rsa_keys(self):
        pub = filedialog.askopenfilename(title="Clé publique RSA")
        priv = filedialog.askopenfilename(title="Clé privée RSA")
        if pub and priv:
            res = requests.post(f"{API_URL}/rsa/load_keys", data={"pub_file": pub, "priv_file": priv})
            messagebox.showinfo("Chargement RSA", res.json()["status"])

    def encrypt_data(self):
        data = simpledialog.askstring("Chiffrement", "Texte à chiffrer :")
        if not data:
            return

        if self.cipher_type.get() == "AES":
            res = requests.post(f"{API_URL}/aes/encrypt_string", data={"data": data})
        else:
            res = requests.post(f"{API_URL}/rsa/encrypt", data={"data": data})

        messagebox.showinfo("Résultat", res.json().get("encrypted", "Erreur"))

    def decrypt_data(self):
        data = simpledialog.askstring("Déchiffrement", "Texte chiffré (Base64) :")
        if not data:
            return

        if self.cipher_type.get() == "AES":
            res = requests.post(f"{API_URL}/aes/decrypt_string", data={"data": data})
        else:
            res = requests.post(f"{API_URL}/rsa/decrypt", data={"data": data})

        messagebox.showinfo("Résultat", res.json().get("decrypted", "Erreur"))

    def hash_sha256(self):
        data = simpledialog.askstring("SHA-256", "Texte à hacher :")
        if data:
            res = requests.post(f"{API_URL}/hash/sha256", data={"data": data})
            messagebox.showinfo("SHA-256", res.json()["sha256"])


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
