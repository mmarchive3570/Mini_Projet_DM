import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import requests

API_URL = "http://192.168.1.77:8000"


class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Mini Projet - Cryptographie")
        root.geometry("520x320")
        root.configure(bg="#969696")

        self.cipher_type = tk.StringVar(value="AES")
        self.aes_buttons_visible = False
        self.rsa_buttons_visible = False

        # === Choix du chiffrement ===
        tk.Label(root, text="Choix du chiffrement :", bg="#969696", font=("Segoe UI", 10, "bold"))\
            .grid(row=0, column=0, sticky='e', padx=5, pady=5)
        tk.OptionMenu(root, self.cipher_type, "AES", "RSA")\
            .grid(row=0, column=1, sticky='w', padx=5, pady=5)

        # === AES ===
        tk.Label(root, text="Clé AES :", bg="#969696", font=("Segoe UI", 10, "bold"))\
            .grid(row=1, column=0, sticky='e', padx=5, pady=5)
        self.btn_load_aes = tk.Button(root, text="Charger", command=self.toggle_aes_buttons, width=12)
        self.btn_load_aes.grid(row=1, column=1, sticky='w', padx=5, pady=5)

        self.btn_generate_aes = tk.Button(root, text=" Générer", command=self.generate_aes_key,
                                          width=12, bg="#666666", fg="white")
        self.btn_save_aes = tk.Button(root, text=" Enregistrer", command=self.save_aes_key,
                                      width=12, bg="#6d6d6d", fg="white")

        # === RSA ===
        tk.Label(root, text="Clés RSA :", bg="#969696", font=("Segoe UI", 10, "bold"))\
            .grid(row=2, column=0, sticky='e', padx=5, pady=5)
        self.btn_load_rsa = tk.Button(root, text="Charger", command=self.toggle_rsa_buttons, width=12)
        self.btn_load_rsa.grid(row=2, column=1, sticky='w', padx=5, pady=5)

        self.btn_generate_rsa = tk.Button(root, text=" Générer", command=self.generate_rsa_keys,
                                          width=12, bg="#6d6d6d", fg="white")
        self.btn_save_rsa = tk.Button(root, text=" Enregistrer", command=self.save_rsa_keys,
                                      width=12, bg="#696969", fg="white")

        # === Boutons d’action (alignés) ===
        btn_frame = tk.Frame(root, bg="#969696")
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)

        tk.Button(btn_frame, text="Déchiffrer", command=self.decrypt_data,
                  width=12, bg="#8d8d8d", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(btn_frame, text="Chiffrer", command=self.encrypt_data,
                  width=12, bg="#8d8d8d", fg="white").grid(row=0, column=1, padx=10)
        tk.Button(btn_frame, text="SHA-256", command=self.hash_sha256,
                  width=12, bg="#8d8d8d", fg="white").grid(row=0, column=2, padx=10)

    # === AES ===
    def toggle_aes_buttons(self):
        """Affiche / cache les boutons de gestion AES"""
        if not self.aes_buttons_visible:
            self.btn_generate_aes.grid(row=1, column=2, padx=5)
            self.btn_save_aes.grid(row=1, column=3, padx=5)
            self.aes_buttons_visible = True
        else:
            self.btn_generate_aes.grid_remove()
            self.btn_save_aes.grid_remove()
            self.aes_buttons_visible = False

        filepath = filedialog.askopenfilename(title="Choisir la clé AES")
        if filepath:
            try:
                res = requests.post(f"{API_URL}/aes/load_key", data={"filename": filepath})
                messagebox.showinfo("Chargement AES", res.json().get("status", "Clé AES chargée."))
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de charger la clé AES : {e}")

    def generate_aes_key(self):
        try:
            res = requests.post(f"{API_URL}/aes/generate_key")
            messagebox.showinfo("Génération clé AES", res.json().get("status", "Clé AES générée."))
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de générer la clé AES : {e}")

    def save_aes_key(self):
        filepath = filedialog.asksaveasfilename(
            title="Enregistrer la clé AES",
            defaultextension=".key",
            filetypes=[("Fichier clé", "*.key")]
        )
        if filepath:
            try:
                res = requests.post(f"{API_URL}/aes/save_key", data={"filename": filepath})
                messagebox.showinfo("Sauvegarde AES", res.json().get("status", "Clé AES enregistrée."))
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d’enregistrer la clé AES : {e}")

    # === RSA ===
    def toggle_rsa_buttons(self):
        """Affiche / cache les boutons RSA + permet de charger les clés"""
        if not self.rsa_buttons_visible:
            self.btn_generate_rsa.grid(row=2, column=2, padx=5)
            self.btn_save_rsa.grid(row=2, column=3, padx=5)
            self.rsa_buttons_visible = True
        else:
            self.btn_generate_rsa.grid_remove()
            self.btn_save_rsa.grid_remove()
            self.rsa_buttons_visible = False

        pub = filedialog.askopenfilename(title="Clé publique RSA")
        priv = filedialog.askopenfilename(title="Clé privée RSA")
        if pub and priv:
            try:
                res = requests.post(f"{API_URL}/rsa/load_keys", data={"pub_file": pub, "priv_file": priv})
                messagebox.showinfo("Chargement RSA", res.json().get("status", "Clés RSA chargées."))
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de charger les clés RSA : {e}")

    def generate_rsa_keys(self):
        try:
            res = requests.post(f"{API_URL}/rsa/generate_keys")
            messagebox.showinfo("Génération clés RSA", res.json().get("status", "Paire de clés RSA générée."))
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de générer les clés RSA : {e}")

    def save_rsa_keys(self):
        """Sauvegarder les clés RSA (publique et privée)"""
        pub_path = filedialog.asksaveasfilename(
            title="Enregistrer la clé publique RSA",
            defaultextension=".pem",
            filetypes=[("Fichier PEM", "*.pem")]
        )
        priv_path = filedialog.asksaveasfilename(
            title="Enregistrer la clé privée RSA",
            defaultextension=".pem",
            filetypes=[("Fichier PEM", "*.pem")]
        )
        if pub_path and priv_path:
            try:
                res = requests.post(f"{API_URL}/rsa/save_keys", data={"pub_file": pub_path, "priv_file": priv_path})
                messagebox.showinfo("Sauvegarde RSA", res.json().get("status", "Clés RSA enregistrées."))
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible d’enregistrer les clés RSA : {e}")

    # === Chiffrement / Déchiffrement ===
    def encrypt_data(self):
        data = simpledialog.askstring("Chiffrement", "Texte à chiffrer :")
        if not data:
            return

        try:
            if self.cipher_type.get() == "AES":
                res = requests.post(f"{API_URL}/aes/encrypt_string", data={"data": data})
            else:
                res = requests.post(f"{API_URL}/rsa/encrypt", data={"data": data})
            messagebox.showinfo("Résultat", res.json().get("encrypted", "Erreur"))
        except Exception as e:
            messagebox.showerror("Erreur", f"Chiffrement échoué : {e}")

    def decrypt_data(self):
        data = simpledialog.askstring("Déchiffrement", "Texte chiffré (Base64) :")
        if not data:
            return

        try:
            if self.cipher_type.get() == "AES":
                res = requests.post(f"{API_URL}/aes/decrypt_string", data={"data": data})
            else:
                res = requests.post(f"{API_URL}/rsa/decrypt", data={"data": data})
            messagebox.showinfo("Résultat", res.json().get("decrypted", "Erreur"))
        except Exception as e:
            messagebox.showerror("Erreur", f"Déchiffrement échoué : {e}")

    # === SHA-256 ===
    def hash_sha256(self):
        data = simpledialog.askstring("SHA-256", "Texte à hacher :")
        if data:
            try:
                res = requests.post(f"{API_URL}/hash/sha256", data={"data": data})
                messagebox.showinfo("SHA-256", res.json()["sha256"])
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de calculer SHA-256 : {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
