import json
import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, messagebox


def load_key():
    if os.path.exists(encryption_key_path):
        with open(encryption_key_path, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(encryption_key_path, "wb") as key_file:
            key_file.write(key)
        return key

def encrypt(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt(data, key):
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()

def save_data(data):
    encrypted_data = encrypt(json.dumps(data), load_key())
    with open("passwords.json", "w") as password_file:
        password_file.write(encrypted_data)

def retrieve_data():
    if not os.path.exists("passwords.json"):
        return {}
    with open("passwords.json", "r") as password_file:
        data = password_file.read()
        if data == "":
            return {}
        decrypted_data = decrypt(data, load_key())
        return json.loads(decrypted_data)

def retrieve_login_entry():
    website = input("Enter website: ")
    data = retrieve_data()
    if website not in data:
        print(f"Website not found")
        return
    print("Emails and Passwords for " + website + ":")
    for email in data[website]:
        print(f"{email}: {data[website][email]} ")

def create_login_entry():
    website = input("Enter website: ")
    email = input("Enter email: ")
    password = input("Enter password: ")
    data = retrieve_data()
    if website not in data:
        data[website] = {}
    data[website][email] = password
    save_data(json.dumps(data))
    print("Login registered successfully!")

def export_passwords():
    passwords_file = "passwords.json"
    if not os.path.exists(passwords_file):
        return "Passwords file not found."

    with open(passwords_file, "r") as file:
        encrypted_data = file.read()
        if encrypted_data == "":
            return f"Passwords file is empty."
        data = json.loads(decrypt(encrypted_data, load_key()))
        with open("passwords_decrypted.json", "w") as output_file:
            json.dump(data, output_file, indent=4)
            filename = "passwords_decrypted.json"
            output = os.path.abspath(filename)
            return f"Passwords exported successfully to %s" % output

def import_passwords():
    decrypted_file = "passwords_decrypted.json"
    if not os.path.exists(decrypted_file):
        return f"passwords_decrypted.json file not found."

    with open(decrypted_file, "r") as file:
        data = json.load(file)
        save_data(data)  # Remove the json.dumps() function call
        return f"Passwords imported successfully from passwords_decrypted.json"

def reset_encryption_key():
    export_passwords()
    if os.path.exists("passwords.json"):
        os.remove("passwords.json")
    if os.path.exists("encryption_key.key"):
        os.remove("encryption_key.key")
    load_key()
    import_passwords()
    if os.path.exists("passwords_decrypted.json"):
        os.remove("passwords_decrypted.json")
    print("Encryption key reset successfully!")

encryption_key_path = 'encryption_key.key'

class PasswordManagerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.create_main_window()

    def create_main_window(self):
        self.main_window = tk.Toplevel(self.root)
        self.main_window.title("Password Manager")

        self.notebook = ttk.Notebook(self.main_window)
        self.notebook.pack(fill=tk.BOTH, expand=False)

        self.create_retrieve_tab()
        self.create_register_tab()
        self.create_query_tab()
        self.create_operator_tools_tab()

    def create_retrieve_tab(self):
        retrieve_tab = ttk.Frame(self.notebook)
        self.notebook.add(retrieve_tab, text="Retrieve")

        website_label = ttk.Label(retrieve_tab, text="Website:")
        website_label.pack()

        self.website_entry = ttk.Entry(retrieve_tab)
        self.website_entry.pack()

        retrieve_button = ttk.Button(retrieve_tab, text="Retrieve", command=self.retrieve_login_entry)
        retrieve_button.pack()

        self.retrieve_result_label = ttk.Label(retrieve_tab)
        self.retrieve_result_label.pack()

    def retrieve_login_entry(self):
        website = self.website_entry.get()
        data = retrieve_data()
        if website in data:
            result = ""
            for email, password in data[website].items():
                result += f"Email: {email}, Password: {password}\n"
            self.retrieve_result_label.configure(text=result)
        else:
            messagebox.showinfo("Website Not Found", "Website not found.")

    def create_register_tab(self):
        register_tab = ttk.Frame(self.notebook)
        self.notebook.add(register_tab, text="Register")

        website_label = ttk.Label(register_tab, text="Website:")
        website_label.pack()

        self.register_website_entry = ttk.Entry(register_tab)
        self.register_website_entry.pack()

        email_label = ttk.Label(register_tab, text="Email:")
        email_label.pack()

        self.register_email_entry = ttk.Entry(register_tab)
        self.register_email_entry.pack()

        password_label = ttk.Label(register_tab, text="Password:")
        password_label.pack()

        self.register_password_entry = ttk.Entry(register_tab, show="*")
        self.register_password_entry.pack()

        register_button = ttk.Button(register_tab, text="Register", command=self.create_login_entry)
        register_button.pack()

        self.register_result_label = ttk.Label(register_tab)
        self.register_result_label.pack()

    def create_login_entry(self):
        website = self.register_website_entry.get()
        email = self.register_email_entry.get()
        password = self.register_password_entry.get()
        data = retrieve_data()
        if website not in data:
            data[website] = {}
        data[website][email] = password
        save_data(data)
        self.register_result_label.configure(text="Login registered successfully!")

    def create_query_tab(self):
        query_tab = ttk.Frame(self.notebook)
        self.notebook.add(query_tab, text="Query")

        self.query_listbox = tk.Listbox(query_tab)
        self.query_listbox.pack()

        query_button = ttk.Button(query_tab, text="Query", command=self.query_websites)
        query_button.pack()

    def query_websites(self):
        data = retrieve_data()
        self.query_listbox.delete(0, tk.END)
        for website in data:
            self.query_listbox.insert(tk.END, website)

    def create_operator_tools_tab(self):
        operator_tools_tab = ttk.Frame(self.notebook)
        self.notebook.add(operator_tools_tab, text="Operator Tools")

        export_button = ttk.Button(operator_tools_tab, text="Export Passwords", command=self.export_passwords)
        export_button.pack()

        import_button = ttk.Button(operator_tools_tab, text="Import Passwords", command=self.import_passwords)
        import_button.pack()

        reset_button = ttk.Button(operator_tools_tab, text="Reset Key", command=self.reset_encryption_key)
        reset_button.pack()

    def export_passwords(self):
        result = export_passwords()
        messagebox.showinfo("Export Passwords", result)

    def import_passwords(self):
        result = import_passwords()
        messagebox.showinfo("Import Passwords", result)

    def reset_encryption_key(self):
        result = reset_encryption_key()
        messagebox.showinfo("Reset Encryption Key", result)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.run()
