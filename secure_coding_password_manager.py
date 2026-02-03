import tkinter as tk
from tkinter import messagebox
import bcrypt

# ---------------- SECURE IN-MEMORY STORAGE ----------------
users_db = {}          # username : hashed_password
password_store = []    # secure storage (masked view only)

# ---------------- SECURE REGISTER ----------------
def register_user():
    username = entry_reg_user.get().strip()
    password = entry_reg_pass.get().strip()

    # Input validation
    if not username or not password:
        messagebox.showerror("Validation Error", "All fields are mandatory")
        return

    if username in users_db:
        messagebox.showerror("Error", "User already exists")
        return

    # Secure password hashing
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users_db[username] = hashed_password

    messagebox.showinfo("Success", "User registered securely")
    entry_reg_user.delete(0, tk.END)
    entry_reg_pass.delete(0, tk.END)

# ---------------- SECURE LOGIN ----------------
def login_user():
    username = entry_log_user.get().strip()
    password = entry_log_pass.get().strip()

    # Authentication check
    if username in users_db and bcrypt.checkpw(password.encode(), users_db[username]):
        messagebox.showinfo("Success", "Secure Login Successful")
        open_secure_dashboard()
    else:
        messagebox.showerror("Access Denied", "Invalid credentials")

# ---------------- SECURE PASSWORD SAVE ----------------
def save_password():
    site = entry_site.get().strip()
    user = entry_site_user.get().strip()
    pwd = entry_site_pass.get().strip()

    if not site or not user or not pwd:
        messagebox.showerror("Validation Error", "All fields are required")
        return

    password_store.append({
        "site": site,
        "username": user,
        "password": pwd
    })

    messagebox.showinfo("Saved", "Password stored securely")
    entry_site.delete(0, tk.END)
    entry_site_user.delete(0, tk.END)
    entry_site_pass.delete(0, tk.END)

# ---------------- SECURE PASSWORD VIEW ----------------
def view_passwords():
    view = tk.Toplevel(root)
    view.title("Secure Password View")
    view.geometry("450x300")

    tk.Label(view, text="Stored Passwords (Masked)", font=("Arial", 14)).pack(pady=10)

    if not password_store:
        tk.Label(view, text="No records available").pack()
        return

    for record in password_store:
        masked = f"Website: {record['site']} | Username: {record['username']} | Password: ****"
        tk.Label(view, text=masked, anchor="w").pack(pady=2)

# ---------------- SECURE DASHBOARD ----------------
def open_secure_dashboard():
    dash = tk.Toplevel(root)
    dash.title("Secure Dashboard")
    dash.geometry("350x350")

    tk.Label(dash, text="Password Manager (Secure Mode)", font=("Arial", 14)).pack(pady=10)

    tk.Label(dash, text="Website").pack()
    global entry_site
    entry_site = tk.Entry(dash)
    entry_site.pack()

    tk.Label(dash, text="Username").pack()
    global entry_site_user
    entry_site_user = tk.Entry(dash)
    entry_site_user.pack()

    tk.Label(dash, text="Password").pack()
    global entry_site_pass
    entry_site_pass = tk.Entry(dash, show="*")
    entry_site_pass.pack()

    tk.Button(dash, text="Save Securely", command=save_password,
              bg="green", fg="white").pack(pady=8)

    tk.Button(dash, text="View Saved Passwords", command=view_passwords,
              bg="gray", fg="white").pack(pady=5)

# ---------------- MAIN WINDOW ----------------
root = tk.Tk()
root.title("Secure Coding Password Manager")
root.geometry("360x440")
root.resizable(False, False)

tk.Label(root, text="Secure Coding Password Manager", font=("Arial", 16)).pack(pady=10)

# Registration
tk.Label(root, text="Secure Registration", font=("Arial", 12)).pack()
entry_reg_user = tk.Entry(root)
entry_reg_user.pack()
entry_reg_pass = tk.Entry(root, show="*")
entry_reg_pass.pack()
tk.Button(root, text="Register Securely", command=register_user).pack(pady=5)

# Login
tk.Label(root, text="Secure Login", font=("Arial", 12)).pack(pady=10)
entry_log_user = tk.Entry(root)
entry_log_user.pack()
entry_log_pass = tk.Entry(root, show="*")
entry_log_pass.pack()
tk.Button(root, text="Login Securely", command=login_user,
          bg="blue", fg="white").pack(pady=10)

root.mainloop()
