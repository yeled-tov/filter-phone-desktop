import tkinter as tk
import webbrowser

APP_NAME = "FilterPhone Desktop"
PROJECT_URL = "https://github.com/yeled-tov/filter-phone-desktop"
DASHBOARD_URL = "https://api.filterphone.com/admin"


class FilterPhoneDesktop:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry("520x390")
        root.minsize(480, 350)
        root.configure(bg="#f5f7fb")

        outer = tk.Frame(root, bg="#f5f7fb", padx=28, pady=24)
        outer.pack(fill="both", expand=True)

        tk.Label(
            outer, text="FilterPhone", font=("Segoe UI", 24, "bold"),
            fg="#12336b", bg="#f5f7fb"
        ).pack(anchor="w")
        tk.Label(
            outer, text="Desktop · Windows 10 / 11",
            font=("Segoe UI", 11), fg="#53627a", bg="#f5f7fb"
        ).pack(anchor="w", pady=(2, 18))

        status = tk.Frame(outer, bg="#fff0d6", padx=14, pady=12)
        status.pack(fill="x", pady=(0, 14))
        tk.Label(
            status, text="Prototype — filtering is NOT active",
            font=("Segoe UI", 12, "bold"), fg="#7a4200", bg="#fff0d6"
        ).pack(anchor="w")
        tk.Label(
            status,
            text=("This starter build does not yet connect a VPN or filter "
                  "web traffic. Do not rely on it for protection."),
            font=("Segoe UI", 10), fg="#633f18", bg="#fff0d6",
            wraplength=420, justify="left"
        ).pack(anchor="w", pady=(6, 0))

        tk.Label(
            outer,
            text=("The next development step is secure PC enrollment, "
                  "a unique VPN configuration, and integration with the "
                  "FilterPhone filtering server."),
            font=("Segoe UI", 10), fg="#27364d", bg="#f5f7fb",
            wraplength=450, justify="left"
        ).pack(anchor="w", pady=(2, 18))

        buttons = tk.Frame(outer, bg="#f5f7fb")
        buttons.pack(fill="x", side="bottom")
        tk.Button(
            buttons, text="Open FilterPhone dashboard",
            command=lambda: webbrowser.open(DASHBOARD_URL),
            font=("Segoe UI", 10), padx=10, pady=8
        ).pack(fill="x", pady=(0, 8))
        tk.Button(
            buttons, text="Open project on GitHub",
            command=lambda: webbrowser.open(PROJECT_URL),
            font=("Segoe UI", 10), padx=10, pady=8
        ).pack(fill="x")


if __name__ == "__main__":
    window = tk.Tk()
    FilterPhoneDesktop(window)
    window.mainloop()
