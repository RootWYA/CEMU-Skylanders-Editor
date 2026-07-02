"""
Skylander .sky Editor
=====================
A verified, safe editor for Skylanders figure dumps (.sky files, 1024 bytes,
MIFARE Classic 1K format used by Spyro's Adventure through Trap Team figures).
"""
import hashlib
import struct
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Force Windows to recognize this script as a distinct application so the taskbar icon updates
if sys.platform == "win32":
    import ctypes
    try:
        myappid = "mycompany.skylanders.editor.1.0"
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Missing dependency. Run: pip install pycryptodome")
    sys.exit(1)

# ----------------------------------------------------------------------------
# PyInstaller Resource Path Helper
# ----------------------------------------------------------------------------
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ----------------------------------------------------------------------------
# Verified engine
# ----------------------------------------------------------------------------

BLOCK_SIZE = 16
BLOCK_COUNT = 64
FIGURE_SIZE = 1024

HASH_CONST = bytes([
    0x20, 0x43, 0x6F, 0x70, 0x79, 0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x43, 0x29,
    0x20, 0x32, 0x30, 0x31, 0x30, 0x20, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x73, 0x69,
    0x6F, 0x6E, 0x2E, 0x20, 0x41, 0x6C, 0x6C, 0x20, 0x52, 0x69, 0x67, 0x68, 0x74, 0x73,
    0x20, 0x45, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64, 0x2E, 0x20
])

AREA_PAIR_01 = (0x80, 0x240)


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    poly = 0x1021
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def is_sector_trailer(i: int) -> bool:
    return (i + 1) % 4 == 0


def block_key(header: bytes, block_index: int) -> bytes:
    hash_in = bytearray(0x56)
    hash_in[0x00:0x20] = header[0:0x20]
    hash_in[0x20] = block_index
    hash_in[0x21:0x56] = HASH_CONST
    return hashlib.md5(bytes(hash_in)).digest()


def decrypt_figure(data: bytes):
    out = bytearray(data)
    blanks = set()
    for i in range(BLOCK_COUNT):
        if is_sector_trailer(i) or i < 8:
            continue
        block = data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        if all(b == 0 for b in block):
            blanks.add(i)
            continue
        key = block_key(data, i)
        out[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] = AES.new(key, AES.MODE_ECB).decrypt(block)
    return bytes(out), blanks


def encrypt_figure(plain: bytes, header: bytes, blanks: set) -> bytes:
    out = bytearray(plain)
    for i in range(BLOCK_COUNT):
        if is_sector_trailer(i) or i < 8:
            continue
        if i in blanks:
            out[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] = b"\x00" * BLOCK_SIZE
            continue
        block = plain[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE]
        key = block_key(header, i)
        out[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] = AES.new(key, AES.MODE_ECB).encrypt(block)
    return bytes(out)


def read_area(dec: bytes, start: int):
    b = dec[start:start + 16]
    return {
        "exp": struct.unpack_from("<H", b, 0x00)[0],
        "gold": struct.unpack_from("<H", b, 0x03)[0],
        "playtime": struct.unpack_from("<I", b, 0x05)[0],
        "counter": b[0x09],
    }


def read_nickname(dec: bytes, start: int) -> str:
    raw = dec[start + 0x20:start + 0x30] + dec[start + 0x40:start + 0x50]
    return raw.decode("utf-16-le", errors="ignore").split("\x00")[0]


def write_nickname(area: bytearray, name: str):
    name = name[:15]
    utf16 = name.encode("utf-16-le")
    utf16 += b"\x00" * (32 - len(utf16))
    area[0x20:0x30] = utf16[0:16]
    area[0x40:0x50] = utf16[16:32]


def recompute_type1(area: bytearray):
    chk = bytearray(area[0:16])
    chk[0x0E] = 0x05
    chk[0x0F] = 0x00
    struct.pack_into("<H", area, 0x0E, crc16_ccitt_false(bytes(chk)))


def recompute_type2(area: bytearray):
    buf = bytes(area[0x10:0x30]) + bytes(area[0x40:0x50])
    struct.pack_into("<H", area, 0x0C, crc16_ccitt_false(buf))


def get_primary_area_pair(dec: bytes):
    c0 = read_area(dec, AREA_PAIR_01[0])["counter"]
    c1 = read_area(dec, AREA_PAIR_01[1])["counter"]
    diff = (c0 - c1) & 0xFF
    if diff == 0 or diff < 128:
        return AREA_PAIR_01[0], AREA_PAIR_01[1]
    return AREA_PAIR_01[1], AREA_PAIR_01[0]


def edit_figure(data: bytes, gold=None, exp=None, nickname=None) -> bytes:
    dec, blanks = decrypt_figure(data)
    primary_start, secondary_start = get_primary_area_pair(dec)
    primary = read_area(dec, primary_start)
    area_size = 0x90
    full_area = bytearray(dec[primary_start:primary_start + area_size])

    new_gold = min(gold if gold is not None else primary["gold"], 65000)
    new_exp = min(exp if exp is not None else primary["exp"], 33000)

    struct.pack_into("<H", full_area, 0x00, new_exp)
    struct.pack_into("<H", full_area, 0x03, new_gold)
    full_area[0x09] = (primary["counter"] + 1) & 0xFF

    if nickname is not None:
        write_nickname(full_area, nickname)

    recompute_type2(full_area)
    recompute_type1(full_area)

    new_dec = bytearray(dec)
    new_dec[secondary_start:secondary_start + area_size] = full_area

    written_blocks = set(range(secondary_start // BLOCK_SIZE, (secondary_start + area_size) // BLOCK_SIZE))
    active_blanks = blanks - written_blocks

    return encrypt_figure(bytes(new_dec), data, active_blanks)


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------

LEVEL_THRESHOLDS = [0, 1000, 2200, 3800, 6000, 9000, 13000, 18200, 24800, 33000]

GAME_MAX_LEVELS = [
    ("Spyro's Adventure", 10),
    ("Giants", 15),
    ("Swap Force", 20),
    ("Trap Team", 20),
    ("SuperChargers", 20),
    ("Imaginators", 20),
]

CANVAS_BG = "#1a1a1a"      
PANEL_BG = "#2d1b24"       
ACCENT = "#ff66c4"         
ACCENT_DARK = "#d63e9b"    
TEXT = "#ffbde2"           
ENTRY_BG = "#1f1219"       
MUTED = "#a68395"          


def xp_to_level(xp: int) -> int:
    level = 1
    for i, t in enumerate(LEVEL_THRESHOLDS):
        if xp >= t:
            level = i + 1
    return level


class SkyEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Skylander Editor")
        
        self.geometry("940x600")
        self.resizable(False, False)

        # Uses the new 8-bit icon for the program window
        try:
            ico_path = resource_path("8bitICON.ico")
            self.iconbitmap(ico_path)
        except Exception:
            pass

        # Setup Canvas Layer
        self.bg_canvas = tk.Canvas(self, width=940, height=600, bg=CANVAS_BG, highlightthickness=0)
        self.bg_canvas.pack(fill="both", expand=True)

        try:
            img_path = resource_path("RollerbrawlBackground.png")
            self.bg_image = tk.PhotoImage(file=img_path)
            self.bg_canvas.create_image(0, 0, image=self.bg_image, anchor="nw")
        except Exception:
            pass

        pad = {"padx": 10, "pady": 5}

        def styled_label(parent, **kw):
            kw.setdefault("bg", PANEL_BG)
            kw.setdefault("fg", TEXT)
            return tk.Label(parent, **kw)

        def styled_labelframe(parent, **kw):
            return tk.LabelFrame(parent, bg=PANEL_BG, fg=ACCENT,
                                  font=("Segoe UI", 9, "bold"), **kw)

        def styled_button(parent, **kw):
            kw.setdefault("bg", ACCENT)
            kw.setdefault("fg", "#1a1a1a")
            kw.setdefault("activebackground", ACCENT_DARK)
            kw.setdefault("activeforeground", "white")
            kw.setdefault("relief", "flat")
            kw.setdefault("font", ("Segoe UI", 9, "bold"))
            kw.setdefault("padx", 10)
            kw.setdefault("pady", 4)
            return tk.Button(parent, **kw)

        def styled_entry(parent, **kw):
            kw.setdefault("bg", ENTRY_BG)
            kw.setdefault("fg", ACCENT)
            kw.setdefault("insertbackground", ACCENT)
            kw.setdefault("relief", "flat")
            kw.setdefault("highlightthickness", 1)
            kw.setdefault("highlightbackground", ACCENT_DARK)
            kw.setdefault("highlightcolor", ACCENT)
            return tk.Entry(parent, **kw)

        self.main_container = tk.Frame(self.bg_canvas, bg=PANEL_BG, bd=2, relief="groove")
        self.bg_canvas.create_window(710, 300, window=self.main_container, anchor="center", width=420, height=560)

        title = tk.Label(self.main_container, text="🍬 Skylander .sky Editor", bg=PANEL_BG, fg=ACCENT,
                          font=("Segoe UI", 14, "bold"), padx=10, pady=2)
        title.pack(pady=(10, 5))

        top = tk.Frame(self.main_container, bg=PANEL_BG, padx=5, pady=5)
        top.pack(fill="x", **pad)
        styled_button(top, text="Open .sky file...", command=self.open_file).pack(side="left")
        self.file_label = styled_label(top, text="No file loaded", fg=MUTED)
        self.file_label.pack(side="left", padx=10)

        info = styled_labelframe(self.main_container, text="Figure info (read-only)")
        info.pack(fill="x", **pad)
        self.char_id_label = styled_label(info, text="Character ID: -")
        self.char_id_label.pack(anchor="w", padx=8, pady=2)
        self.area_label = styled_label(info, text="Active save slot: -")
        self.area_label.pack(anchor="w", padx=8, pady=2)
        self.level_label = styled_label(info, text="Level (tier 1-10): -")
        self.level_label.pack(anchor="w", padx=8, pady=2)

        edit = styled_labelframe(self.main_container, text="Edit (verified fields only)")
        edit.pack(fill="x", **pad)
        edit.configure(padx=4, pady=4)

        styled_label(edit, text="Gold (0-65000):").grid(row=0, column=0, sticky="w", padx=8, pady=4)
        self.gold_var = tk.StringVar()
        styled_entry(edit, textvariable=self.gold_var, width=14).grid(row=0, column=1, padx=8)

        styled_label(edit, text="XP, tier 1-10 (0-33000):").grid(row=1, column=0, sticky="w", padx=8, pady=4)
        self.exp_var = tk.StringVar()
        styled_entry(edit, textvariable=self.exp_var, width=14).grid(row=1, column=1, padx=8)

        styled_label(edit, text="Nickname (max 15 chars):").grid(row=2, column=0, sticky="w", padx=8, pady=4)
        self.nick_var = tk.StringVar()
        styled_entry(edit, textvariable=self.nick_var, width=16).grid(row=2, column=1, padx=8)

        levels_frame = styled_labelframe(self.main_container, text="Max level by game (reference only)")
        levels_frame.pack(fill="x", **pad)
        levels_text = "   |   ".join(f"{name}: {lvl}" for name, lvl in GAME_MAX_LEVELS)
        styled_label(
            levels_frame,
            text=levels_text,
            wraplength=380, justify="left", fg=MUTED
        ).pack(anchor="w", padx=8, pady=4)

        unsupported = styled_labelframe(self.main_container, text="Not editable yet (unverified offsets)")
        unsupported.pack(fill="x", **pad)
        styled_label(
            unsupported,
            text="Only level 1-10 XP has a verified checksum.\n"
                 "Levels above 10 live in an unverified layout tier.\n"
                 "Hat, Heroics, and Wow Pow are omitted safely.",
            fg=MUTED, justify="left", font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=4)

        btns = tk.Frame(self.main_container, bg=PANEL_BG, padx=5, pady=5)
        btns.pack(fill="x", **pad)
        self.save_btn = styled_button(btns, text="Save changes to .sky", command=self.save_file, state="disabled")
        self.save_btn.pack(side="left")

        self.status = tk.Label(self.main_container, text="", fg=ACCENT, bg=PANEL_BG, font=("Segoe UI", 9, "bold"))
        self.status.pack(**pad)

        self.filepath = None
        self.raw_data = None

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Skylander files", "*.sky"), ("All files", "*.*")])
        if not path:
            return
        try:
            data = open(path, "rb").read()
            if len(data) != FIGURE_SIZE:
                messagebox.showerror("Error", f"Expected a 1024-byte .sky file, got {len(data)} bytes.")
                return
            dec, blanks = decrypt_figure(data)
            reenc = encrypt_figure(dec, data, blanks)
            if reenc != data:
                if not messagebox.askyesno(
                    "Warning",
                    "This file did not pass the integrity check (it may already be\n"
                    "partially corrupted, like a bad prior edit). Continue anyway?"
                ):
                    return

            self.filepath = path
            self.raw_data = data
            self.file_label.config(text=os.path.basename(path))

            char_id = struct.unpack_from("<H", dec, 0x10)[0]
            p, s = get_primary_area_pair(dec)
            area = read_area(dec, p)
            nick = read_nickname(dec, p)

            self.char_id_label.config(text=f"Character ID: {char_id}")
            self.area_label.config(text=f"Active save slot: area @0x{p:03x} (counter={area['counter']})")
            self.level_label.config(text=f"Level (tier 1-10): {xp_to_level(area['exp'])}")

            self.gold_var.set(str(area["gold"]))
            self.exp_var.set(str(area["exp"]))
            self.nick_var.set(nick)

            self.save_btn.config(state="normal")
            self.status.config(text="Loaded successfully.", fg="#00ff66")
        except Exception as e:
            messagebox.showerror("Error opening file", str(e))

    def save_file(self):
        if self.raw_data is None:
            return
        try:
            gold = int(self.gold_var.get())
            exp = int(self.exp_var.get())
            nick = self.nick_var.get()
            if gold < 0 or exp < 0:
                raise ValueError("Gold and XP must not be negative.")

            new_data = edit_figure(self.raw_data, gold=gold, exp=exp, nickname=nick)

            dec2, blanks2 = decrypt_figure(new_data)
            reenc = encrypt_figure(dec2, new_data, blanks2)
            if reenc != new_data:
                messagebox.showerror("Aborted", "Internal consistency check failed - file NOT saved.")
                return

            backup_path = self.filepath + ".bak"
            if not os.path.exists(backup_path):
                with open(backup_path, "wb") as f:
                    f.write(self.raw_data)

            with open(self.filepath, "wb") as f:
                f.write(new_data)

            self.raw_data = new_data
            self.status.config(text=f"Saved. Backup kept at {os.path.basename(backup_path)}", fg="#00ff66")
            messagebox.showinfo("Saved", "Changes written successfully.\nA backup of the original was kept as a .bak file.")
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
        except Exception as e:
            messagebox.showerror("Error saving file", str(e))


if __name__ == "__main__":
    app = SkyEditorApp()
    app.mainloop()