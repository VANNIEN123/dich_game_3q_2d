import sys
import os
import ctypes
import subprocess
import time
import socket
import threading
import json
import urllib.request
import urllib.parse
import tkinter as tk
from tkinter import messagebox, ttk
import unicodedata

# Process snapshot structs
TH32CS_SNAPPROCESS = 0x00000002

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_char * 260)
    ]

kernel32 = ctypes.windll.kernel32

def get_process_list():
    processes = []
    hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcessSnap == -1:
        return processes
    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if kernel32.Process32First(hProcessSnap, ctypes.byref(pe32)):
        while True:
            exe_name = pe32.szExeFile.decode('ansi', errors='ignore')
            processes.append((pe32.th32ProcessID, exe_name))
            if not kernel32.Process32Next(hProcessSnap, ctypes.byref(pe32)):
                break
    kernel32.CloseHandle(hProcessSnap)
    return processes

def inject_dll(pid, dll_path):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04
    
    process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        return False
        
    try:
        dll_path_bytes = dll_path.encode('utf-16le') + b'\x00\x00'
        dll_path_len = len(dll_path_bytes)
        alloc_address = kernel32.VirtualAllocEx(process_handle, 0, dll_path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not alloc_address:
            return False
        written = ctypes.c_size_t(0)
        wpm_result = kernel32.WriteProcessMemory(process_handle, alloc_address, dll_path_bytes, dll_path_len, ctypes.byref(written))
        if not wpm_result:
            return False
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")
        if not load_library_addr:
            return False
        thread_id = ctypes.c_ulong(0)
        h_thread = kernel32.CreateRemoteThread(process_handle, None, 0, load_library_addr, alloc_address, 0, ctypes.byref(thread_id))
        if not h_thread:
            return False
        kernel32.CloseHandle(h_thread)
        return True
    finally:
        kernel32.CloseHandle(process_handle)

def normalize_vietnamese_font(text):
    # Map characters in U+1E00-U+1EFF (Latin Extended Additional)
    # and other problematic characters to their closest standard counterparts.
    # This avoids U+1E00 block which the game font lacks glyphs for.
    mapping = {
        # Lowercase
        'ạ': 'a', 'ả': 'a', 'ã': 'a',
        'ấ': 'â', 'ầ': 'â', 'ẩ': 'â', 'ẫ': 'â', 'ậ': 'â',
        'ắ': 'ă', 'ằ': 'ă', 'ẳ': 'ă', 'ẵ': 'ă', 'ặ': 'ă',
        'ẹ': 'e', 'ẻ': 'e', 'ẽ': 'e',
        'ế': 'ê', 'ệ': 'ê', 'ề': 'ê', 'ể': 'ê', 'ễ': 'ê',
        'ỉ': 'i', 'ị': 'i',
        'ọ': 'o', 'ỏ': 'o',
        'ố': 'ô', 'ồ': 'ô', 'ổ': 'ô', 'ỗ': 'ô', 'ộ': 'ô',
        'ớ': 'ơ', 'ờ': 'ơ', 'ở': 'ơ', 'ỡ': 'ơ', 'ợ': 'ơ',
        'ụ': 'u', 'ủ': 'u', 'ũ': 'u',
        'ứ': 'ư', 'ừ': 'ư', 'ử': 'ư', 'ữ': 'ư', 'ự': 'ư',
        'ỳ': 'y', 'ỵ': 'y', 'ỷ': 'y', 'ỹ': 'y',
        # Uppercase
        'Ạ': 'A', 'Ả': 'A', 'Ã': 'A',
        'Ấ': 'Â', 'Ầ': 'Â', 'Ẩ': 'Â', 'Ẫ': 'Â', 'Ậ': 'Â',
        'Ắ': 'Ă', 'Ằ': 'Ă', 'Ẳ': 'Ă', 'Ẵ': 'Ă', 'Ặ': 'Ă',
        'Ẹ': 'E', 'Ẻ': 'E', 'Ẽ': 'E',
        'Ế': 'Ê', 'Ệ': 'Ê', 'Ề': 'Ê', 'Ể': 'Ê', 'Ễ': 'Ê',
        'Ỉ': 'I', 'Ị': 'I',
        'Ọ': 'O', 'Ỏ': 'O',
        'Ố': 'Ô', 'Ồ': 'Ô', 'Ổ': 'Ô', 'Ỗ': 'Ô', 'Ộ': 'Ô',
        'Ớ': 'Ơ', 'Ờ': 'Ơ', 'Ở': 'Ơ', 'Ợ': 'Ơ', 'Ợ': 'Ơ',
        'Ụ': 'U', 'Ủ': 'U', 'Ũ': 'U',
        'Ứ': 'Ư', 'Ừ': 'Ư', 'Ử': 'Ư', 'Ữ': 'Ư', 'Ự': 'Ư',
        'Ỳ': 'Y', 'Ỵ': 'Y', 'Ỷ': 'Y', 'Ỹ': 'Y',
        # Extra characters that might show as boxes
        'đ': 'd', 'Đ': 'D'
    }
    if not text:
        return ""
    text = unicodedata.normalize('NFC', text)
    return "".join(mapping.get(c, c) for c in text)

class RealtimeTranslatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("3Q Củ Hành - Realtime Translator")
        self.root.geometry("620x460")
        self.root.configure(bg="#1e222b")
        self.root.resizable(False, False)
        
        # Styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TProgressbar", thickness=8, troughcolor="#282c34", background="#4a90e2")
        
        # State variables
        self.is_connected = False
        self.injected_pids = set()
        self.translation_cache = {}
        self.vietphrase_dict = {}
        self.lock = threading.Lock()
        
        # Setup GUI Components
        self.create_widgets()
        
        # Load dictionary
        self.load_vietphrase()
        
        # Start UDP translation server
        self.udp_running = True
        self.udp_thread = threading.Thread(target=self.run_udp_server, daemon=True)
        self.udp_thread.start()
        
        # Start Polling Injector thread
        self.poll_running = True
        self.poll_thread = threading.Thread(target=self.poll_and_inject_loop, daemon=True)
        self.poll_thread.start()
        
        # Add a test log
        self.add_log("Hệ thống", "Ứng dụng khởi động thành công. Đang chạy UDP Server trên cổng 9999.")

    def load_vietphrase(self):
        # Resolve path relative to the script directory for portability
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dict_path = os.path.join(script_dir, "vietphrase.txt")
        if os.path.exists(dict_path):
            try:
                with open(dict_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        if '=' in line:
                            parts = line.strip().split('=', 1)
                            if len(parts) == 2:
                                self.vietphrase_dict[parts[0].strip()] = parts[1].strip()
                self.add_log("Từ điển", f"Đã tải {len(self.vietphrase_dict)} từ dịch từ vietphrase.txt")
            except Exception as e:
                self.add_log("Từ điển", f"Lỗi tải vietphrase.txt: {e}")
        else:
            # Create a blank file for convenience
            try:
                with open(dict_path, 'w', encoding='utf-8') as f:
                    f.write("# Từ điển tùy chỉnh. Định dạng: Tiếng Trung=Tiếng Việt\n")
                    f.write("开始游戏=Bắt đầu game\n")
                    f.write("确定=Xác nhận\n")
                    f.write("取消=Hủy\n")
                self.vietphrase_dict["开始游戏"] = "Bắt đầu game"
                self.vietphrase_dict["确定"] = "Xác nhận"
                self.vietphrase_dict["取消"] = "Hủy"
            except:
                pass

    def create_widgets(self):
        # Header Frame
        header_frame = tk.Frame(self.root, bg="#282c34", height=70)
        header_frame.pack(fill="x", side="top")
        
        title_label = tk.Label(header_frame, text="3Q CỦ HÀNH / MỘNG TAM QUỐC", font=("Segoe UI", 14, "bold"), fg="#4a90e2", bg="#282c34")
        title_label.pack(anchor="w", padx=20, pady=(12, 2))
        
        subtitle_label = tk.Label(header_frame, text="Bộ dịch thuật trực tiếp thời gian thực bằng Hooking", font=("Segoe UI", 9, "italic"), fg="#abb2bf", bg="#282c34")
        subtitle_label.pack(anchor="w", padx=20, pady=(0, 10))
        
        # Main Panel
        main_frame = tk.Frame(self.root, bg="#1e222b", padx=20, pady=15)
        main_frame.pack(fill="both", expand=True)
        
        # Controls Frame
        ctrl_frame = tk.Frame(main_frame, bg="#1e222b")
        ctrl_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_connect = tk.Button(ctrl_frame, text="KẾT NỐI DỊCH THUẬT", font=("Segoe UI", 10, "bold"), fg="#ffffff", bg="#4a90e2", activebackground="#357abd", relief="flat", padx=15, pady=8, command=self.toggle_connect)
        self.btn_connect.pack(side="left")
        
        self.status_label = tk.Label(ctrl_frame, text="Trạng thái: Chưa kết nối", font=("Segoe UI", 10, "bold"), fg="#e06c75", bg="#1e222b", padx=15)
        self.status_label.pack(side="left", fill="y")
        
        # Logs Listbox
        log_frame = tk.Frame(main_frame, bg="#1e222b")
        log_frame.pack(fill="both", expand=True)
        
        log_title = tk.Label(log_frame, text="Lịch sử dịch thuật thời gian thực:", font=("Segoe UI", 9, "bold"), fg="#dcdfe4", bg="#1e222b")
        log_title.pack(anchor="w", pady=(0, 5))
        
        scrollbar = tk.Scrollbar(log_frame, orient="vertical")
        self.log_listbox = tk.Listbox(log_frame, yscrollcommand=scrollbar.set, bg="#181a1f", fg="#98c379", font=("Consolas", 9), relief="flat", selectbackground="#3e4452")
        scrollbar.config(command=self.log_listbox.yview)
        
        scrollbar.pack(side="right", fill="y")
        self.log_listbox.pack(side="left", fill="both", expand=True)
        
        # Footer
        footer_frame = tk.Frame(self.root, bg="#1e222b", height=30)
        footer_frame.pack(fill="x", side="bottom")
        
        help_label = tk.Label(footer_frame, text="Hướng dẫn: Mở App -> Bấm 'KẾT NỐI DỊCH THUẬT' -> Mở Game. Tiếng Trung sẽ tự động đổi.", font=("Segoe UI", 8), fg="#5c6370", bg="#1e222b")
        help_label.pack(pady=5)

    def toggle_connect(self):
        if not self.is_connected:
            self.is_connected = True
            self.btn_connect.config(text="NGẮT KẾT NỐI", bg="#e06c75", activebackground="#be5046")
            self.status_label.config(text="Trạng thái: Đang quét tìm game...", fg="#61afef")
            self.add_log("Hệ thống", "Đang quét tìm các tiến trình MSango.bin / MSango.exe...")
        else:
            self.is_connected = False
            self.btn_connect.config(text="KẾT NỐI DỊCH THUẬT", bg="#4a90e2", activebackground="#357abd")
            self.status_label.config(text="Trạng thái: Chưa kết nối", fg="#e06c75")
            self.add_log("Hệ thống", "Đã ngắt kết nối.")

    def add_log(self, tag, message):
        t_str = time.strftime("%H:%M:%S")
        log_line = f"[{t_str}] [{tag}] {message}"
        self.log_listbox.insert(tk.END, log_line)
        self.log_listbox.see(tk.END)

    def translate_online(self, text):
        try:
            url = "https://translate.googleapis.com/translate_a/single?client=gtx&sl=zh-CN&tl=vi&dt=t&q=" + urllib.parse.quote(text)
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as response:
                res_data = json.loads(response.read().decode('utf-8'))
                translated = "".join([part[0] for part in res_data[0] if part[0]])
                return translated
        except Exception as e:
            return None

    def run_udp_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            server_socket.bind(('127.0.0.1', 9999))
        except Exception as e:
            self.root.after(0, self.add_log, "Lỗi mạng", f"Không thể bind port 9999: {e}")
            return
            
        while self.udp_running:
            try:
                # Receive Chinese string bytes (UTF-16 Little Endian)
                data, addr = server_socket.recvfrom(65536)
                if not data:
                    continue
                    
                # Decode bytes to Python unicode string
                chinese_str = data.decode('utf-16le', errors='ignore')
                
                # Check if we already have it in cache
                with self.lock:
                    if chinese_str in self.translation_cache:
                        viet_str = self.translation_cache[chinese_str]
                        # Send back the translated string
                        reply = (chinese_str + "|" + viet_str).encode('utf-16le')
                        server_socket.sendto(reply, addr)
                        continue
                
                # Resolve translation
                viet_str = None
                
                # 1. Check custom user dictionary
                if chinese_str in self.vietphrase_dict:
                    viet_str = normalize_vietnamese_font(self.vietphrase_dict[chinese_str])
                    source = "Từ điển"
                
                # 2. Check online translation
                if not viet_str:
                    # Run online translation in a separate thread so UDP server doesn't block
                    # but wait, since it's UDP, we can just spawn a quick translator task!
                    threading.Thread(target=self.async_translate_task, args=(server_socket, addr, chinese_str), daemon=True).start()
                    continue
                
                # Cache and reply if translation was found
                with self.lock:
                    self.translation_cache[chinese_str] = viet_str
                
                self.root.after(0, self.add_log, source, f"{chinese_str} -> {viet_str}")
                self.write_translation_log(chinese_str, viet_str, source)
                reply = (chinese_str + "|" + viet_str).encode('utf-16le')
                server_socket.sendto(reply, addr)
                
            except Exception as e:
                pass

    def async_translate_task(self, server_socket, addr, chinese_str):
        viet_str = self.translate_online(chinese_str)
        if viet_str:
            viet_str = normalize_vietnamese_font(viet_str)
            with self.lock:
                self.translation_cache[chinese_str] = viet_str
            self.root.after(0, self.add_log, "Google", f"{chinese_str} -> {viet_str}")
            self.write_translation_log(chinese_str, viet_str, "Google")
            reply = (chinese_str + "|" + viet_str).encode('utf-16le')
            try:
                server_socket.sendto(reply, addr)
            except:
                pass

    def write_translation_log(self, chinese, vietnamese, source):
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            log_path = os.path.join(script_dir, "translation_log.txt")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{source}] {repr(chinese)} -> {repr(vietnamese)}\n")
        except:
            pass

    def poll_and_inject_loop(self):
        target_names = ["msango.bin", "msango.exe", "dhcore.bin", "dhcore.exe"]
        # Resolve path relative to the script directory for portability
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dll_path = os.path.join(script_dir, "translator.dll")
        
        while self.poll_running:
            if self.is_connected:
                try:
                    procs = get_process_list()
                    for pid, name in procs:
                        name_lower = name.lower()
                        if name_lower in target_names and pid not in self.injected_pids:
                            self.root.after(0, self.add_log, "Hệ thống", f"Phát hiện game: {name} (PID: {pid})")
                            
                            # Perform injection using 32-bit C++ injector
                            injector_path = os.path.join(script_dir, "injector.exe")
                            try:
                                result = subprocess.run([injector_path, str(pid), dll_path], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                                success = (result.returncode == 0)
                                if not success:
                                    err_msg = result.stdout.strip() if result.stdout else result.stderr.strip()
                                    self.root.after(0, self.add_log, "Hệ thống", f"Lỗi injector: {err_msg}")
                            except Exception as e:
                                success = False
                                self.root.after(0, self.add_log, "Hệ thống", f"Không tìm thấy injector.exe: {e}")
                            
                            if success:
                                self.injected_pids.add(pid)
                                self.root.after(0, self.add_log, "Hệ thống", "Đã kết nối và kích hoạt dịch thuật thành công!")
                                self.status_label.config(text="Trạng thái: ĐÃ KẾT NỐI", fg="#98c379")
                                # Run module list debugger in a background thread
                                threading.Thread(target=self.debug_log_modules, args=(pid,), daemon=True).start()
                            else:
                                self.root.after(0, self.add_log, "Hệ thống", "Lỗi: Không thể kết nối (Injection failed).")
                except Exception as e:
                    pass
            time.sleep(1.0)

    def debug_log_modules(self, pid):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_file = os.path.join(script_dir, "modules_log.txt")
        try:
            TH32CS_SNAPMODULE = 0x00000008
            TH32CS_SNAPMODULE32 = 0x00000010
            class MODULEENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("GlblcntUsage", ctypes.c_ulong),
                    ("ProccntUsage", ctypes.c_ulong),
                    ("modBaseAddr", ctypes.c_void_p),
                    ("modBaseSize", ctypes.c_ulong),
                    ("hModule", ctypes.c_void_p),
                    ("szModule", ctypes.c_char * 256),
                    ("szExePath", ctypes.c_char * 260)
                ]
            
            hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
            if hSnapshot == -1:
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write(f"Failed to create module snapshot. Error: {kernel32.GetLastError()}\n")
                return
            
            me32 = MODULEENTRY32()
            me32.dwSize = ctypes.sizeof(MODULEENTRY32)
            
            modules = []
            if kernel32.Module32First(hSnapshot, ctypes.byref(me32)):
                while True:
                    mod_name = me32.szModule.decode('ansi', errors='ignore')
                    exe_path = me32.szExePath.decode('ansi', errors='ignore')
                    modules.append(f"{mod_name} | {hex(me32.modBaseAddr or 0)} | {exe_path}")
                    if not kernel32.Module32Next(hSnapshot, ctypes.byref(me32)):
                        break
            kernel32.CloseHandle(hSnapshot)
            
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"Loaded modules for PID {pid}:\n")
                for m in modules:
                    f.write(m + "\n")
            self.root.after(0, self.add_log, "Debug", "Đã xuất danh sách modules ra file modules_log.txt")
        except Exception as e:
            try:
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write(f"Error enumerating modules: {e}\n")
            except:
                pass

    def on_closing(self):
        self.udp_running = False
        self.poll_running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = RealtimeTranslatorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
