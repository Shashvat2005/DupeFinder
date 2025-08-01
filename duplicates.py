import os, hashlib
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from collections import defaultdict
import threading
import time

def hash_file(path):
    hasher = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading {path}: {e}")
        return None

def find_duplicates(folder_path, progress_callback=None):
    hash_groups = defaultdict(list)
    total_files = 0
    processed_files = 0
    start_time = time.time()
    
    # First pass: count total files
    for root, _, files in os.walk(folder_path):
        total_files += len(files)
    
    # Second pass: process files
    for root, _, files in os.walk(folder_path):
        for file in files:
            processed_files += 1
            full_path = os.path.join(root, file)
            
            # Calculate ETA
            current_time = time.time()
            elapsed = current_time - start_time
            if processed_files > 1:
                time_per_file = elapsed / processed_files
                remaining_files = total_files - processed_files
                eta = time_per_file * remaining_files
                eta_str = f"ETA: {eta:.0f}s" if eta > 1 else f"ETA: <1s"
            else:
                eta_str = "Calculating..."
                
            if progress_callback:
                progress_callback(processed_files, total_files, eta_str)
                
            file_hash = hash_file(full_path)
            
            if file_hash:
                hash_groups[file_hash].append(full_path)
    
    # Return only groups with duplicates
    return [group for group in hash_groups.values() if len(group) > 1], total_files, time.time() - start_time

# ---------- GUI ----------
class DuplicateFinderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate File Finder")
        self.root.state('zoomed')  # Open in full screen (maximized)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", font=("Arial", 10), padding=6)
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"), background="#f0f0f0")
        self.style.configure("TProgressbar", thickness=20)
        
        self.selected_folder = tk.StringVar()
        self.scan_thread = None
        self.scanning = False
        self.total_files = 0
        self.scan_time = 0.0
        
        self.build_ui()
        
    def build_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header_frame, text="Duplicate File Finder", style="Header.TLabel").pack(side=tk.LEFT)
        
        # Folder selection
        folder_frame = ttk.Frame(main_frame)
        folder_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(folder_frame, text="Select Folder:").pack(side=tk.LEFT, padx=(0, 10))
        
        folder_entry = ttk.Entry(folder_frame, textvariable=self.selected_folder, width=50)
        folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_btn = ttk.Button(folder_frame, text="Browse", command=self.select_folder)
        browse_btn.pack(side=tk.LEFT)
        
        # Progress area
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        # Progress bar with time estimation
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X)
        
        # Container for progress text and ETA
        progress_text_frame = ttk.Frame(progress_frame)
        progress_text_frame.pack(fill=tk.X)
        
        self.progress_label = ttk.Label(progress_text_frame, text="Ready to scan")
        self.progress_label.pack(side=tk.LEFT, padx=(0, 10))
        
        self.eta_label = ttk.Label(progress_text_frame, text="", foreground="#666666")
        self.eta_label.pack(side=tk.LEFT)
        
        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.scan_btn = ttk.Button(btn_frame, text="Scan for Duplicates", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_btn = ttk.Button(btn_frame, text="Clear Results", command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT)
        
        # Results area
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create treeview with vertical scrollbar only
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview (single column)
        self.tree = ttk.Treeview(tree_frame, columns=(), show="tree")
        self.tree.heading("#0", text="Duplicate Files")
        self.tree.column("#0", minwidth=300, width=400, stretch=True)
        
        # Add vertical scrollbar only
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
            
    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder.set(folder)
            
    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.progress_bar["value"] = 0
        self.progress_label.config(text="Ready to scan")
        self.eta_label.config(text="")
        self.total_files = 0
        self.scan_time = 0.0
    
    def update_progress(self, current, total, eta_str):
        if total > 0:
            percent = (current / total) * 100
            self.progress_bar["value"] = percent
            self.progress_label.config(text=f"Processing: {current}/{total} files ({percent:.1f}%)")
            self.eta_label.config(text=eta_str)
    
    def scan_complete(self, results):
        duplicates, total_files, scan_time = results
        self.scanning = False
        self.scan_btn.config(text="Scan for Duplicates")
        self.progress_bar["value"] = 100
        self.total_files = total_files
        self.scan_time = scan_time

        # Format time taken
        if scan_time < 1:
            time_str = f"{scan_time:.3f} seconds"
        elif scan_time < 60:
            time_str = f"{scan_time:.1f} seconds"
        else:
            minutes = int(scan_time // 60)
            seconds = scan_time % 60
            time_str = f"{minutes} minutes {seconds:.1f} seconds"
        
        self.eta_label.config(text="Scan complete!")
        self.progress_label.config(text=f"Scanned {total_files} files in {time_str}")

        if not duplicates:
            messagebox.showinfo("Scan Complete", "No duplicate files found!")
            return
            
        total_dupes = sum(len(group) for group in duplicates) - len(duplicates)
        self.progress_label.config(text=f"Scanned {total_files} files in {time_str}")
        self.eta_label.config(text=f"Found {len(duplicates)} groups with {total_dupes} duplicates")
        
        # Populate treeview
        for group_idx, group in enumerate(duplicates, 1):
            # Create parent item with first file name
            first_file = os.path.basename(group[0])
            parent = self.tree.insert("", "end", text=f"{first_file} ({len(group)} duplicates)", open=True)
            
            # Add all files in the group with full paths
            for path in group:
                self.tree.insert(parent, "end", text=path)
                
    def start_scan_thread(self):
        folder = self.selected_folder.get()
        if not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return
            
        self.clear_results()
        self.scanning = True
        self.scan_btn.config(text="Scanning...")
        self.progress_label.config(text="Preparing to scan...")
        
        def scan_task():
            try:
                results = find_duplicates(folder, self.update_progress)
                self.root.after(0, lambda: self.scan_complete(results))
            except Exception as e:
                self.root.after(0, lambda: self.scan_error(str(e)))
                
        self.scan_thread = threading.Thread(target=scan_task, daemon=True)
        self.scan_thread.start()
        
    def start_scan(self):
        if self.scanning:
            return
            
        if not self.selected_folder.get():
            messagebox.showwarning("Warning", "Please select a folder first")
            return
            
        threading.Thread(target=self.start_scan_thread, daemon=True).start()
        
    def scan_error(self, error_msg):
        self.scanning = False
        self.scan_btn.config(text="Scan for Duplicates")
        self.progress_label.config(text="Scan failed!")
        self.eta_label.config(text="")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
        
# ---------- Main ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = DuplicateFinderApp(root)
    root.mainloop()