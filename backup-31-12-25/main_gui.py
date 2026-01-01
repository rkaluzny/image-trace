import os
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, Label, Entry, Button, Frame
import tkinter.ttk as ttk
import threading
import queue
import re
import json
import random # For sanitize improvements

# Import all core functions from the new central module
import analysis_core as core

# -----------------------------
# GUI - EXIF Editor Window
# -----------------------------

class ModifyWindow(Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Modify EXIF Data (Batch Capable)")
        self.geometry("600x600") # Increased size for new options
        self.transient(master)

        self.source_path = tk.StringVar()
        self.output_dir = tk.StringVar()
        self.tag_entries = {}
        # New:
        self.selected_action = tk.StringVar(value="none") # To manage mutual exclusivity

        self.build_ui()
        self._update_state() # Set initial state of widgets

    def build_ui(self):
        # Source and Output Frames
        top_frame = Frame(self)
        top_frame.pack(fill="x", padx=10, pady=5)

        Label(top_frame, text="Source (File/Dir):").grid(row=0, column=0, sticky="w")
        Entry(top_frame, textvariable=self.source_path, width=40).grid(row=0, column=1, sticky="we", padx=5)
        Button(top_frame, text="Browse...", command=self.browse_source).grid(row=0, column=2)

        Label(top_frame, text="Output Directory:").grid(row=1, column=0, sticky="w")
        Entry(top_frame, textvariable=self.output_dir, width=40).grid(row=1, column=1, sticky="we", padx=5)
        Button(top_frame, text="Browse...", command=self.browse_output_dir).grid(row=1, column=2)

        # Action Options (Mutually Exclusive)
        action_frame = Frame(self, bd=2, relief=tk.GROOVE)
        action_frame.pack(fill="x", padx=10, pady=5)
        Label(action_frame, text="Action:").pack(anchor="w")

        tk.Radiobutton(action_frame, text="Set Specific Tags", variable=self.selected_action, value="set", command=self._update_state).pack(anchor="w")
        tk.Radiobutton(action_frame, text="Clear All EXIF Data", variable=self.selected_action, value="clear", command=self._update_state).pack(anchor="w")
        tk.Radiobutton(action_frame, text="Sanitize EXIF Data", variable=self.selected_action, value="sanitize", command=self._update_state).pack(anchor="w")

        # Tag Entry Frame (Scrollable)
        tags_frame_container = Frame(self, relief="groove", borderwidth=2)
        tags_frame_container.pack(fill="both", expand=True, padx=10, pady=5)
        Label(tags_frame_container, text="Tags to Set:").pack(anchor="w")
        
        canvas = tk.Canvas(tags_frame_container)
        scrollbar = tk.Scrollbar(tags_frame_container, orient="vertical", command=canvas.yview)
        scrollable_frame = Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        editable_tags = list(core.TAG_MAP.keys())
        for i, tag in enumerate(editable_tags):
            Label(scrollable_frame, text=tag, width=20, anchor="w").grid(row=i, column=0, sticky="w", padx=5, pady=2)
            entry = Entry(scrollable_frame, width=40)
            entry.grid(row=i, column=1, sticky="we", padx=5)
            self.tag_entries[tag] = entry

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bottom Frame
        bottom_frame = Frame(self)
        bottom_frame.pack(fill="x", padx=10, pady=10)
        Button(bottom_frame, text="Process Images...", command=self.process_images).pack(side="left")
        Button(bottom_frame, text="Load Tags from File...", command=self.load_tags_from_file).pack(side="left", padx=5)

    def _update_state(self):
        """Manages mutual exclusivity of action options and enables/disables tag entry fields."""
        selected = self.selected_action.get()

        # Enable/disable tag entry fields
        for entry in self.tag_entries.values():
            if selected == "set":
                entry.config(state="normal")
            else:
                entry.config(state="disabled")
                entry.delete(0, "end") # Clear content when disabled

    def browse_source(self):
        # Allow selecting file or directory
        filepath = filedialog.askopenfilename(title="Select source image or directory")
        if not filepath:
            filepath = filedialog.askdirectory(title="Select source directory")

        if filepath:
            self.source_path.set(filepath)
            # If a single file is selected, try to load its tags into entry fields
            if os.path.isfile(filepath):
                self.load_tags_from_file(filepath=filepath)
        else: # If user cancelled both file and directory dialogs
            self.source_path.set("")


    def browse_output_dir(self):
        dirpath = filedialog.askdirectory(title="Select output directory")
        if dirpath:
            self.output_dir.set(dirpath)

    def load_tags_from_file(self, filepath=None):
        """Loads EXIF tags from a single selected image into the entry fields."""
        if not core.PIEXIF_AVAILABLE:
            messagebox.showerror("Error", "piexif library not found.")
            return

        if not filepath: # If called from button, filepath will be None
            filepath = filedialog.askopenfilename(title="Select an image to load tags from", filetypes=[("JPEG Images", "*.jpg *.jpeg")])
        
        if not filepath:
            return
        
        # Clear existing entries first
        for entry in self.tag_entries.values():
            entry.delete(0, "end")

        try:
            exif_dict = core.piexif.load(filepath)
            for ifd_name in ("0th", "Exif"):
                for key, value in exif_dict.get(ifd_name, {}).items():
                    for tag_name, (ifd, tag_id) in core.TAG_MAP.items():
                        if ifd == ifd_name and tag_id == key:
                            try:
                                self.tag_entries[tag_name].insert(0, value.decode().strip('\x00'))
                            except:
                                self.tag_entries[tag_name].insert(0, str(value))
            self.selected_action.set("set") # Automatically select "Set Specific Tags"
            self._update_state()
            messagebox.showinfo("Tags Loaded", f"EXIF tags from {os.path.basename(filepath)} loaded successfully.")
        except Exception as e:
            messagebox.showwarning("Error Loading Tags", f"Could not load EXIF data from {os.path.basename(filepath)}.\nError: {e}")

    def process_images(self):
        source = self.source_path.get()
        output_dir = self.output_dir.get()
        action = self.selected_action.get()

        if not source:
            messagebox.showerror("Error", "Please select a source file or directory.")
            return
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory.")
            return
        if action == "none":
            messagebox.showerror("Error", "Please select an action (Set, Clear, or Sanitize).")
            return

        if not os.path.exists(source):
            messagebox.showerror("Error", f"Source not found: {source}")
            return
        if not os.path.isdir(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                messagebox.showerror("Error", f"Could not create output directory: {e}")
                return

        files_to_process = []
        if os.path.isfile(source):
            files_to_process.append(source)
        elif os.path.isdir(source):
            files_to_process = core.collect_files([source], recursive=True)
        
        # Filter for image types that piexif supports
        image_files = [f for f in files_to_process if f.lower().endswith(('.jpg', '.jpeg', '.tif', '.tiff'))]
        if not image_files:
            messagebox.showwarning("No Images", "No supported image files (JPG, TIF) found in the source.")
            return

        if not core.PIEXIF_AVAILABLE:
            messagebox.showerror("Error", "piexif library not found. Please install it with 'pip install piexif'.")
            return

        processed_count = 0
        error_count = 0
        for input_path in image_files:
            try:
                output_path = os.path.join(output_dir, os.path.basename(input_path))
                
                if action == "clear":
                    core.piexif.remove(input_path, output_path)
                    processed_count += 1
                elif action == "sanitize":
                    # For sanitization, we need to load the image first to remove all EXIF,
                    # then insert new, generated EXIF.
                    # Temporarily save image without EXIF, then load and add new EXIF.
                    temp_output_no_exif = output_path + ".temp"
                    core.piexif.remove(input_path, temp_output_no_exif)
                    
                    exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None} # Start with empty EXIF structure
                    core.generate_trustworthy_exif(exif_dict) # Populate with generated data
                    
                    exif_bytes = core.piexif.dump(exif_dict)
                    core.piexif.insert(exif_bytes, temp_output_no_exif, output_path)
                    os.remove(temp_output_no_exif) # Clean up temp file
                    processed_count += 1

                elif action == "set":
                    # Build exif_dict from entries
                    exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
                    # Try to load existing first to preserve other tags
                    try:
                        existing_exif_dict = core.piexif.load(input_path)
                        # Merge existing with new values. New values take precedence
                        for ifd in existing_exif_dict:
                            if ifd not in exif_dict: exif_dict[ifd] = {}
                            if existing_exif_dict[ifd] and isinstance(existing_exif_dict[ifd], dict):
                                exif_dict[ifd].update(existing_exif_dict[ifd])
                    except Exception:
                        pass # No existing EXIF, start fresh

                    has_set_tags = False
                    for tag_name, entry in self.tag_entries.items():
                        value = entry.get()
                        if value:
                            has_set_tags = True
                            ifd, tag_id = core.TAG_MAP[tag_name]
                            exif_dict[ifd][tag_id] = value.encode("utf-8")
                    
                    if has_set_tags:
                        exif_bytes = core.piexif.dump(exif_dict)
                        core.piexif.insert(exif_bytes, input_path, output_path)
                        processed_count += 1
                    else:
                        messagebox.showwarning("No Tags to Set", f"No specific tags were entered to set for {os.path.basename(input_path)}. File skipped.")
            except Exception as e:
                error_count += 1
                messagebox.showerror("Processing Error", f"Error processing {os.path.basename(input_path)}: {e}")

        messagebox.showinfo("Processing Complete", f"Finished processing {processed_count} images. {error_count} errors encountered.")


# -----------------------------
# GUI - Steganography Window
# -----------------------------

class SteganoWindow(Toplevel):

    def __init__(self, master):
        super().__init__(master)
        self.title("ImageTrace - Steganography")
        self.geometry("600x400")
        self.transient(master)

        self.hide_filepath = None
        self.reveal_filepath = None

        self.build_ui()

    def build_ui(self):
        # Create a notebook (tabs) for Hide/Reveal
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Hide Message Tab ---
        hide_frame = Frame(notebook)
        hide_frame.pack(fill="both", expand=True) # Ensure it expands
        notebook.add(hide_frame, text="Hide Message")

        # Input File
        hide_file_frame = Frame(hide_frame)
        hide_file_frame.pack(fill="x", padx=5, pady=5)
        Button(hide_file_frame, text="Select Carrier Image...", command=self.load_hide_file).pack(side="left")
        self.hide_file_label = Label(hide_file_frame, text="No carrier image selected (PNG recommended)")
        self.hide_file_label.pack(side="left", padx=5)

        # Message Input
        Label(hide_frame, text="Message to hide:").pack(anchor="w", padx=5, pady=5)
        self.message_text = tk.Text(hide_frame, height=5, width=60)
        self.message_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Hide Button
        Button(hide_frame, text="Hide & Save Image...", command=self.hide_message).pack(pady=10)

        # --- Reveal Message Tab ---
        reveal_frame = Frame(notebook)
        reveal_frame.pack(fill="both", expand=True) # Ensure it expands
        notebook.add(reveal_frame, text="Reveal Message")

        # Input File
        reveal_file_frame = Frame(reveal_frame)
        reveal_file_frame.pack(fill="x", padx=5, pady=5)
        Button(reveal_file_frame, text="Select Stegano Image...", command=self.load_reveal_file).pack(side="left")
        self.reveal_file_label = Label(reveal_file_frame, text="No steganographic image selected")
        self.reveal_file_label.pack(side="left", padx=5)

        # Reveal Button
        Button(reveal_frame, text="Reveal Message", command=self.reveal_message).pack(pady=10)

        # Revealed Message Output
        Label(reveal_frame, text="Revealed Message:").pack(anchor="w", padx=5, pady=5)
        self.revealed_message_text = tk.Text(reveal_frame, height=5, width=60, state="disabled")
        self.revealed_message_text.pack(fill="both", expand=True, padx=5, pady=5)

    def load_hide_file(self):
        filepath = filedialog.askopenfilename(title="Select carrier image", filetypes=[("Lossless Images", "*.png *.bmp")])
        if not filepath:
            return
        self.hide_filepath = filepath
        self.hide_file_label.config(text=os.path.basename(filepath))

    def hide_message(self):
        if not self.hide_filepath:
            messagebox.showerror("Error", "Please select a carrier image first.")
            return
        message = self.message_text.get("1.0", "end-1c").strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message to hide.")
            return

        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")], title="Save Stegano Image As...")
        if not output_path:
            return

        success, msg = core.hide_message_in_image(self.hide_filepath, output_path, message)
        if success:
            messagebox.showinfo("Success", msg)
        else:
            messagebox.showerror("Error", msg)

    def load_reveal_file(self):
        filepath = filedialog.askopenfilename(title="Select steganographic image", filetypes=[("Image Files", "*.png *.bmp")])
        if not filepath:
            return
        self.reveal_filepath = filepath
        self.reveal_file_label.config(text=os.path.basename(filepath))
        self.revealed_message_text.config(state="normal")
        self.revealed_message_text.delete("1.0", "end")
        self.revealed_message_text.config(state="disabled")

    def reveal_message(self):
        if not self.reveal_filepath:
            messagebox.showerror("Error", "Please select an image to reveal from.")
            return
        
        message, status = core.reveal_message_from_image(self.reveal_filepath)
        self.revealed_message_text.config(state="normal")
        self.revealed_message_text.delete("1.0", "end")
        self.revealed_message_text.insert("1.0", message if message else status)
        self.revealed_message_text.config(state="disabled")
        if message:
            messagebox.showinfo("Message Revealed", "Message found and displayed.")
        else:
            messagebox.showinfo("No Message", status)

# -----------------------------
# GUI - Case Manager Window
# -----------------------------
class CaseManagerWindow(Toplevel):
    def __init__(self, master, app_instance):
        super().__init__(master)
        self.master_app = app_instance # Reference to the main App instance
        self.title("Case Manager")
        self.geometry("400x400")
        self.transient(master) # Make this window stay on top of the main window

        self.case_name_var = tk.StringVar()
        self.case_dir_var = tk.StringVar(value=core.get_cases_base_path()) # Default to current base path

        self.build_ui()
        self._load_cases()

    def build_ui(self):
        # Case Directory Selection
        dir_frame = Frame(self, bd=2, relief=tk.GROOVE)
        dir_frame.pack(fill="x", padx=5, pady=5)
        Label(dir_frame, text="Case Root Dir:").pack(side="left")
        Entry(dir_frame, textvariable=self.case_dir_var, state="readonly").pack(side="left", expand=True, fill="x", padx=5)
        Button(dir_frame, text="Change...", command=self._browse_case_dir).pack(side="left")

        # Frame for new case creation
        create_frame = Frame(self, bd=2, relief=tk.GROOVE)
        create_frame.pack(fill="x", padx=5, pady=5)
        Label(create_frame, text="New Case Name:").pack(side="left")
        Entry(create_frame, textvariable=self.case_name_var).pack(side="left", expand=True, fill="x", padx=5)
        Button(create_frame, text="Create", command=self._create_case).pack(side="left")

        # Frame for case list
        list_frame = Frame(self, bd=2, relief=tk.GROOVE)
        list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        Label(list_frame, text="Existing Cases:").pack(anchor="w")

        self.case_listbox = tk.Listbox(list_frame)
        self.case_listbox.pack(side="left", fill="both", expand=True)
        case_scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.case_listbox.yview)
        case_scrollbar.pack(side="right", fill="y")
        self.case_listbox.config(yscrollcommand=case_scrollbar.set)

        # Frame for action buttons
        button_frame = Frame(self, bd=2, relief=tk.GROOVE)
        button_frame.pack(fill="x", padx=5, pady=5)
        Button(button_frame, text="Select Case", command=self._select_case).pack(side="left", expand=True)
        Button(button_frame, text="Delete Case", command=self._delete_case).pack(side="left", expand=True)
        Button(button_frame, text="Refresh", command=self._load_cases).pack(side="left", expand=True)
        Button(button_frame, text="Close", command=self.destroy).pack(side="left", expand=True)

    def _browse_case_dir(self):
        dirpath = filedialog.askdirectory(title="Select Case Root Directory")
        if dirpath:
            # Check if directory is valid or create it
            if not os.path.exists(dirpath):
                try:
                    os.makedirs(dirpath)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not create selected directory: {e}")
                    return
            
            # Set the new base path in the core logic
            if core.set_cases_base_path(dirpath):
                self.case_dir_var.set(dirpath)
                self._load_cases() # Reload cases from new directory
            else:
                messagebox.showerror("Error", "Selected path is not a valid directory.")


    def _load_cases(self):
        self.case_listbox.delete(0, tk.END)
        cases = core.list_cases()
        if not cases:
            self.case_listbox.insert(tk.END, "No cases found.")
        else:
            for case in cases:
                self.case_listbox.insert(tk.END, case)
        self.case_name_var.set("") # Clear new case name field

    def _create_case(self):
        case_name = self.case_name_var.get().strip()
        if not case_name:
            messagebox.showerror("Error", "Case name cannot be empty.")
            return
        if not re.match(r"^[a-zA-Z0-9_-]+$", case_name):
            messagebox.showerror("Error", "Case name can only contain letters, numbers, underscores, and hyphens.")
            return

        success, msg = core.create_case(case_name)
        if success:
            messagebox.showinfo("Success", msg)
            self._load_cases()
        else:
            messagebox.showerror("Error", msg)

    def _delete_case(self):
        selected_index = self.case_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Please select a case to delete.")
            return

        case_name = self.case_listbox.get(selected_index[0])
        if case_name == "No cases found.": # Handle placeholder text
            return

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete case '{case_name}'? This action cannot be undone."):
            success, msg = core.delete_case(case_name)
            if success:
                messagebox.showinfo("Success", msg)
                self._load_cases()
                # If current case was deleted, clear context in main app
                if self.master_app.current_case_name.get() == case_name:
                    self.master_app.set_active_case(None)
            else:
                messagebox.showerror("Error", msg)

    def _select_case(self):
        selected_index = self.case_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Warning", "Please select a case to open.")
            return

        case_name = self.case_listbox.get(selected_index[0])
        if case_name == "No cases found.": # Handle placeholder text
            return

        self.master_app.set_active_case(case_name)
        messagebox.showinfo("Case Selected", f"Case '{case_name}' is now active.")
        self.destroy() # Close Case Manager Window


# -----------------------------
# GUI - Main App
# -----------------------------

class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("ImageTrace")
        self.geometry("800x700") # Increased height for case management

        # Case Management
        self.current_case_name = tk.StringVar(value="No Case Selected")
        self.current_case_path = tk.StringVar(value="")
        self.current_case_reports_dir = tk.StringVar(value="")

        # Analysis options
        self.scan_recursively = tk.BooleanVar(value=True)
        self.show_all_tags = tk.BooleanVar(value=True)
        self.enable_Ela = tk.BooleanVar(value=True)
        self.enable_strings = tk.BooleanVar(value=True)
        self.timeline_analysis = tk.BooleanVar(value=True)
        self.fingerprint_analysis = tk.BooleanVar(value=True)
        self.thumbnail_analysis = tk.BooleanVar(value=True)
        self.pattern_file_path = tk.StringVar()

        # Export options
        self.export_html = tk.BooleanVar(value=True)
        self.export_pdf = tk.BooleanVar()
        self.export_json = tk.BooleanVar()
        self.export_csv = tk.BooleanVar()

        self.sources = []
        self.analysis_queue = queue.Queue()
        self.run_button = None
        self.build_ui()

    def build_ui(self):
        # Main container frames
        top_frame = Frame(self, bd=2, relief=tk.RIDGE)
        top_frame.pack(side="top", fill="x", padx=5, pady=5)

        middle_frame = Frame(self)
        middle_frame.pack(side="top", fill="both", expand=True, padx=5)

        bottom_frame = Frame(self, bd=2, relief=tk.GROOVE)
        bottom_frame.pack(side="bottom", fill="x", padx=5, pady=5)

        # Case Management Display (now at the very top of the App window)
        case_display_frame = Frame(top_frame, bd=2, relief=tk.GROOVE)
        case_display_frame.pack(fill="x", padx=5, pady=2)
        Label(case_display_frame, text="Active Case:").pack(side="left")
        Label(case_display_frame, textvariable=self.current_case_name, font=("Helvetica", 10, "bold")).pack(side="left", expand=True, fill="x", padx=5)
        Button(case_display_frame, text="Manage Cases...", command=self.open_case_manager).pack(side="right")

        # --- Top Frame: Source Selection --- (Existing content now below case display)
        source_frame = Frame(top_frame, bd=2, relief=tk.GROOVE)
        source_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        Label(source_frame, text="Sources (Files/Directories):").pack(anchor="w")
        
        list_frame = Frame(source_frame)
        list_frame.pack(fill="both", expand=True)
        self.source_listbox = tk.Listbox(list_frame)
        self.source_listbox.pack(side="left", fill="both", expand=True)
        
        source_scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.source_listbox.yview)
        source_scrollbar.pack(side="right", fill="y")
        self.source_listbox.config(yscrollcommand=source_scrollbar.set)

        button_frame = Frame(source_frame)
        button_frame.pack(fill="x")
        Button(button_frame, text="Add File(s)...", command=self.add_source).pack(side="left", fill="x", expand=True)
        Button(button_frame, text="Add Directory...", command=self.add_directory).pack(side="left", fill="x", expand=True)
        Button(button_frame, text="Clear", command=self.clear_sources).pack(side="left", fill="x", expand=True)

        # --- Top Frame: Analysis and Export Options ---
        options_container = Frame(top_frame)
        options_container.pack(side="right", fill="y", padx=5, pady=5)

        analysis_frame = Frame(options_container, bd=2, relief=tk.GROOVE)
        analysis_frame.pack(side="left", fill="y", padx=5)
        Label(analysis_frame, text="Analysis Options:").pack(anchor="w")
        
        tk.Checkbutton(analysis_frame, text="Scan Recursively", variable=self.scan_recursively).pack(anchor="w")
        tk.Checkbutton(analysis_frame, text="Show All EXIF Tags", variable=self.show_all_tags).pack(anchor="w")
        tk.Checkbutton(analysis_frame, text="Enable ELA", variable=self.enable_Ela).pack(anchor="w")
        tk.Checkbutton(analysis_frame, text="Extract Strings", variable=self.enable_strings).pack(anchor="w")
        
        pattern_frame = Frame(analysis_frame)
        pattern_frame.pack(anchor="w", fill="x", pady=2)
        Label(pattern_frame, text="Patterns File:").pack(side="left")
        Entry(pattern_frame, textvariable=self.pattern_file_path, width=15).pack(side="left", expand=True, fill="x", padx=2)
        Button(pattern_frame, text="Browse...", command=self.browse_pattern_file).pack(side="left")

        tk.Checkbutton(analysis_frame, text="Timeline Reconstruction", variable=self.timeline_analysis).pack(anchor="w")
        tk.Checkbutton(analysis_frame, text="Software Fingerprinting", variable=self.fingerprint_analysis).pack(anchor="w")
        tk.Checkbutton(analysis_frame, text="Thumbnail Analysis", variable=self.thumbnail_analysis).pack(anchor="w")

        export_frame = Frame(options_container, bd=2, relief=tk.GROOVE)
        export_frame.pack(side="right", fill="y", padx=5)
        Label(export_frame, text="Export Options:").pack(anchor="w")
        tk.Checkbutton(export_frame, text="HTML Report", variable=self.export_html).pack(anchor="w")
        tk.Checkbutton(export_frame, text="PDF Report", variable=self.export_pdf).pack(anchor="w")
        tk.Checkbutton(export_frame, text="JSON Output", variable=self.export_json).pack(anchor="w")
        tk.Checkbutton(export_frame, text="CSV Output", variable=self.export_csv).pack(anchor="w")
        
        # --- Middle Frame: Output ---
        output_frame = Frame(middle_frame, bd=2, relief=tk.SUNKEN)
        output_frame.pack(fill="both", expand=True)
        Label(output_frame, text="Analysis Results:").pack(anchor="w")
        
        self.output_text = tk.Text(output_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.output_text.pack(fill="both", expand=True)
        
        output_scrollbar = tk.Scrollbar(self.output_text, orient="vertical", command=self.output_text.yview)
        output_scrollbar.pack(side="right", fill="y")
        self.output_text.config(yscrollcommand=output_scrollbar.set)

        # --- Bottom Frame: Actions ---
        bottom_buttons_frame = Frame(bottom_frame)
        bottom_buttons_frame.pack(fill="x", padx=10, pady=5)

        self.run_button = Button(bottom_buttons_frame, text="Run Analysis", command=self.run_analysis, font=("Helvetica", 10, "bold"))
        self.run_button.pack(side="left", padx=5)
        Button(bottom_buttons_frame, text="Compare Files", command=self.compare_files).pack(side="left", padx=5)
        Button(bottom_buttons_frame, text="Steganography Tools...", command=self.open_stegano_window).pack(side="right", padx=5)
        Button(bottom_buttons_frame, text="Modify EXIF...", command=self.open_modify_window).pack(side="right", padx=5)
        
    def browse_pattern_file(self):
        filepath = filedialog.askopenfilename(title="Select a pattern file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            self.pattern_file_path.set(filepath)

    def add_source(self):
        filepaths = filedialog.askopenfilenames(title="Select image files")
        for f in filepaths:
            if f not in self.sources:
                self.sources.append(f)
                self.source_listbox.insert(tk.END, os.path.basename(f))

    def add_directory(self):
        dir_path = filedialog.askdirectory(title="Select a directory")
        if dir_path and dir_path not in self.sources:
            self.sources.append(dir_path)
            self.source_listbox.insert(tk.END, f"DIR: {dir_path}")

    def clear_sources(self):
        self.sources.clear()
        self.source_listbox.delete(0, tk.END)

    def open_case_manager(self):
        CaseManagerWindow(self, self)

    def set_active_case(self, case_name):
        if case_name:
            self.current_case_name.set(case_name)
            case_path = core.get_case_path(case_name)
            self.current_case_path.set(case_path)
            
            # Load case metadata to get reports_dir
            case_info_path = os.path.join(case_path, "case.json")
            if os.path.exists(case_info_path):
                with open(case_info_path, "r") as f:
                    case_info = json.load(f)
                    self.current_case_reports_dir.set(os.path.join(case_path, case_info.get("reports_dir", "reports")))
            else: # Fallback if case.json is missing
                 self.current_case_reports_dir.set(os.path.join(case_path, "reports"))
        else: # No case selected (e.g., if active case was deleted)
            self.current_case_name.set("No Case Selected")
            self.current_case_path.set("")
            self.current_case_reports_dir.set("")
        
        self.title(f"ImageTrace - Case: {self.current_case_name.get()}")


    def open_stegano_window(self):
        SteganoWindow(self)

    def open_modify_window(self):
        ModifyWindow(self)

    def compare_files(self):
        if len(self.sources) != 2:
            messagebox.showwarning("Selection Error", "Please select exactly two files to compare.")
            return

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)

        try:
            data1, name1 = core.get_data_from_source(self.sources[0])
            data2, name2 = core.get_data_from_source(self.sources[1])
            meta1 = core.read_metadata(data1)
            meta2 = core.read_metadata(data2)

            diff = core.exif_diff(meta1, meta2)

            self.output_text.insert(tk.END, f"--- Comparing {name1} and {name2} ---")

            if not diff:
                self.output_text.insert(tk.END, "✔ No differences found in metadata.")
            else:
                header = f"{'{Tag':<30} | {'Image 1':<40} | {'Image 2':<40}\n"
                self.output_text.insert(tk.END, header)
                self.output_text.insert(tk.END, "-" * len(header) + "\n")
                for k, v1, v2 in diff:
                    self.output_text.insert(tk.END, f"{k:<30} | {v1:<40} | {v2:<40}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"❌ An error occurred during comparison: {e}")
        finally:
            self.output_text.config(state=tk.DISABLED)

    def run_analysis(self):
        if not self.sources:
            messagebox.showwarning("No Sources", "Please add at least one source file or directory.")
            return

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.run_button.config(state=tk.DISABLED, text="Analyzing...")

        # Run analysis in a separate thread
        thread = threading.Thread(target=self._analysis_thread)
        thread.daemon = True  # Allows main window to exit even if thread is running
        thread.start()

        # Start processing the queue for UI updates
        self.process_queue()

    def _analysis_thread(self):
        """
        This function runs in a separate thread to perform the analysis
        without blocking the GUI. It communicates with the main thread
        via a queue.
        """
        try:
            # Load string patterns if provided
            string_patterns = []
            pattern_file = self.pattern_file_path.get()
            if pattern_file:
                if not os.path.exists(pattern_file):
                    self.analysis_queue.put(("error", f"Pattern file not found: {pattern_file}"))
                    return
                try:
                    with open(pattern_file, 'r', encoding='utf-8') as f:
                        string_patterns = [line.strip() for line in f if line.strip()]
                    self.analysis_queue.put(("progress", f"Loaded {len(string_patterns)} patterns from {os.path.basename(pattern_file)}\n"))
                except Exception as e:
                    self.analysis_queue.put(("error", f"Could not load patterns from {pattern_file}: {e}"))
                    return

            all_files = core.collect_files(self.sources, self.scan_recursively.get())
            results = []
            
            for filepath in all_files:
                try:
                    self.analysis_queue.put(("progress", f"--- Analyzing: {os.path.basename(filepath)} ---"))

                    data, name = core.get_data_from_source(filepath)
                    meta = core.read_metadata(data)
                    
                    result = {
                        "name": name, "hash": core.sha256(data),
                        "meta": meta, "analysis": core.basic_forensic_analysis(meta)
                    }
                    
                    gps_coords, gps_link = core.format_gps_coordinates(meta)
                    if gps_coords:
                        result["gps_coords"] = gps_coords
                        result["gps_link"] = gps_link

                    if self.enable_strings.get():
                        result["strings"] = core.extract_strings(data, patterns=string_patterns)
                    if self.thumbnail_analysis.get():
                        result["thumbnail_analysis"] = core.analyze_thumbnail(data)
                    if self.enable_Ela.get():
                        ela_img, ela_msg = core.perform_ela(data)
                        if ela_img:
                            ela_filename = f"ELA_{os.path.basename(name)}.png"
                            ela_img.save(ela_filename)
                            result["analysis"].append(f"✔ ELA image saved: {ela_filename}")
                        else:
                            result["analysis"].append(f"❌ ELA Error: {ela_msg}")
                    if self.timeline_analysis.get():
                        result["timeline_reconstruction"] = core.reconstruct_timeline(meta, filepath)
                    if self.fingerprint_analysis.get():
                        result["software_fingerprint"] = core.fingerprint_software(meta)

                    results.append(result)
                    self.analysis_queue.put(("progress", f"✔ Analysis complete for {name}\n\n"))

                except Exception as e:
                    self.analysis_queue.put(("progress", f"❌ An error occurred during analysis for {filepath}: {e}\n\n"))

            self.analysis_queue.put(("display", results))
        except Exception as e:
            self.analysis_queue.put(("error", e))
        finally:
            self.analysis_queue.put(("finished", None))

    def process_queue(self):
        """
        Process messages from the analysis thread's queue to update the GUI.
        """
        try:
            msg_type, data = self.analysis_queue.get_nowait()

            if msg_type == "progress":
                self.output_text.insert(tk.END, data)
                self.output_text.see(tk.END)  # Scroll to the end
            elif msg_type == "display":
                self.display_results(data)
                self.export_results(data)
            elif msg_type == "error":
                messagebox.showerror("Analysis Error", f"An unexpected error occurred: {data}")
            elif msg_type == "finished":
                self.run_button.config(state=tk.NORMAL, text="Run Analysis")
                # Only show success message if no errors were logged in the text widget
                if "❌" not in self.output_text.get("1.0", tk.END):
                    messagebox.showinfo("Completed", "Analysis finished.")
                return  # Stop the polling loop

        except queue.Empty:
            pass  # Continue polling
        
        self.after(100, self.process_queue)  # Poll again after 100ms

    def display_results(self, results):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        for r in results:
            self.output_text.insert(tk.END, f"--- Analysis for: {r['name']} ---")
            self.output_text.insert(tk.END, f"SHA256: {r['hash']}\n\n")
            
            self.output_text.insert(tk.END, "--- Metadata ---")
            all_meta = r.get("meta") # This now contains EXIF and XMP
            
            if not all_meta:
                self.output_text.insert(tk.END, "No metadata found.\n\n")
            else:
                # Process EXIF data
                output_exif = []
                exif_meta = {k: v for k, v in all_meta.items() if not k.startswith("XMP")}
                
                tags_to_iterate_exif = sorted(exif_meta.keys()) if self.show_all_tags.get() else core.FORENSIC_TAGS
                for k in tags_to_iterate_exif:
                    if k in exif_meta and "JPEGThumbnail" not in k:
                        output_exif.append(f"{k}: {exif_meta[k]}")
                
                if not self.show_all_tags.get():
                    # GPS data is already formatted and stored in the result dict
                    if r.get("gps_coords"):
                        output_exif.append(f"GPS Coordinates: {r['gps_coords']}")
                        output_exif.append(f"Map Link: {r['gps_link']}")
                
                self.output_text.insert(tk.END, "\n".join(output_exif) if output_exif else "No EXIF metadata found.")
                self.output_text.insert(tk.END, "\n\n")

                # Process XMP data if available
                if 'XMP' in all_meta:
                    self.output_text.insert(tk.END, "--- XMP Metadata ---")
                    xmp_data = all_meta['XMP']
                    if isinstance(xmp_data, dict):
                        output_xmp = []
                        for k, v in sorted(xmp_data.items()):
                            output_xmp.append(f"{k}: {v}")
                        self.output_text.insert(tk.END, "\n".join(output_xmp) + "\n\n")
                    else: # Raw XMP string
                        self.output_text.insert(tk.END, f"Raw XMP: {xmp_data[:200]}...\n\n")
                self.output_text.insert(tk.END, "\n") # Add a separator (optional, depending on desired spacing)

            for item in r.get("analysis", []):
                self.output_text.insert(tk.END, item + "\n")
            self.output_text.insert(tk.END, "\n")
            
            if "strings" in r and isinstance(r["strings"], dict):
                strings_data = r["strings"]
                if strings_data.get("all_strings"):
                    self.output_text.insert(tk.END, "--- All Printable Strings (Preview) ---")
                    preview_strings = strings_data["all_strings"][:5] # Show first 5
                    for s in preview_strings:
                        self.output_text.insert(tk.END, f"  - {s[:100]}{'...' if len(s)>100 else ''}\n")
                    if len(strings_data["all_strings"]) > 5:
                        self.output_text.insert(tk.END, f"  ... ({len(strings_data['all_strings']) - 5} more)\n")
                    self.output_text.insert(tk.END, "\n")
                
                if strings_data.get("matched_patterns"):
                    self.output_text.insert(tk.END, "--- Matched Patterns ---")
                    for pattern_desc, matches in strings_data["matched_patterns"].items():
                        self.output_text.insert(tk.END, f"Pattern: {pattern_desc}\n")
                        for match in matches:
                            self.output_text.insert(tk.END, f"  - {match}\n")
                    self.output_text.insert(tk.END, "\n")
            elif "strings" in r and isinstance(r["strings"], str): # Fallback for old string format or error message
                self.output_text.insert(tk.END, "--- Strings ---" + r["strings"] + "\n\n")
            if "thumbnail_analysis" in r:
                self.output_text.insert(tk.END, "--- Thumbnail Analysis ---" + r["thumbnail_analysis"] + "\n\n")
            if "timeline_reconstruction" in r:
                self.output_text.insert(tk.END, "--- Timeline Reconstruction ---" + r["timeline_reconstruction"] + "\n\n")
            if "software_fingerprint" in r:
                self.output_text.insert(tk.END, "--- Software Fingerprinting ---" + r["software_fingerprint"] + "\n\n")
        self.output_text.config(state=tk.DISABLED)

    def export_results(self, results):
        if not any([self.export_html.get(), self.export_pdf.get(), self.export_json.get(), self.export_csv.get()]):
            return

        # Do not ask user for path if no results are generated
        if not results:
            return

        # If a case is active, use its reports directory as default
        initial_dir = self.current_case_reports_dir.get() if self.current_case_path.get() else ""
        if initial_dir and not os.path.exists(initial_dir):
            os.makedirs(initial_dir)
        
        output_path = filedialog.asksaveasfilename(
            title="Save Report As...",
            initialdir=initial_dir,
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html"), ("All Files", "*.*")]
        )

        if not output_path:
            messagebox.showwarning("Export Cancelled", "Report export was cancelled.")
            return
        
        base_path, _ = os.path.splitext(output_path)
        
        try:
            if self.export_html.get():
                html_path = base_path + ".html"
                core.export_html(results, html_path, all_tags=self.show_all_tags.get())
            if self.export_pdf.get():
                pdf_path = base_path + ".pdf"
                core.export_pdf(results, pdf_path, all_tags=self.show_all_tags.get())
            if self.export_json.get():
                json_path = base_path + ".json"
                core.export_json(results, json_path)
            if self.export_csv.get():
                csv_path = base_path + ".csv"
                core.export_csv(results, csv_path)

            messagebox.showinfo("Export Success", f"Reports saved successfully near '{base_path}'")

        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred during export:\n{e}")



if __name__ == "__main__":
    app = App()
    app.mainloop()