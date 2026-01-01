# ImageTrace - Digital Image Forensics Tool

![App Icon](icon.png)

## About

ImageTrace is a powerful and easy-to-use tool for digital image forensics. It allows investigators, researchers, and hobbyists to perform detailed analysis on image files to uncover metadata, detect manipulations, and trace an image's history.

The tool is available in two versions:
- **A user-friendly graphical interface (GUI)** for interactive analysis with integrated case management.
- **A powerful command-line interface (CLI)** for batch processing and scripting.

## Features

ImageTrace offers a wide range of forensic analysis modules:

### Case Management (GUI)
- **Organize Your Work:** Create, select, and delete forensic cases. All reports are saved in a structured folder for the active case.
- **Flexible Storage:** Set a custom root directory for all your cases, allowing for storage on network drives or external media.

### Core Analysis
- **Comprehensive Metadata Support (EXIF, XMP, IPTC):** View all available EXIF tags, structured XMP data, and raw IPTC blocks. Includes specific parsing for GPS coordinates with a direct link to a map.
- **Hash Calculation:** Computes the SHA-256 hash of the image file for integrity verification.
- **File System Metadata:** Extracts file creation, modification, and access times.

### Manipulation Detection
- **Error Level Analysis (ELA):** A sophisticated technique to detect altered or composited parts of an image by analyzing JPEG compression levels.
- **Thumbnail Analysis:** Compares the embedded thumbnail with the main image. A mismatch is a strong indicator of manipulation.

### Data & Event Analysis
- **Intelligent String Analysis:** Extracts all printable strings from the image's binary data to find hidden text or software signatures. It can also match strings against a user-provided file of custom regex patterns.
- **Timeline Reconstruction:** Creates a chronological timeline of events based on EXIF timestamps and file system metadata.
- **Software Fingerprinting (DQT & Metadata):** Attempts to identify the software used to create or edit an image by first checking for known JPEG DQT hashes and then falling back to analyzing metadata tags.

### Steganography
- **Hide Message:** Hides a secret text message within a PNG or BMP image.
- **Reveal Message:** Extracts a secret text message from a steganographic image.

### EXIF Data Modification (Batch Capable)
- **Batch Processing:** Modify or strip EXIF data from entire directories of images, as well as single files.
- **Set Specific Tags:** Add or change individual EXIF tags.
- **Clear All Tags:** Remove all EXIF metadata from a file.
- **Sanitize with Plausible Data:** A powerful feature that clears all existing metadata and replaces it with plausible, randomized data from a built-in table of common cameras (e.g., "Canon", "iPhone 15") and software (e.g., "Adobe Photoshop", "GIMP").

### Flexible Reporting & Export
- Export analysis results into multiple formats, saved directly to the active case folder:
    - **HTML:** For a detailed, human-readable report.
    - **PDF:** For a portable and printable version of the report.
    - **JSON:** For easy integration with other tools and scripts.
    - **CSV:** For batch analysis and spreadsheet processing.

## Usage

### GUI Version (`main_gui.py`)

The GUI provides an intuitive way to access the core analysis features.

1.  Launch `main_gui.py`.
2.  Use the **"Manage Cases"** button to create a new case or select an existing one. You can also change the root directory where cases are stored from this window. All reports will be saved to the active case.
3.  Use **"Add File(s)"** or **"Add Directory"** to add sources to the list.
4.  Select the desired **Analysis Options**:
    - `Scan Recursively`: Scan through subdirectories of any added directories.
    - `Show All EXIF Tags`: Display every single metadata tag found.
    - `Enable ELA`: Perform Error Level Analysis.
    - `Extract Strings`: Perform a binary string extraction.
    - `Patterns File`: Use the "Browse..." button to select a `.txt` file containing regular expressions (one per line) to match against extracted strings.
    - `Timeline Reconstruction`: Generate a timeline from file and EXIF dates.
    - `Software Fingerprinting`: Attempt to identify editing software.
5.  Click **"Run Analysis"**. The results will appear in the main text area and can be saved as reports.

**Additional Tools:**
- **Modify EXIF:** Open the EXIF editor to change, clear, or sanitize metadata from JPEG/TIFF files or entire directories, saving the results to a new location.
- **Steganography Tools:** Open a dedicated window to hide or reveal secret messages in PNG/BMP images.

### CLI Version (`main_cli.py`)

Open a terminal (`cmd` or PowerShell) and use the `main_cli.py` script.

**Syntax:**
```
python main_cli.py [command] [options]
```

**Commands:**
- `analyze`: Perform forensic analysis.
- `modify`: Modify EXIF data.
- `stegano`: Hide or reveal messages in images.

**`analyze` Examples:**

- **Full analysis of an image with intelligent string matching and multiple reports:**
  ```bash
  python main_cli.py analyze "path/to/image.jpg" --pattern-file patterns.txt -o report.html --json report.json --ela --string-analysis --timeline --fingerprint
  ```

- **Compare the metadata of two images:**
  ```bash
  python main_cli.py analyze "image1.jpg" "image2.jpg" --compare
  ```

**`modify` Examples:**

- **Set a specific EXIF tag for all images in a folder:**
  ```bash
  python main_cli.py modify --source "./input_folder/" --output-dir "./modified_folder/" --set "Image Software=My Custom Software"
  ```

- **Sanitize all images in a folder with plausible, randomized data:**
  ```bash
  python main_cli.py modify --source "./sensitive_images/" --output-dir "./sanitized_images/" --sanitize
  ```

- **Clear all EXIF data from a single file:**
  ```bash
  python main_cli.py modify --source "image.jpg" --output-dir "./cleared_images/" --clear
  ```

**`stegano` Examples:**

- **Hide a message:**
  ```bash
  python main_cli.py stegano hide --input carrier.png --output stegano_img.png --message "secret"
  ```

- **Reveal a message:**
  ```bash
  python main_cli.py stegano reveal --input stegano_img.png
  ```

Use `python main_cli.py [command] --help` for a full list of options.

## Building from Source

To build the project from the Python source files, you need to have Python installed.

1.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Compile the executables:**
    The project uses PyInstaller. Spec files are included for easy compilation.
    ```bash
    # To build the GUI
    pyinstaller main_gui.spec

    # To build the CLI
    pyinstaller main_cli.spec
    ```
    The executables will be located in the `dist/` directory.
