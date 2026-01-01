import os
import hashlib
import exifread
import requests
import re
import json
import csv
from datetime import datetime
from io import BytesIO
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import xml.etree.ElementTree as ET
import base64
import random # For sanitize improvements
from datetime import datetime, timedelta # For sanitize improvements

# Attempt to import piexif and Pillow for optional features
try:
    import piexif
    PIEXIF_AVAILABLE = True
except ImportError:
    PIEXIF_AVAILABLE = False

try:
    from PIL import Image, ImageChops, ImageStat
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    from stegano import lsb
    STEGANO_AVAILABLE = True
except ImportError:
    STEGANO_AVAILABLE = False

# -----------------------------
# Constants
# -----------------------------

FORENSIC_TAGS = [
    "Image Make", "Image Model", "Image Software", "Image DateTime",
    "EXIF DateTimeOriginal", "EXIF DateTimeDigitized", "EXIF BodySerialNumber", "EXIF LensModel",
    "GPS GPSLatitude", "GPS GPSLongitude", "GPS GPSAltitude"
]

if PIEXIF_AVAILABLE:
    TAG_MAP = {
        "Image Make": ("0th", piexif.ImageIFD.Make),
        "Image Model": ("0th", piexif.ImageIFD.Model),
        "Image Software": ("0th", piexif.ImageIFD.Software),
        "Image DateTime": ("0th", piexif.ImageIFD.DateTime),
        "EXIF DateTimeOriginal": ("Exif", piexif.ExifIFD.DateTimeOriginal),
        "EXIF DateTimeDigitized": ("Exif", piexif.ExifIFD.DateTimeDigitized),
        "EXIF LensModel": ("Exif", piexif.ExifIFD.LensModel),
        "EXIF BodySerialNumber": ("Exif", piexif.ExifIFD.BodySerialNumber),
    }

# Base directory for storing cases
BASE_CASES_DIR = "cases"

# Allow user to set a custom path for the cases directory
CUSTOM_BASE_CASES_DIR = None

# -----------------------------
# Core Analysis Functions
# -----------------------------

def sha256(data):
    """Computes SHA256 hash of byte data."""
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def _extract_dqt_hash(data):
    """
    Extracts JPEG Quantization Tables (DQT) and computes their SHA256 hash.
    Returns None if not a JPEG or Pillow not available.
    """
    if not PILLOW_AVAILABLE:
        return None
    try:
        img = Image.open(BytesIO(data))
        if img.format == 'JPEG' and hasattr(img, 'quantization'):
            # img.quantization gives the quantization tables as a list of lists/tuples
            # We need to flatten and serialize this to a consistent byte string for hashing
            # The exact representation of DQT can vary, so ensure consistency
            dqt_bytes = b''
            for table in img.quantization:
                for val in table:
                    dqt_bytes += val.to_bytes(1, 'big') # Assuming values fit in a byte
            if dqt_bytes:
                return hashlib.sha256(dqt_bytes).hexdigest()
        return None
    except Exception:
        return None


def read_metadata(data):
    """Reads EXIF, XMP, IPTC, and other metadata from byte data."""
    metadata = {}
    
    # Read EXIF data
    try:
        exif_tags = exifread.process_file(BytesIO(data), details=False)
        for k, v in exif_tags.items():
            metadata[k] = str(v) # Convert exifread tags to string for consistency
    except Exception:
        pass # Error reading EXIF, proceed to other metadata

    # Read XMP, IPTC, and DQT data using Pillow (if available)
    if PILLOW_AVAILABLE:
        try:
            img_stream = BytesIO(data)
            img = Image.open(img_stream)
            img.load() # Load image data to ensure all info is available
            
            # Extract XMP data
            if 'xmp' in img.info:
                xmp_raw = img.info['xmp']
                xmp_decoded = xmp_raw.decode('utf-8', errors='ignore')
                
                try:
                    root = ET.fromstring(xmp_decoded)
                    xmp_data = {}
                    for elem in root.iter():
                        if elem.tag and elem.text and elem.text.strip():
                            tag_name = elem.tag.split('}')[-1] # Remove namespace
                            if f"XMP {tag_name}" not in xmp_data:
                                xmp_data[f"XMP {tag_name}"] = elem.text.strip()
                    if xmp_data:
                        metadata['XMP'] = xmp_data
                except ET.ParseError:
                    metadata['XMP Raw'] = xmp_decoded # Store raw if parsing fails

            # Extract raw IPTC data (often embedded in Photoshop info block APP13)
            if 'photoshop' in img.info:
                iptc_raw_bytes = img.info['photoshop']
                metadata['IPTC Raw'] = base64.b64encode(iptc_raw_bytes).decode('ascii') # Store as base64

            # Extract DQT hash for JPEG fingerprinting
            if img.format == 'JPEG': # Check format directly from img object
                dqt_hash = _extract_dqt_hash(data) # Pass original data for consistency
                if dqt_hash:
                    metadata['JPEG DQT Hash'] = dqt_hash

        except Exception:
            pass # Error reading XMP/IPTC/DQT with Pillow
            
    return metadata

def get_data_from_source(src):
    """Gets byte data from a local file path or a URL."""
    if src.startswith("http"):
        data = requests.get(src).content
        name = src
    else:
        with open(src, "rb") as f:
            data = f.read()
        name = os.path.basename(src)
    return data, name
    
def collect_files(sources, recursive):
    """Collects all image files from a list of sources (files or directories)."""
    all_files = []
    for src in sources:
        if os.path.isfile(src):
            all_files.append(src)
        elif os.path.isdir(src):
            if recursive:
                for root, _, files in os.walk(src):
                    for f in files:
                        all_files.append(os.path.join(root, f))
            else:
                for f in os.listdir(src):
                    path = os.path.join(src, f)
                    if os.path.isfile(path):
                        all_files.append(path)
    return all_files

# -----------------------------
# Forensic Analysis Modules
# -----------------------------

def basic_forensic_analysis(meta):
    """Performs a basic analysis of EXIF tags for inconsistencies and plausibility."""
    hints = []
    if not meta:
        return ["❌ No EXIF data found (likely stripped)."]

    # --- Check for software processing ---
    if "Image Software" in meta:
        hints.append("⚠ Image has been processed by software.")

    # --- Check date/time consistency and plausibility ---
    now = datetime.now()
    exif_dt_original = None
    image_dt = None

    if "EXIF DateTimeOriginal" in meta:
        try:
            exif_dt_original = datetime.strptime(str(meta["EXIF DateTimeOriginal"]), "%Y:%m:%d %H:%M:%S")
            if exif_dt_original > now:
                hints.append("❌ EXIF DateTimeOriginal is in the future (possible manipulation).")
        except ValueError:
            hints.append("⚠ EXIF DateTimeOriginal has an invalid format.")

    if "Image DateTime" in meta:
        try:
            image_dt = datetime.strptime(str(meta["Image DateTime"]), "%Y:%m:%d %H:%M:%S")
            if image_dt > now:
                hints.append("❌ Image DateTime is in the future (possible manipulation).")
        except ValueError:
            hints.append("⚠ Image DateTime has an invalid format.")

    if exif_dt_original and image_dt:
        if exif_dt_original > image_dt:
            hints.append("⚠ EXIF DateTimeOriginal is later than Image DateTime (unusual timestamp order).")
        if abs((image_dt - exif_dt_original).total_seconds()) > 3600: # More than 1 hour difference
            hints.append("⚠ Significant difference between EXIF DateTimeOriginal and Image DateTime.")

    # --- Check GPS data plausibility ---
    # format_gps_coordinates might not be called by get_metadata depending on args.all_tags
    # so we'll do a basic check here.
    if "GPS GPSLatitude" in meta and "GPS GPSLongitude" in meta:
        try:
            # Need to get actual numerical lat/lon values
            # The format_gps_coordinates function converts exifread objects to a numeric string and a link
            # We can re-use its internal logic or just check the strings from meta directly if they are parsable
            # For simplicity, we'll try to convert from the string representation as stored by read_metadata
            # The structure of EXIFREAD GPS tags is complex, so we rely on format_gps_coordinates to handle parsing from exifread objects.
            # We already have gps_coords in the result dict in main_cli/gui, but here we only have 'meta'.
            # So, re-parse via format_gps_coordinates and extract numbers.
            
            # This will return a string like "52.520000, 13.405000"
            gps_coords_str, _ = format_gps_coordinates(meta) 
            if gps_coords_str:
                lat, lon = map(float, gps_coords_str.split(','))

                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    hints.append("❌ GPS coordinates are outside valid global ranges (possible manipulation).")
                # Basic check for zero coordinates (often default/invalid)
                if abs(lat) < 0.0001 and abs(lon) < 0.0001:
                    hints.append("⚠ GPS coordinates are near (0,0) which can indicate invalid data.")
        except Exception:
            hints.append("⚠ Could not parse GPS coordinates for plausibility check.")


    return hints or ["✔ No obvious signs of manipulation found."]

def exif_diff(meta1, meta2):
    """Compares two sets of EXIF metadata and returns the differences."""
    keys1 = set(meta1.keys())
    keys2 = set(meta2.keys())
    
    diff = []
    
    all_keys = sorted(list(keys1.union(keys2)))
    
    for k in all_keys:
        if "JPEGThumbnail" in k:
            continue
        v1 = str(meta1.get(k, "N/A"))
        v2 = str(meta2.get(k, "N/A"))
        if v1 != v2:
            diff.append((k, v1, v2))
            
    return diff

def format_gps_coordinates(tags):
    """Formats GPS data and creates a map link."""
    try:
        lat_tag = tags.get("GPS GPSLatitude")
        lon_tag = tags.get("GPS GPSLongitude")
        lat_ref_tag = tags.get("GPS GPSLatitudeRef")
        lon_ref_tag = tags.get("GPS GPSLongitudeRef")

        if not all([lat_tag, lon_tag, lat_ref_tag, lon_ref_tag]):
            return None, None

        def to_deg(value):
            d = float(value.values[0].num) / float(value.values[0].den)
            m = float(value.values[1].num) / float(value.values[1].den)
            s = float(value.values[2].num) / float(value.values[2].den)
            return d + (m / 60.0) + (s / 3600.0)

        lat = to_deg(lat_tag)
        lon = to_deg(lon_tag)

        if lat_ref_tag.values[0] != "N": lat = -lat
        if lon_ref_tag.values[0] != "E": lon = -lon
        
        link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
        return f"{lat:.6f}, {lon:.6f}", link
    except Exception:
        return None, None

def reconstruct_timeline(meta, file_path):
    """Reconstructs a timeline of events for an image based on EXIF and file system timestamps."""
    timeline_events = []

    # EXIF Timestamps
    if meta:
        if "EXIF DateTimeOriginal" in meta:
            try:
                dt_str = str(meta["EXIF DateTimeOriginal"])
                timeline_events.append(("EXIF Original Capture", datetime.strptime(dt_str, "%Y:%m:%d %H:%M:%S")))
            except ValueError:
                pass # Malformed EXIF date
        if "Image DateTime" in meta:
            try:
                dt_str = str(meta["Image DateTime"])
                timeline_events.append(("EXIF Last Modified (Software)", datetime.strptime(dt_str, "%Y:%m:%d %H:%M:%S")))
            except ValueError:
                pass # Malformed EXIF date
        if "EXIF DateTimeDigitized" in meta:
            try:
                dt_str = str(meta["EXIF DateTimeDigitized"])
                timeline_events.append(("EXIF Digitized Date", datetime.strptime(dt_str, "%Y:%m:%d %H:%M:%S")))
            except ValueError:
                pass # Malformed EXIF date

    # File System Timestamps
    if file_path and os.path.exists(file_path):
        try:
            timeline_events.append(("File System Creation", datetime.fromtimestamp(os.path.getctime(file_path))))
            timeline_events.append(("File System Modification", datetime.fromtimestamp(os.path.getmtime(file_path))))
        except Exception:
            pass # Handle cases where filesystem access fails

    # Sort events chronologically
    timeline_events.sort(key=lambda x: x[1])

    # Format for display
    formatted_timeline = []
    for description, dt_obj in timeline_events:
        formatted_timeline.append(f"{description}: {dt_obj.strftime('%Y-%m-%d %H:%M:%S')}")

    return "\n".join(formatted_timeline) if formatted_timeline else "No timeline data available."

# --- Plausible EXIF Data for Sanitization ---
PLOSIBLE_MAKES = ["Canon", "Nikon", "Sony", "Fujifilm", "Olympus", "Panasonic", "Leica", "Samsung", "Google", "Apple"]
PLOSIBLE_MODELS = {
    "Canon": ["EOS Rebel T6i", "EOS 5D Mark IV", "PowerShot G7 X Mark III", "EOS R5"],
    "Nikon": ["D3500", "Z 6II", "Coolpix P1000", "Z 9"],
    "Sony": ["Alpha a7 III", "Alpha a6000", "Cyber-shot RX100 VII", "Alpha 1"],
    "Fujifilm": ["X-T4", "X100V", "GFX 100S"],
    "Olympus": ["OM-D E-M5 Mark III", "Tough TG-6", "PEN-F"],
    "Panasonic": ["Lumix GH5 II", "Lumix LX100 II", "Lumix S5"],
    "Leica": ["Q2", "M10-P", "SL2"],
    "Samsung": ["Galaxy S23 Camera", "Galaxy Note20 Camera"],
    "Google": ["Pixel 7 Camera", "Pixel 8 Camera"],
    "Apple": ["iPhone 14 Camera", "iPhone 15 Camera"]
}
PLOSIBLE_SOFTWARE = ["Adobe Photoshop 2024", "GIMP 2.10.36", "Lightroom Classic 13.0", "Capture One 23", "Affinity Photo 2", "Snapseed 2.19", "iOS Photos 16.5", "Android Gallery"]
PLOSIBLE_ARTISTS = ["John Doe", "Jane Smith", "Alex Johnson", "Maria Garcia", "David Lee", "Sarah Chen"]


# Helper to convert a datetime object to EXIF DateTime string format
def _datetime_to_exif_datetime(dt_obj):
    return dt_obj.strftime("%Y:%m:%d %H:%M:%S")

def generate_trustworthy_exif(exif_dict):
    """
    Generates plausible, generic EXIF data for an image, removing sensitive information.
    Modifies the exif_dict in place.
    """
    # Clear all existing EXIF tags in all IFDs for a clean slate
    for ifd_name in exif_dict:
        if isinstance(exif_dict[ifd_name], dict): # Ensure it's a dictionary before clearing
            exif_dict[ifd_name].clear()
    
    # Generate plausible date/time within the last ~5 years
    now = datetime.now()
    five_years_ago = now.replace(year=now.year - 5)
    
    # Random number of days between 5 years ago and now
    time_difference_days = (now - five_years_ago).days
    random_days_offset = random.randint(0, time_difference_days)
    random_datetime = five_years_ago + timedelta(days=random_days_offset,
                                                  hours=random.randint(0, 23),
                                                  minutes=random.randint(0, 59),
                                                  seconds=random.randint(0, 59))
    random_datetime_str = _datetime_to_exif_datetime(random_datetime)

    # Randomly select plausible make, model, and software
    make = random.choice(PLOSIBLE_MAKES)
    # Ensure model is compatible with selected make, or pick a generic one
    if make in PLOSIBLE_MODELS:
        model = random.choice(PLOSIBLE_MODELS[make])
    else:
        model = "Digital Camera" # Fallback
    software = random.choice(PLOSIBLE_SOFTWARE)
    artist = random.choice(PLOSIBLE_ARTISTS)
    
    # Initialize IFDs if they don't exist after clearing
    if "0th" not in exif_dict: exif_dict["0th"] = {}
    if "Exif" not in exif_dict: exif_dict["Exif"] = {}
    
    # Set plausible values for key tags
    exif_dict["0th"][piexif.ImageIFD.Make] = make.encode("utf-8")
    exif_dict["0th"][piexif.ImageIFD.Model] = model.encode("utf-8")
    exif_dict["0th"][piexif.ImageIFD.Software] = software.encode("utf-8")
    exif_dict["0th"][piexif.ImageIFD.DateTime] = random_datetime_str.encode("utf-8")
    exif_dict["0th"][piexif.ImageIFD.Artist] = artist.encode("utf-8")
    exif_dict["0th"][piexif.ImageIFD.Copyright] = f"© {random_datetime.year} {artist}".encode("utf-8")

    exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = random_datetime_str.encode("utf-8")
    exif_dict["Exif"][piexif.ExifIFD.DateTimeDigitized] = random_datetime_str.encode("utf-8")
    
    # Ensure GPS IFD is cleared or remains empty
    if "GPS" in exif_dict:
        exif_dict["GPS"].clear()
    
    return exif_dict

# -----------------------------
# Case Management Functions
# -----------------------------

# Allow user to set a custom path for the cases directory
CUSTOM_BASE_CASES_DIR = None

def get_cases_base_path():
    """Returns the base directory for all cases."""
    if CUSTOM_BASE_CASES_DIR:
        return CUSTOM_BASE_CASES_DIR
    return os.path.join(os.getcwd(), BASE_CASES_DIR)

def set_cases_base_path(path):
    """Sets a custom base directory for cases."""
    global CUSTOM_BASE_CASES_DIR
    if os.path.isdir(path):
        CUSTOM_BASE_CASES_DIR = path
        return True
    return False

def create_case(case_name):
    """Creates a new case directory."""
    case_path = os.path.join(get_cases_base_path(), case_name)
    if os.path.exists(case_path):
        return False, f"Case '{case_name}' already exists."
    try:
        os.makedirs(case_path)
        # Create a simple metadata file for the case
        case_info = {
            "name": case_name,
            "created_at": datetime.now().isoformat(),
            "description": f"Forensic case for {case_name}",
            "reports_dir": "reports" # Subdirectory for reports
        }
        with open(os.path.join(case_path, "case.json"), "w") as f:
            json.dump(case_info, f, indent=4)
        os.makedirs(os.path.join(case_path, case_info["reports_dir"]))
        return True, f"Case '{case_name}' created successfully at {case_path}"
    except Exception as e:
        return False, f"Error creating case: {e}"

def delete_case(case_name):
    """Deletes a case directory and all its contents."""
    case_path = os.path.join(get_cases_base_path(), case_name)
    if not os.path.exists(case_path):
        return False, f"Case '{case_name}' does not exist."
    try:
        import shutil
        shutil.rmtree(case_path)
        return True, f"Case '{case_name}' deleted successfully."
    except Exception as e:
        return False, f"Error deleting case: {e}"

def list_cases():
    """Lists all available cases."""
    cases_base_path = get_cases_base_path()
    if not os.path.exists(cases_base_path):
        return []
    case_dirs = [d for d in os.listdir(cases_base_path) if os.path.isdir(os.path.join(cases_base_path, d))]
    return sorted(case_dirs)

def get_case_path(case_name):
    """Returns the full path to a specific case."""
    return os.path.join(get_cases_base_path(), case_name)

# -----------------------------
# JPEG DQT Fingerprinting ---
# A very basic proof-of-concept for DQT analysis.
# In a real scenario, this would be a large database of known DQT hashes for various cameras/software.
KNOWN_DQT_HASHES = {
    # Example hashes (these are not real hashes, just illustrative)
    hashlib.sha256(b'\x00\x01\x02\x03\x04\x05').hexdigest(): "Adobe Photoshop (Example DQT)",
    hashlib.sha256(b'\x01\x01\x01\x01\x01\x01').hexdigest(): "GIMP (Example DQT)",
    hashlib.sha256(b'\x11\x11\x11\x11\x11\x11').hexdigest(): "Canon Camera (Example DQT)",
    hashlib.sha256(b'\x22\x22\x22\x22\x22\x22').hexdigest(): "iPhone Camera (Example DQT)",
}

def fingerprint_software(meta):
    """
    Attempts to identify image editing software by analyzing metadata tags and DQT hashes.
    """
    if not meta:
        return "Unknown (no metadata)"

    # First, check for DQT hash if available
    if "JPEG DQT Hash" in meta:
        dqt_hash = meta["JPEG DQT Hash"]
        if dqt_hash in KNOWN_DQT_HASHES:
            return f"Identified by DQT Hash: {KNOWN_DQT_HASHES[dqt_hash]}"
        else:
            return f"DQT Hash found: {dqt_hash} (Unknown source)"


    # Fallback to software tag analysis
    software_tag = str(meta.get("Image Software", ""))
    if "photoshop" in software_tag.lower():
        return "Adobe Photoshop (via Software Tag)"
    if "gimp" in software_tag.lower():
        return "GIMP (via Software Tag)"
    if "paint" in software_tag.lower():
        return "Microsoft Paint (via Software Tag)"
        
    return f"Unknown (Software Tag: {software_tag})" if software_tag else "Unknown (no DQT or Software Tag)"

def get_metadata(filepath, show_all_tags=False):
    """
    Reads and formats metadata from an image file into a string.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        
        all_meta = read_metadata(data) # This now contains EXIF and XMP
        
        # If all_meta is empty, it means no metadata could be extracted
        if not all_meta:
            return "No metadata found."

        output = []

        # Process EXIF data (flat keys directly in all_meta)
        exif_meta = {k: v for k, v in all_meta.items() if not k.startswith("XMP") and not k.startswith("IPTC Raw")} # Filter out XMP/IPTC Raw for EXIF display
        
        tags_to_iterate = sorted(exif_meta.keys()) if show_all_tags else FORENSIC_TAGS
        for k in tags_to_iterate:
            if k in exif_meta and "JPEGThumbnail" not in k:
                output.append(f"{k}: {exif_meta[k]}")
        
        if not show_all_tags: # GPS is an EXIF tag, so we use exif_meta
            gps_coords, gps_link = format_gps_coordinates(exif_meta)
            if gps_coords:
                output.append(f"GPS Coordinates: {gps_coords}")
                output.append(f"Map Link: {gps_link}")

        # Process XMP data if available
        if 'XMP' in all_meta:
            output.append("\n--- XMP Metadata ---")
            xmp_data = all_meta['XMP']
            if isinstance(xmp_data, dict):
                for k, v in sorted(xmp_data.items()):
                    output.append(f"{k}: {v}")
            else: # Raw XMP string
                output.append(f"Raw XMP: {xmp_data[:200]}...") # Show a preview

        # Process IPTC Raw data if available
        if 'IPTC Raw' in all_meta:
            output.append("\n--- IPTC Raw Data ---")
            iptc_raw = all_meta['IPTC Raw']
            output.append(f"Raw IPTC (base64-encoded): {iptc_raw[:200]}...") # Show a preview

        return "\n".join(output) if output else "No relevant metadata found."
    except Exception as e:
        return f"Error reading metadata: {e}"

def perform_ela(data, quality=90):
    """Performs Error Level Analysis on image data."""
    if not PILLOW_AVAILABLE:
        return None, "Pillow library not installed."
    try:
        original_image = Image.open(BytesIO(data))
        if original_image.mode not in ['RGB', 'RGBA']:
             original_image = original_image.convert('RGB')

        resave_buffer = BytesIO()
        original_image.save(resave_buffer, "JPEG", quality=quality)
        resaved_image = Image.open(resave_buffer)

        ela_image = ImageChops.difference(original_image, resaved_image)
        
        extrema = ela_image.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        if max_diff == 0: max_diff = 1
            
        scale = 255.0 / max_diff
        ela_image = Image.eval(ela_image, lambda x: x * scale)
        
        return ela_image, "ELA performed successfully."
    except Exception as e:
        return None, f"ELA failed: {e}"

def extract_strings(data, min_len=8, patterns=None):
    """
    Extracts printable strings from byte data and optionally finds strings matching specific regex patterns.
    Returns a dictionary with 'all_strings' and 'matched_patterns'.
    """
    results = {
        "all_strings": [],
        "matched_patterns": {}
    }
    try:
        decoded_data = data.decode("latin-1")
        
        # Extract all printable strings
        basic_pattern = f"([ -~]{{{min_len},}})"
        all_string_list = re.findall(basic_pattern, decoded_data)
        if all_string_list:
            results["all_strings"] = all_string_list

        # Search for specific patterns if provided
        if patterns and isinstance(patterns, list):
            for i, pattern_str in enumerate(patterns):
                try:
                    compiled_pattern = re.compile(pattern_str)
                    matches = compiled_pattern.findall(decoded_data)
                    if matches:
                        results["matched_patterns"][f"Pattern {i+1} ({pattern_str})"] = matches
                except re.error as e:
                    # Handle invalid regex pattern from user
                    results["matched_patterns"][f"Pattern {i+1} (Invalid Regex: {pattern_str})"] = [f"Error: {e}"]
        
        return results
    except Exception:
        return {"all_strings": ["Could not extract strings due to encoding error."]}

def analyze_thumbnail(data):
    """Extracts and compares the thumbnail with the main image."""
    if not PILLOW_AVAILABLE:
        return "Pillow library not installed."
    try:
        meta = read_metadata(data)
        if "JPEGThumbnail" not in meta:
            return "No thumbnail found in EXIF data."

        thumb_data = meta["JPEGThumbnail"]
        thumb_img = Image.open(BytesIO(thumb_data))
        
        main_img = Image.open(BytesIO(data))
        main_img_resized = main_img.resize(thumb_img.size)

        diff = ImageChops.difference(main_img_resized, thumb_img).getbbox()
        if diff is None:
            return "✔ Thumbnail is consistent with the main image."
        else:
            return "⚠ Thumbnail may be inconsistent with the main image."
            
    except Exception as e:
        return f"Thumbnail analysis failed: {e}"

    return exif_dict

# -----------------------------
# Case Management Functions
# -----------------------------

def get_cases_base_path():
    """Returns the base directory for all cases."""
    return os.path.join(os.getcwd(), BASE_CASES_DIR)

def create_case(case_name):
    """Creates a new case directory."""
    case_path = os.path.join(get_cases_base_path(), case_name)
    if os.path.exists(case_path):
        return False, f"Case '{case_name}' already exists."
    try:
        os.makedirs(case_path)
        # Create a simple metadata file for the case
        case_info = {
            "name": case_name,
            "created_at": datetime.now().isoformat(),
            "description": f"Forensic case for {case_name}",
            "reports_dir": "reports" # Subdirectory for reports
        }
        with open(os.path.join(case_path, "case.json"), "w") as f:
            json.dump(case_info, f, indent=4)
        os.makedirs(os.path.join(case_path, case_info["reports_dir"]))
        return True, f"Case '{case_name}' created successfully at {case_path}"
    except Exception as e:
        return False, f"Error creating case: {e}"

def delete_case(case_name):
    """Deletes a case directory and all its contents."""
    case_path = os.path.join(get_cases_base_path(), case_name)
    if not os.path.exists(case_path):
        return False, f"Case '{case_name}' does not exist."
    try:
        import shutil
        shutil.rmtree(case_path)
        return True, f"Case '{case_name}' deleted successfully."
    except Exception as e:
        return False, f"Error deleting case: {e}"

def list_cases():
    """Lists all available cases."""
    cases_base_path = get_cases_base_path()
    if not os.path.exists(cases_base_path):
        return []
    case_dirs = [d for d in os.listdir(cases_base_path) if os.path.isdir(os.path.join(cases_base_path, d))]
    return sorted(case_dirs)

def get_case_path(case_name):
    """Returns the full path to a specific case."""
    return os.path.join(get_cases_base_path(), case_name)

# -----------------------------
# Report Generation
# -----------------------------

def export_html(results, output_path, all_tags=False):
    """Generates an HTML report from the analysis results."""
    body = ""
    for r in results:
        rows = ""
        # Assuming r["meta"] now contains EXIF tags directly, and 'XMP' key for XMP data
        
        exif_meta = {k: v for k, v in r["meta"].items() if not k.startswith("XMP") and not k.startswith("IPTC Raw")} if r.get("meta") else {}

        if not exif_meta:
            rows = "<tr><td colspan='2'><b>No EXIF metadata found</b></td></tr>"
        else:
            tags_to_iterate = sorted(exif_meta.keys()) if all_tags else FORENSIC_TAGS
            for k in tags_to_iterate:
                if k in exif_meta and "JPEGThumbnail" not in k:
                    rows += f"<tr><td>{k}</td><td>{exif_meta[k]}</td></tr>"
        
        if r.get("gps_coords") and not all_tags:
            rows += f"<tr><td><b>GPS Coordinates</b></td><td><a href='{r['gps_link']}' target='_blank'>{r['gps_coords']}</a></td></tr>"

        xmp_html = ""
        if r.get("meta") and "XMP" in r["meta"]:
            xmp_html += "<h4>XMP Metadata</h4><ul>"
            xmp_data = r["meta"]["XMP"]
            if isinstance(xmp_data, dict):
                for k, v in sorted(xmp_data.items()):
                    xmp_html += f"<li><b>{k}</b>: {v}</li>"
            else: # Raw XMP string
                # Sanitize raw XMP for HTML display (basic escaping)
                safe_xmp = xmp_data.replace('<', '&lt;').replace('>', '&gt;')
                xmp_html += f"<li><b>Raw XMP</b>: <pre>{safe_xmp}</pre></li>"
            xmp_html += "</ul>"
            
        iptc_html = ""
        if r.get("meta") and "IPTC Raw" in r["meta"]:
            iptc_html += "<h4>IPTC Raw Data</h4><ul>"
            iptc_raw = r["meta"]["IPTC Raw"]
            # Sanitize raw IPTC for HTML display
            safe_iptc = iptc_raw.replace('<', '&lt;').replace('>', '&gt;')
            iptc_html += f"<li><b>Raw IPTC (base64-encoded)</b>: <pre>{safe_iptc[:500]}...</pre></li>" # Show preview
            iptc_html += "</ul>"

        analysis_items = "".join(f"<li>{h}</li>" for h in r["analysis"])
        
        if "thumbnail_analysis" in r:
            analysis_items += f"<li><b>Thumbnail:</b> {r['thumbnail_analysis']}</li>"

        string_report = ""
        if "strings" in r:
            string_report = f"<h4>Found Strings ({len(r['strings'])})</h4><div class='string-box'>{'<br>'.join(r['strings'])}</div>"
        
        timeline_report = ""
        if "timeline_reconstruction" in r:
            timeline_report = f"<h4>Timeline Reconstruction</h4><ul>{''.join(f'<li>{e}</li>' for e in r['timeline_reconstruction'])}</ul>"

        software_fingerprint_report = ""
        if "software_fingerprint" in r:
            software_fingerprint_report = f"<h4>Software Fingerprint</h4><p>{r['software_fingerprint']}</p>"


        body += f"""
        <div class="card">
            <h3>{r['name']}</h3>
            <p><b>SHA-256:</b> {r['hash']}</p>
            <table>{rows}</table>
            {xmp_html}
            {iptc_html} <!-- Insert IPTC here -->
            <h4>Analysis:</h4>
            <ul>{analysis_items}</ul>
            {string_report}
            {timeline_report}
            {software_fingerprint_report}
        </div>
        """
    html = f"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Image Forensic Report</title><style>
body {{ font-family: Arial, sans-serif; background:#f4f6f8; padding:20px; }}
.card {{ background:white; padding:15px; margin-bottom:20px; border-radius:10px; box-shadow:0 4px 10px rgba(0,0,0,.1); }}
table {{ width:100%; border-collapse:collapse; }}
td, th {{ border:1px solid #ddd; padding:8px; }}
a {{ color:#0066cc; }}
.string-box {{ height: 100px; overflow-y: scroll; border: 1px solid #ddd; padding: 5px; background: #fafafa; font-family: monospace; }}
</style></head><body><h1>Image Forensic Report</h1>{body}
<footer>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</footer></body></html>"""
    with open(output_path, "w", encoding="utf-8") as f: f.write(html)

def export_pdf(results, output_path, all_tags=False):
    """Generates a PDF report."""
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(output_path)
    story = [Paragraph("Image Forensic Report", styles["Title"])]
    for r in results:
        story.append(Paragraph(f"<b>{r['name']}</b>", styles["Heading2"]))
        story.append(Paragraph(f"SHA-256: {r['hash']}", styles["Normal"]))
        
        # EXIF Metadata Table
        exif_meta = {k: v for k, v in r["meta"].items() if not k.startswith("XMP") and not k.startswith("IPTC Raw")} if r.get("meta") else {}
        table_data = [["EXIF Tag", "Value"]]
        if exif_meta:
            tags_to_iterate = sorted(exif_meta.keys()) if all_tags else FORENSIC_TAGS
            for k in tags_to_iterate:
                if k in exif_meta and "JPEGThumbnail" not in k: 
                    table_data.append([k, str(exif_meta[k])])

        if r.get("gps_coords") and not all_tags:
            table_data.append(["GPS Coordinates", r['gps_coords']])
        
        if len(table_data) == 1: table_data.append(["-", "No EXIF metadata found"]) # If only header, add 'No data'
        story.append(Table(table_data, colWidths=[100, 350])) # Adjust col widths as needed
        story.append(Spacer(1, 12))

        # XMP Metadata
        if r.get("meta") and "XMP" in r["meta"]:
            story.append(Paragraph("<h4>XMP Metadata</h4>", styles["h4"]))
            xmp_data = r["meta"]["XMP"]
            if isinstance(xmp_data, dict):
                xmp_table_data = [["XMP Tag", "Value"]]
                for k, v in sorted(xmp_data.items()):
                    xmp_table_data.append([k, str(v)])
                story.append(Table(xmp_table_data, colWidths=[100, 350]))
            else: # Raw XMP string
                story.append(Paragraph(f"<b>Raw XMP:</b> {xmp_data}", styles["Normal"]))
            story.append(Spacer(1, 12))

        # IPTC Raw Data
        if r.get("meta") and "IPTC Raw" in r["meta"]:
            story.append(Paragraph("<h4>IPTC Raw Data</h4>", styles["h4"]))
            iptc_raw = r["meta"]["IPTC Raw"]
            story.append(Paragraph(f"<b>Raw IPTC (base64-encoded):</b> {iptc_raw[:500]}...", styles["Normal"]))
            story.append(Spacer(1, 12))

        story.append(Paragraph("Analysis:", styles["h4"]))
        for h in r["analysis"]: story.append(Paragraph(h, styles["Normal"]))
        if "thumbnail_analysis" in r: story.append(Paragraph(f"Thumbnail: {r['thumbnail_analysis']}", styles["Normal"]))
        
        if "timeline_reconstruction" in r:
            story.append(Paragraph("<h4>Timeline Reconstruction</h4>", styles["h4"]))
            for event in r["timeline_reconstruction"]:
                story.append(Paragraph(event, styles["Normal"]))
        
        if "software_fingerprint" in r:
            story.append(Paragraph("<h4>Software Fingerprint</h4>", styles["h4"]))
            story.append(Paragraph(r["software_fingerprint"], styles["Normal"]))

        story.append(Spacer(1, 16))
    doc.build(story)

def export_json(results, output_path):
    """Exports results to a JSON file."""
    # Custom serialization for metadata values
    def serialize_meta_value(value):
        if isinstance(value, dict):
            return {k: serialize_meta_value(v) for k, v in value.items()}
        # exifread objects have a __str__ method, so convert them to string
        # For Bytes, decode them if possible
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore')
        return str(value) # Default to string conversion

    serializable_results = []
    for r in results:
        serializable_r = r.copy() # Create a copy to modify
        if serializable_r.get("meta"):
            serializable_r["meta"] = serialize_meta_value(serializable_r["meta"])
        serializable_results.append(serializable_r)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(serializable_results, f, indent=4)

def export_csv(results, output_path):
    """Exports results to a CSV file."""
    if not results: return
    
    # Flatten the data and collect all possible headers
    flat_results = []
    all_headers = set(['name', 'hash'])
    
    for r in results:
        flat = {'name': r['name'], 'hash': r['hash']}
        if r.get("meta"):
            # Process EXIF
            exif_meta = {k: v for k, v in r['meta'].items() if not k.startswith("XMP") and not k.startswith("IPTC Raw")} # Filter out XMP/IPTC Raw
            for k, v in exif_meta.items():
                if k in FORENSIC_TAGS: # Only include defined forensic tags for EXIF
                    flat[k] = str(v)
                    all_headers.add(k)
            
            # Process XMP
            if "XMP" in r['meta']:
                xmp_data = r['meta']['XMP']
                if isinstance(xmp_data, dict):
                    for k, v in xmp_data.items():
                        # For CSV, flatten XMP tags to "XMP TagName"
                        csv_key = f"XMP {k}"
                        flat[csv_key] = str(v)
                        all_headers.add(csv_key)
                else: # Raw XMP string
                    flat["XMP Raw"] = str(xmp_data)
                    all_headers.add("XMP Raw")

            # Process IPTC Raw
            if "IPTC Raw" in r['meta']:
                iptc_raw = r['meta']['IPTC Raw']
                flat["IPTC Raw"] = str(iptc_raw)
                all_headers.add("IPTC Raw")

        flat_results.append(flat)
    
    sorted_headers = sorted(list(all_headers))

    with open(output_path, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=sorted_headers)
        writer.writeheader()
        writer.writerows(flat_results)

# -----------------------------
# Steganography Functions
# -----------------------------

def hide_message_in_image(input_path, output_path, message):
    """Hides a message in an image and saves it to a new file."""
    if not STEGANO_AVAILABLE:
        return False, "Stegano library not available. Please install it with 'pip install stegano'."
    
    try:
        secret_image = lsb.hide(input_path, message)
        secret_image.save(output_path)
        return True, f"Message hidden successfully in {output_path}"
    except Exception as e:
        return False, f"An error occurred: {e}"

def reveal_message_from_image(input_path):
    """Reveals a hidden message from an image."""
    if not STEGANO_AVAILABLE:
        return None, "Stegano library not available. Please install it with 'pip install stegano'."
        
    try:
        message = lsb.reveal(input_path)
        return message, "Message revealed successfully." if message else "No hidden message found."
    except Exception as e:
        return None, f"An error occurred: {e}"
