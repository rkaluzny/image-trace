import argparse
import os

# Import all core functions from the new central module
import analysis_core as core

# -----------------------------
# CLI UI/UX Enhancements
# -----------------------------

# Enable ANSI escape codes on Windows
if os.name == 'nt':
    os.system('')

class Colors:
    """ANSI color codes for prettier terminal output."""
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def print_error(msg):
    """Prints a formatted error message."""
    print(f"{Colors.RED}{Colors.BOLD}❌ Error: {msg}{Colors.RESET}")

def print_success(msg):
    """Prints a formatted success message."""
    print(f"{Colors.GREEN}✔ {msg}{Colors.RESET}")

def print_warning(msg):
    """Prints a formatted warning message."""
    print(f"{Colors.YELLOW}⚠ Warning: {msg}{Colors.RESET}")

def print_info(msg):
    """Prints a formatted info message."""
    print(f"{Colors.BLUE}ℹ {msg}{Colors.RESET}")

def print_header(title):
    """Prints a styled header."""
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}--- {title.upper()} ---{Colors.RESET}")

# -----------------------------
# Command Handlers
# -----------------------------

def run_analyze(args):
    """Handler for the 'analyze' command."""
    if args.compare:
        if len(args.sources) != 2:
            print_error("Compare mode requires exactly two sources.")
            return
        print_info("Comparing metadata of two images...")
        try:
            data1, name1 = core.get_data_from_source(args.sources[0])
            data2, name2 = core.get_data_from_source(args.sources[1])
            meta1 = core.read_metadata(data1)
            meta2 = core.read_metadata(data2)
        except Exception as e:
            print_error(f"Processing files: {e}")
            return
        
        diff = core.exif_diff(meta1, meta2)
        print_header(f"Comparison: {name1} vs {name2}")
        if not diff:
            print_success("No differences found in metadata.")
        else:
            max_key_len = max(len(d[0]) for d in diff) if diff else 0
            header = f"{'Tag':<{max_key_len}} | {'Image 1'} | {'Image 2'}"
            print(f"{Colors.BOLD}{header}{Colors.RESET}")
            print("-" * (len(header) + 5))
            for k, v1, v2 in diff:
                print(f"{Colors.CYAN}{k:<{max_key_len}}{Colors.RESET} | {v1} | {v2}")
            print("-" * (len(header) + 5))
        return

    # Load string patterns if provided
    string_patterns = []
    if args.pattern_file:
        try:
            with open(args.pattern_file, 'r', encoding='utf-8') as f:
                string_patterns = [line.strip() for line in f if line.strip()]
            print_info(f"Loaded {len(string_patterns)} patterns from {args.pattern_file}")
        except Exception as e:
            print_error(f"Could not load patterns from {args.pattern_file}: {e}")
            return # Abort if patterns cannot be loaded

    results = []
    print_info(f"Analyzing {len(args.sources)} source(s)...")
    from tqdm import tqdm
    for src in tqdm(args.sources, desc="Analyzing sources", unit="file"):
        try:
            print(f"Processing: {Colors.CYAN}{src}{Colors.RESET}")
            data, name = core.get_data_from_source(src)
            meta = core.read_metadata(data)
            
            result = {
                "name": name, "hash": core.sha256(data),
                "meta": meta, "analysis": core.basic_forensic_analysis(meta),
                "filepath_or_url": src,
            }
            
            # GPS Analysis (always on)
            gps_coords, gps_link = core.format_gps_coordinates(meta)
            if gps_coords:
                result["gps_coords"] = gps_coords
                result["gps_link"] = gps_link

            # Optional analyses based on flags
            if args.string_analysis:
                result["strings"] = core.extract_strings(data, patterns=string_patterns)
            if args.thumbnail_analysis:
                result["thumbnail_analysis"] = core.analyze_thumbnail(data)
            if args.ela:
                ela_image_bytes, ela_msg = core.perform_ela(data)
                if ela_image_bytes:
                    result["ela_image_bytes"] = ela_image_bytes
                    result["analysis"].append(f"✔ ELA performed successfully (image embedded in HTML report).")
                else:
                    result["analysis"].append(f"❌ ELA Error: {ela_msg}")
            if args.timeline:
                result["timeline_reconstruction"] = core.reconstruct_timeline(meta, src if not src.startswith("http") else None)
            if args.fingerprint:
                result["software_fingerprint"] = core.fingerprint_software(meta)

            results.append(result)
            print_success(f"Finished processing {name}")

        except FileNotFoundError:
            print_error(f"File not found: {src}")
        except Exception as e:
            print_error(f"Could not process {src}: {e}")
    
    if not results:
        print_warning("No results were generated.")
        return

    # --- Print to console if no output format is specified ---
    if not any([args.output, args.json, args.csv]):
        print_header("Analysis Quick Report")
        for r in results:
            print(f"\n{Colors.BOLD}File: {r['name']}{Colors.RESET}")
            print(f"{Colors.DIM}SHA-256: {r['hash']}{Colors.RESET}")
            
            # Handling metadata display for local files vs. URLs
            if os.path.exists(r['filepath_or_url']) and not r['filepath_or_url'].startswith("http"):
                 metadata_str = core.get_metadata(r['filepath_or_url'], args.all_tags)
                 print(f"{Colors.CYAN}--- Metadata ---{Colors.RESET}\n{metadata_str}\n")
            elif r['meta']: # For URLs or when file might not be accessible locally later
                print(f"{Colors.CYAN}--- Metadata ---{Colors.RESET}")
                # Simple display of meta dict structure
                for k, v in r['meta'].items():
                    if k == "XMP": # Handle XMP specifically
                        print(f"{k}: (see XMP section below or report for details)")
                    else:
                        print(f"{k}: {v}")
                print("\n")
            else:
                print(f"{Colors.CYAN}--- Metadata ---{Colors.RESET}\nNo metadata found.\n")
            
            print(f"{Colors.CYAN}--- Analysis Hints ---{Colors.RESET}")
            for item in r.get("analysis", []): print(item)
            
            if "thumbnail_analysis" in r: print(f"Thumbnail: {r['thumbnail_analysis']}")
            if "timeline_reconstruction" in r: print(f"\n{Colors.CYAN}--- Timeline ---{Colors.RESET}\n{r['timeline_reconstruction']}")
            if "software_fingerprint" in r: print(f"\n{Colors.CYAN}--- Software Fingerprint ---{Colors.RESET}\n{r['software_fingerprint']}")
            
            if "strings" in r:
                strings_data = r["strings"]
                if strings_data.get("all_strings"):
                    print(f"\n{Colors.CYAN}--- All Printable Strings (Preview) ---{Colors.RESET}")
                    preview_strings = strings_data["all_strings"][:5] # Show first 5
                    for s in preview_strings:
                        print(f"  - {s[:100]}{'...' if len(s)>100 else ''}")
                    if len(strings_data["all_strings"]) > 5:
                        print(f"  ... ({len(strings_data['all_strings']) - 5} more)")
                
                if strings_data.get("matched_patterns"):
                    print(f"\n{Colors.CYAN}--- Matched Patterns ---{Colors.RESET}")
                    for pattern_desc, matches in strings_data["matched_patterns"].items():
                        print(f"{Colors.BOLD}{pattern_desc}{Colors.RESET}")
                        for match in matches:
                            print(f"  - {match}")

    # --- Handle report exports ---
    if args.output:
        print_info(f"Generating HTML report at {args.output}")
        core.export_html(results, args.output, all_tags=args.all_tags)
        print_success("HTML report saved.")
        if not args.no_pdf:
            pdf_output = os.path.splitext(args.output)[0] + ".pdf"
            print_info(f"Generating PDF report at {pdf_output}")
            core.export_pdf(results, pdf_output, all_tags=args.all_tags)
            print_success("PDF report saved.")
    
    if args.json:
        print_info(f"Exporting results to {args.json}")
        core.export_json(results, args.json)
        print_success("JSON report saved.")
    
    if args.csv:
        print_info(f"Exporting metadata to {args.csv}")
        core.export_csv(results, args.csv)
        print_success("CSV report saved.")

    print_header("Analysis complete.")


def run_modify(args):
    """Handler for the 'modify' command, now with batch support."""
    if not core.PIEXIF_AVAILABLE:
        print_error("The 'piexif' library is required for this function.")
        print_info("Please install it using: pip install piexif")
        return

    source_path = args.from_file
    output_dir = args.to_file

    if not os.path.exists(source_path):
        print_error(f"Source file or directory not found: {source_path}")
        return

    # In a batch context, the output must be a directory.
    # We create it if it doesn't exist.
    if not os.path.exists(output_dir):
        print_info(f"Creating output directory: {output_dir}")
        os.makedirs(output_dir)
    elif not os.path.isdir(output_dir):
        print_error(f"Output path '{output_dir}' exists but is not a directory.")
        return


    # Collect files to process
    if os.path.isfile(source_path):
        files_to_process = [source_path]
    else:
        print_info(f"Scanning directory for images: {source_path}")
        files_to_process = core.collect_files([source_path], recursive=True)
    
    # Filter for image types that piexif supports (JPEG, TIFF)
    image_files = [f for f in files_to_process if f.lower().endswith(('.jpg', '.jpeg', '.tif', '.tiff'))]
    if not image_files:
        print_warning("No supported image files (JPG, TIF) found in the source.")
        return

    print_info(f"Found {len(image_files)} image(s) to process.")
    print_header("Starting Batch Modification")
    from tqdm import tqdm
    for input_path in tqdm(image_files, desc="Modifying images", unit="file"):
        output_path = os.path.join(output_dir, os.path.basename(input_path))
        print(f"Processing {Colors.CYAN}{os.path.basename(input_path)}{Colors.RESET} -> {Colors.CYAN}{os.path.basename(output_path)}{Colors.RESET}")

        if args.clear:
            try:
                core.piexif.remove(input_path, output_path)
                print_success("  - All EXIF data removed.")
            except Exception as e:
                print_error(f"  - Could not remove EXIF data: {e}")
            continue  # Go to next file
        
        # New: Sanitize operation
        if args.sanitize:
            try:
                # Load existing EXIF data first to preserve any non-sanitized sections, then modify
                exif_dict = core.piexif.load(input_path)
                print_info("  - Generating trustworthy EXIF data...")
                core.generate_trustworthy_exif(exif_dict)
                exif_bytes = core.piexif.dump(exif_dict)
                core.piexif.insert(exif_bytes, input_path, output_path)
                print_success("  - Trustworthy EXIF data generated and saved.")
            except Exception as e:
                print_error(f"  - Could not sanitize EXIF data: {e}")
            continue # Go to next file

        if args.set:
            try:
                exif_dict = core.piexif.load(input_path)
            except Exception:
                exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
                print_warning("  - Could not load existing EXIF data. Creating new tags.")

            for item in args.set:
                try:
                    key, value = item.split('=', 1)
                    if key in core.TAG_MAP:
                        ifd, tag_id = core.TAG_MAP[key]
                        exif_dict[ifd][tag_id] = value.encode('utf-8')
                        print(f"  - Setting '{key}' to '{value}'")
                    else:
                        print_warning(f"  - Unknown tag '{key}'. It will be ignored.")
                except ValueError:
                    print_error(f"  - Invalid --set format '{item}'. Must be 'TAG=VALUE'.")
                    continue
            try:
                exif_bytes = core.piexif.dump(exif_dict)
                # Use insert to preserve image data from the original file
                core.piexif.insert(exif_bytes, input_path, output_path)
                print_success("  - Modified EXIF data saved.")
            except Exception as e:
                print_error(f"  - Could not save the new image file: {e}")
    print_header("Batch modification complete.")

def run_stegano_hide(args):
    """Handler for the 'stegano hide' command."""
    if not core.STEGANO_AVAILABLE:
        print_error("The 'stegano' library is required for this function.")
        print_info("Please install it using: pip install stegano")
        return
    
    if not os.path.exists(args.input):
        print_error(f"Input file not found: {args.input}")
        return

    success, message = core.hide_message_in_image(args.input, args.output, args.message)
    if success:
        print_success(message)
    else:
        print_error(message)

def run_stegano_reveal(args):
    """Handler for the 'stegano reveal' command."""
    if not core.STEGANO_AVAILABLE:
        print_error("The 'stegano' library is required for this function.")
        print_info("Please install it using: pip install stegano")
        return

    if not os.path.exists(args.input):
        print_error(f"Input file not found: {args.input}")
        return
        
    message, status = core.reveal_message_from_image(args.input)
    if message is not None:
        print_success(f"Revealed message: '{Colors.BOLD}{message}{Colors.RESET}'")
    else:
        print_error(status)

# -----------------------------
# Main CLI Logic
# -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ImageTrace: A command-line tool for digital image forensics.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""{Colors.BOLD}Examples:{Colors.RESET}
  - Quick analysis of an image, printed to the console:
    {Colors.CYAN}ImageTrace_CLI analyze image.jpg --timeline --fingerprint{Colors.RESET}

  - Comprehensive analysis of all images in a folder with HTML/PDF reports:
    {Colors.CYAN}ImageTrace_CLI analyze ./my_images/ -o report.html --ela --string-analysis{Colors.RESET}

  - Compare metadata of two images:
    {Colors.CYAN}ImageTrace_CLI analyze image1.jpg image2.jpg --compare{Colors.RESET}

  - Clear all EXIF data from all images in a folder:
    {Colors.CYAN}ImageTrace_CLI modify --source ./input_folder/ --output-dir ./cleared_folder/ --clear{Colors.RESET}
    
  - Sanitize EXIF data for all images in a folder:
    {Colors.CYAN}ImageTrace_CLI modify --source ./input_folder/ --output-dir ./sanitized_folder/ --sanitize{Colors.RESET}

  - Hide a secret message in a PNG file:
    {Colors.CYAN}ImageTrace_CLI stegano hide --input carrier.png --output secret.png --message "top secret"{Colors.RESET}

  - Reveal a message from an image:
    {Colors.CYAN}ImageTrace_CLI stegano reveal --input secret.png{Colors.RESET}
""")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands.")

    # --- Analyze command ---
    parser_analyze = subparsers.add_parser(
        "analyze", 
        help="Performs forensic analysis on image files.",
        description="Analyzes one or more images (local or URL) for metadata, manipulation traces, and hidden data."
    )
    parser_analyze.add_argument("sources", metavar="SOURCE", nargs='+', help="One or more image file paths or URLs to analyze.")
    
    export_group = parser_analyze.add_argument_group(f"{Colors.BOLD}Export Options{Colors.RESET}", "Save analysis results to files. If no option is given, a summary is printed to the console.")
    export_group.add_argument("-o", "--output", help="Path for the main HTML report. A PDF will be generated alongside it.")
    export_group.add_argument("--no-pdf", action="store_true", help="Disables the automatic PDF report creation when -o is used.")
    export_group.add_argument("--json", help="Export the full, raw analysis results to a JSON file.")
    export_group.add_argument("--csv", help="Export a summary of key metadata tags to a CSV file.")

    analysis_group = parser_analyze.add_argument_group(f"{Colors.BOLD}Analysis Modules{Colors.RESET}", "Enable additional, powerful analysis modules.")
    analysis_group.add_argument("--compare", action="store_true", help="Compare the EXIF data of exactly two images. Ignores other analyses and exports.")
    analysis_group.add_argument("--all-tags", action="store_true", help="Show all available EXIF tags, not just the forensically relevant ones.")
    analysis_group.add_argument("--ela", action="store_true", help="Perform Error Level Analysis (ELA) to detect manipulations. The resulting image is embedded in the HTML report.")
    analysis_group.add_argument("--timeline", action="store_true", help="Reconstruct a chronological timeline of events from EXIF and filesystem timestamps.")
    analysis_group.add_argument("--string-analysis", action="store_true", help="Extract and display printable strings from the image's binary data to find hidden text or signatures.")
    analysis_group.add_argument("--thumbnail-analysis", action="store_true", help="Analyze the embedded thumbnail and compare it to the main image, which can indicate manipulation.")
    analysis_group.add_argument("--fingerprint", action="store_true", help="Attempt to identify the camera or software used to save the image by analyzing its JPEG DQT hash.")
    analysis_group.add_argument("--pattern-file", help="Path to a file containing regex patterns (one per line) to search for in strings. Use with --string-analysis.")

    parser_analyze.set_defaults(func=run_analyze)

    # --- Modify command ---
    parser_modify = subparsers.add_parser("modify", help="Modify or strip EXIF data for one or more images.", description="Changes or removes EXIF metadata from a source file or directory and saves the result(s) to an output directory. Requires 'piexif'.")
    parser_modify.add_argument("--source", dest="from_file", required=True, help="Input file or directory of images (e.g., original.jpg or /path/to/images).")
    parser_modify.add_argument("--output-dir", dest="to_file", required=True, help="Output directory to save the modified image(s) (e.g., /path/to/modified_images).")
    modify_group = parser_modify.add_mutually_exclusive_group(required=True)
    modify_group.add_argument("--set", action="append", metavar='TAG=VALUE', help="Set an EXIF tag. Can be used multiple times. E.g., --set \"Image Software=My Editor\"")
    modify_group.add_argument("--clear", action="store_true", help="Remove all EXIF data from the image(s).")
    modify_group.add_argument("--sanitize", action="store_true", help="Generate plausible, generic EXIF data for an image, removing sensitive information.")
    parser_modify.set_defaults(func=run_modify)

    # --- Steganography command ---
    parser_stegano = subparsers.add_parser("stegano", help="Hide or reveal secret messages in images.", description="Uses Least Significant Bit (LSB) steganography. Requires 'stegano'.")
    stegano_subparsers = parser_stegano.add_subparsers(dest="stegano_command", required=True, help="Steganography commands.")

    parser_stegano_hide = stegano_subparsers.add_parser("hide", help="Hide a message in a carrier image.")
    parser_stegano_hide.add_argument("--input", required=True, help="Input carrier image file. Lossless formats like PNG are best.")
    parser_stegano_hide.add_argument("--output", required=True, help="Path to save the output image with the hidden message.")
    parser_stegano_hide.add_argument("--message", required=True, help="The secret message to hide.")
    parser_stegano_hide.set_defaults(func=run_stegano_hide)

    parser_stegano_reveal = stegano_subparsers.add_parser("reveal", help="Reveal a message from an image.")
    parser_stegano_reveal.add_argument("--input", required=True, help="Input image file suspected of containing a hidden message.")
    parser_stegano_reveal.set_defaults(func=run_stegano_reveal)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

