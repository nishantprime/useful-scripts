"""
Single-File Folder Summarizer & File Tree (Tree-Ordered & Diagrammatic)
Double-click or drag-and-drop this file into ANY folder on your computer to
automatically scan all files and generate a clean 'file_summary.txt' report.

Features:
- Diagrammatic ASCII folder map (root -> subfolders -> subfolders with counts).
- Detailed inventory rendered in true hierarchical tree order (depth-first).
- Smart 3-tier SHA-256 hashing (never freezes on large files).
- Real file type detection via magic byte signatures.
- Zero dependencies (100% built-in Python standard library).
"""

import os
import sys
import hashlib
import datetime
import mimetypes

# ==============================================================================
# CONFIGURATION
# ==============================================================================
# Folders to automatically skip (virtual environments, caches, git internals)
IGNORE_DIR_NAMES = {
    "venv", ".venv", "env", ".env", "site-packages",
    ".git", "__pycache__", "node_modules", ".pytest_cache",
    ".idea", ".vscode", ".mypy_cache", ".ruff_cache",
    "$recycle.bin", "system volume information"
}

# Minimum file size in bytes to include (0 = keep all files regardless of size)
MIN_FILE_SIZE_BYTES = 0

# Skip hidden files and folders (starting with a dot like .DS_Store, .gitignore)
SKIP_HIDDEN = True


# ==============================================================================
# 1. SMART HASHING & FILE TYPE HELPERS
# ==============================================================================

def format_size(size_bytes):
    """Convert bytes into human-readable format (KB, MB, GB)."""
    if size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    unit_idx = 0
    while size >= 1024.0 and unit_idx < len(units) - 1:
        size /= 1024.0
        unit_idx += 1
    return f"{size:.2f} {units[unit_idx]}"

def compute_smart_hash(file_path, file_size):
    """
    Smart Hashing:
    - Files <= 5MB: Calculates full SHA-256.
    - Files > 5MB: Reads first 64KB + middle 64KB + last 64KB (instant 0.1ms fingerprint,
      never freezes on huge movies/ISOs).
    """
    if file_size <= 0:
        return "EMPTY_FILE"

    chunk_size = 64 * 1024  # 64 KB
    try:
        hasher = hashlib.sha256()

        if file_size <= (5 * 1024 * 1024):
            with open(file_path, "rb") as f:
                while chunk := f.read(128 * 1024):
                    hasher.update(chunk)
            return hasher.hexdigest()

        with open(file_path, "rb") as f:
            # 1. First 64 KB
            hasher.update(f.read(chunk_size))

            # 2. Middle 64 KB
            mid_offset = max(0, (file_size // 2) - (chunk_size // 2))
            f.seek(mid_offset, os.SEEK_SET)
            hasher.update(f.read(chunk_size))

            # 3. Last 64 KB
            footer_offset = max(0, file_size - chunk_size)
            f.seek(footer_offset, os.SEEK_SET)
            hasher.update(f.read(chunk_size))

        return f"[fast-sha256] {hasher.hexdigest()}"
    except Exception as e:
        return f"ERR_UNREADABLE ({e.__class__.__name__})"

MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG Image"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG Image"),
    (b"GIF87a", "image/gif", "GIF Image"),
    (b"GIF89a", "image/gif", "GIF Image"),
    (b"%PDF-", "application/pdf", "PDF Document"),
    (b"PK\x03\x04", "application/zip", "ZIP Archive (or Office Doc)"),
    (b"Rar!\x1a\x07", "application/x-rar", "RAR Archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z", "7-Zip Archive"),
    (b"\x1a\x45\xdf\xa3", "video/x-matroska", "MKV Video"),
    (b"MZ", "application/x-dosexec", "Windows Executable/DLL"),
    (b"SQLite format 3\x00", "application/x-sqlite3", "SQLite Database"),
]

def detect_file_type(file_path):
    """Detect real file type by reading first bytes, falling back to extension."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(32)
        for sig, mime, desc in MAGIC_SIGNATURES:
            if header.startswith(sig):
                return f"{desc} ({mime})"
        if len(header) >= 12 and header[4:8] == b"ftyp":
            return "MP4 Video (video/mp4)"
    except Exception:
        pass

    guessed, _ = mimetypes.guess_type(file_path)
    if guessed:
        return f"{guessed.split('/')[-1].upper()} ({guessed})"
    return "Unknown Binary"


# ==============================================================================
# 2. HIERARCHICAL FOLDER TREE STRUCTURE
# ==============================================================================

class FolderNode:
    """Represents a directory in the hierarchical folder tree."""
    def __init__(self, full_path, rel_path, name):
        self.full_path = full_path
        self.rel_path = rel_path
        self.name = name
        self.files = []       # list of file record dicts
        self.children = []    # list of child FolderNode objects
        self.direct_size = 0
        self.total_files = 0
        self.total_size = 0

def calculate_tree_stats(node):
    """Recursively calculate file counts and total sizes for each folder."""
    t_files = len(node.files)
    t_size = node.direct_size
    for child in node.children:
        calculate_tree_stats(child)
        t_files += child.total_files
        t_size += child.total_size
    node.total_files = t_files
    node.total_size = t_size

def render_ascii_folder_map(node, prefix="", is_last=True, is_root=True):
    """
    Renders an ASCII folder tree showing directory hierarchy and counts.
    Example:
    📁 .  (5 files, 2 subfolders | 12.40 MB)
    ├── 📁 docs  (2 files, 0 subfolders | 150.00 KB)
    └── 📁 src  (3 files, 1 subfolder | 12.25 MB)
    """
    lines = []
    display_name = "." if is_root else node.name
    count_info = f"({len(node.files)} files, {len(node.children)} subfolders | {format_size(node.total_size)})"
    label = f"📁 {display_name}  {count_info}"

    if is_root:
        lines.append(label)
        child_prefix = ""
    else:
        branch = "└── " if is_last else "├── "
        lines.append(prefix + branch + label)
        child_prefix = prefix + ("    " if is_last else "│   ")

    for i, child in enumerate(node.children):
        last_child = (i == len(node.children) - 1)
        lines.extend(render_ascii_folder_map(child, child_prefix, last_child, is_root=False))

    return lines

def render_detailed_tree_inventory(node, depth=0):
    """
    Renders full file inventory in true hierarchical depth-first tree order.
    Subfolders are rendered indented directly under their parent folder.
    """
    lines = []
    indent = "    " * depth
    rel_folder = "." if node.rel_path == "." else f".\\{node.rel_path}"

    lines.append(f"{indent}📁 [FOLDER] {rel_folder}  ({len(node.files)} files | {format_size(node.direct_size)})")
    lines.append(f"{indent}   Path: {node.full_path}")

    records = sorted(node.files, key=lambda x: x["name"].lower())
    for idx, r in enumerate(records):
        is_last = (idx == len(records) - 1 and len(node.children) == 0)
        branch = "└──" if is_last else "├──"
        pipe = "   " if is_last else "│  "

        lines.append(f"{indent}   {branch} 📄 {r['name']}  ({r['size_human']})")
        lines.append(f"{indent}   {pipe}    Type     : {r['type']}")
        lines.append(f"{indent}   {pipe}    Created  : {r['created']}  |  Modified : {r['modified']}")
        lines.append(f"{indent}   {pipe}    SHA-256  : {r['hash']}")
        lines.append(f"{indent}   {pipe}")

    lines.append("")

    # Recurse into children in true tree order
    for child in node.children:
        lines.extend(render_detailed_tree_inventory(child, depth + 1))

    return lines


# ==============================================================================
# 3. SCANNER CORE
# ==============================================================================

def scan_current_folder():
    target_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(target_dir, "file_summary.txt")
    current_script_name = os.path.basename(__file__)

    print("=" * 65)
    print("  FOLDER SUMMARY & FILE TREE (TREE ORDER)")
    print("=" * 65)
    print(f"[*] Target Folder  : {target_dir}")
    print(f"[*] Ignored Junk   : Virtual envs (.venv/venv), .git, __pycache__, etc.")
    print("[*] Scanning please wait...\n")

    nodes = {}
    root_node = None
    total_files = 0
    total_bytes = 0

    for root, dirs, files in os.walk(target_dir, topdown=True):
        # In-place filtering of dirs stops os.walk from entering junk/venv folders
        dirs[:] = [
            d for d in dirs
            if d.lower() not in IGNORE_DIR_NAMES
            and not (SKIP_HIDDEN and d.startswith("."))
            and not d.startswith("__")
        ]
        dirs.sort(key=str.lower)

        rel_dir = os.path.relpath(root, target_dir)
        folder_name = os.path.basename(root) if rel_dir != "." else "."

        node = FolderNode(root, rel_dir, folder_name)
        nodes[root] = node

        if root == target_dir:
            root_node = node
        else:
            parent_dir = os.path.dirname(root)
            if parent_dir in nodes:
                nodes[parent_dir].children.append(node)

        file_records = []
        for file_name in sorted(files, key=str.lower):
            # Skip the script itself and the output file
            if file_name in (current_script_name, "file_summary.txt"):
                continue

            # Skip hidden files (.gitignore, .DS_Store) and Office lock files (~$)
            if SKIP_HIDDEN and file_name.startswith("."):
                continue
            if file_name.startswith("~$"):
                continue

            full_path = os.path.join(root, file_name)
            try:
                st = os.stat(full_path)
                file_size = st.st_size

                if file_size < MIN_FILE_SIZE_BYTES:
                    continue

                created_date = datetime.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
                modified_date = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                file_type = detect_file_type(full_path)
                file_hash = compute_smart_hash(full_path, file_size)

                file_records.append({
                    "name": file_name,
                    "path": full_path,
                    "size_bytes": file_size,
                    "size_human": format_size(file_size),
                    "created": created_date,
                    "modified": modified_date,
                    "type": file_type,
                    "hash": file_hash
                })

                total_files += 1
                total_bytes += file_size

                if total_files % 25 == 0:
                    print(f"    Cataloged {total_files} files...", end="\r", flush=True)

            except Exception:
                pass

        node.files = file_records
        node.direct_size = sum(f["size_bytes"] for f in file_records)

    print(f"    Total files cataloged: {total_files}\n")

    if root_node is None:
        print("[!] No files or directories found.")
        return

    # Calculate recursive counts and sizes for each folder
    calculate_tree_stats(root_node)

    # ==============================================================================
    # 4. WRITE THE STRUCTURED REPORT (ASCII MAP + TREE INVENTORY)
    # ==============================================================================
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write(f"  FILE TREE & METADATA SUMMARY\n")
        f.write(f"  Target Folder : {target_dir}\n")
        f.write(f"  Scan Date     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total Files   : {total_files:,}\n")
        f.write(f"  Total Size    : {format_size(total_bytes)}\n")
        f.write("=" * 80 + "\n\n")

        # -------------------------------------------------------------
        # Part 1: Diagrammatic ASCII Folder Map
        # -------------------------------------------------------------
        f.write("=" * 80 + "\n")
        f.write("  1. FOLDER TREE STRUCTURE (DIAGRAM)\n")
        f.write("=" * 80 + "\n\n")

        ascii_lines = render_ascii_folder_map(root_node)
        f.write("\n".join(ascii_lines) + "\n\n")

        # -------------------------------------------------------------
        # Part 2: Detailed File Inventory in True Tree Order
        # -------------------------------------------------------------
        f.write("=" * 80 + "\n")
        f.write("  2. DETAILED FILE INVENTORY (IN TREE ORDER)\n")
        f.write("=" * 80 + "\n\n")

        detailed_lines = render_detailed_tree_inventory(root_node)
        f.write("\n".join(detailed_lines) + "\n")

    print("[✔] Scan Complete!")
    print(f"[*] Summary written to: {output_file}")
    print(f"[*] Cataloged: {total_files:,} files  |  Total Size: {format_size(total_bytes)}")


if __name__ == "__main__":
    scan_current_folder()

    try:
        input("\nPress Enter to exit...")
    except Exception:
        pass
