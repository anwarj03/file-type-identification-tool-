# File Type Identifier - Magic Number Analysis Tool

A Python-based cybersecurity tool that detects file type mismatches by analyzing file headers (magic numbers). This tool is essential for malware analysis and digital forensics, as it can identify executables disguised as benign file types.

## 🎯 Purpose

Hackers often disguise malware by renaming executables with innocent-looking extensions:
- `malware.exe` → `photo.jpg`
- `trojan.dll` → `document.pdf`
- `backdoor.sh` → `readme.txt`

This tool reads the actual binary file header to identify the **true** file type, regardless of the extension.

## 🔍 How It Works

1. **Reads file headers** - First few bytes of each file (up to 8KB)
2. **Compares against database** - Matches against known magic number signatures
3. **Detects mismatches** - Flags files where extension doesn't match actual type
4. **Identifies threats** - Marks suspicious combinations (e.g., executable as image)

## 📋 Features

- **Comprehensive signature database**: 40+ file type signatures including:
  - Executables (PE32, ELF, Mach-O)
  - Archives (ZIP, RAR, 7z, Gzip, Bzip2)
  - Images (JPEG, PNG, GIF, BMP, TIFF, WebP)
  - Documents (PDF, RTF, MS Office)
  - Media files (MP3, MP4, AVI, WAV, OGG)
  - Scripts (Python, Shell, Bash)
  - Databases (SQLite)

- **Threat detection**: Automatically flags suspicious mismatches
- **Recursive scanning**: Scan entire directory trees
- **Detailed reporting**: Generates comprehensive analysis reports
- **Exit codes**: Returns non-zero exit code if suspicious files found

## 🚀 Installation

No external dependencies required! Uses only Python standard library.

```bash
# Make the script executable
chmod +x file_type_identifier.py

# Or run with Python 3
python3 file_type_identifier.py
```

## 💻 Usage

### Analyze a Single File

```bash
python file_type_identifier.py suspicious_file.jpg
```

### Scan a Directory

```bash
python file_type_identifier.py /path/to/directory
```

### Recursive Directory Scan

```bash
python file_type_identifier.py /path/to/directory -r
```

### Save Report to File

```bash
python file_type_identifier.py /path/to/directory -o report.txt
```

### Command Line Options

```
usage: file_type_identifier.py [-h] [-r] [-o OUTPUT] [-q] path

positional arguments:
  path                  File or directory to analyze

optional arguments:
  -h, --help           Show help message
  -r, --recursive      Recursively scan subdirectories
  -o OUTPUT, --output OUTPUT
                       Output report to file
  -q, --quiet          Only show suspicious files
```

## 🧪 Testing

Create test files to see the tool in action:

```bash
# Generate test files (includes malicious samples)
python create_test_files.py

# Analyze the test files
python file_type_identifier.py test_files/
```

This creates:
- ✅ Legitimate files with correct extensions
- ⚠️ Executables disguised as images/documents
- ℹ️ Benign type mismatches

## 📊 Sample Output

```
================================================================================
FILE TYPE IDENTIFICATION REPORT
================================================================================
Generated: 2024-02-05 14:30:22
Total files analyzed: 10

Files with type mismatch: 5
Suspicious files detected: 3

⚠️  SUSPICIOUS FILES (HIGH PRIORITY)
--------------------------------------------------------------------------------

File: malware.jpg
  Path: test_files/malware.jpg
  Claimed extension: .jpg
  Detected type: PE32 Executable
  Expected extension: .exe
  Description: Windows PE executable
  ⚠️  WARNING: Potentially malicious file masquerading!

File: trojan.png
  Path: test_files/trojan.png
  Claimed extension: .png
  Detected type: PE32 Executable
  Expected extension: .exe
  Description: Windows PE executable
  ⚠️  WARNING: Potentially malicious file masquerading!

File: backdoor.pdf
  Path: test_files/backdoor.pdf
  Claimed extension: .pdf
  Detected type: ELF Executable
  Expected extension: .elf
  Description: Linux/Unix executable
  ⚠️  WARNING: Potentially malicious file masquerading!

ℹ️  TYPE MISMATCHES (REVIEW RECOMMENDED)
--------------------------------------------------------------------------------

File: document.zip
  Path: test_files/document.zip
  Claimed extension: .zip
  Detected type: ZIP Archive
  Expected extension: .zip

✓ 5 files have matching extensions

================================================================================
```

## 🔬 Technical Details

### Magic Numbers Database

The tool includes signatures for:

| File Type | Magic Bytes | Offset | Extension |
|-----------|-------------|--------|-----------|
| PE32 Executable | `4D 5A` (MZ) | 0 | .exe, .dll, .sys |
| ELF Executable | `7F 45 4C 46` | 0 | .elf, .so |
| PNG Image | `89 50 4E 47 0D 0A 1A 0A` | 0 | .png |
| JPEG Image | `FF D8 FF` | 0 | .jpg, .jpeg |
| PDF Document | `25 50 44 46` (%PDF) | 0 | .pdf |
| ZIP Archive | `50 4B 03 04` (PK) | 0 | .zip, .jar, .docx |

### Suspicious Combinations

The tool flags these as high-priority threats:
- Executables (PE32, ELF, Mach-O) with image extensions (.jpg, .png, .gif)
- Executables with document extensions (.pdf, .doc, .txt)
- Scripts with non-script extensions
- Archives with executable extensions

## 🛡️ Use Cases

1. **Malware Analysis**: Identify executables disguised as benign files
2. **Digital Forensics**: Verify file integrity and detect tampering
3. **Email Attachment Scanning**: Detect malicious attachments
4. **Download Verification**: Ensure downloaded files match expected type
5. **System Auditing**: Scan systems for suspicious files

## 🧩 Extending the Tool

### Add New File Signatures

Edit the `_build_signature_database()` method in `MagicNumberDatabase`:

```python
FileSignature(
    "New File Type",           # Type name
    [".ext1", ".ext2"],        # Valid extensions
    b"\x00\x01\x02",          # Magic bytes
    0,                         # Offset from start
    "Description"              # Description
)
```

### Custom Suspicious Rules

Modify `_is_suspicious_mismatch()` to add custom threat detection logic.

## ⚠️ Limitations

- Only checks first 8KB of each file (configurable)
- Some file types don't have magic numbers (plain text)
- Polymorphic malware may not be detected
- Some legitimate files may have benign mismatches (e.g., .docx are ZIP files)

## 🎓 Learning Outcomes

This project demonstrates:
- **Binary file analysis**: Reading and interpreting raw bytes
- **Pattern matching**: Comparing byte sequences
- **File system operations**: Traversing directories, reading files
- **Threat detection**: Identifying suspicious patterns
- **Python skills**: File I/O, data structures, command-line tools
- **Cybersecurity concepts**: Magic numbers, file signatures, malware evasion

## 📚 References

- [List of file signatures (Wikipedia)](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [File format identification](https://www.garykessler.net/library/file_sigs.html)
- [PE Format (Windows executables)](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ELF Format (Linux executables)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)

## 📄 License

This tool is for educational and legitimate security purposes only. Use responsibly.

## 🤝 Contributing

Ideas for enhancements:
- Add more file type signatures
- Implement deep file analysis (beyond headers)
- Add hash-based malware detection
- Create GUI interface
- Export results to CSV/JSON
- Integration with VirusTotal API

---

**Remember**: This tool identifies file types but doesn't scan for viruses. Always use proper antivirus software for production systems.
