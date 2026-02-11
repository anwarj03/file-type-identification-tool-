# File Type Identifier - Malware Detection Tool

<div align="center">

🔍 **Detect Malware Disguised with Fake File Extensions**

*Your first line of defense against social engineering attacks*

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-Educational-orange.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

[Features](#-features) • [Quick Start](#-quick-start) • [Usage](#-usage) • [Examples](#-examples) • [Documentation](#-documentation)

</div>

---

## 🎯 The Problem

**Hackers disguise malware by renaming file extensions:**

```
malware.exe  →  vacation_photo.jpg
trojan.dll   →  invoice.pdf  
backdoor.sh  →  readme.txt
```

Your operating system relies on the file extension to determine how to handle files. But the **actual file type** is determined by the file's internal structure (magic numbers).

**This tool reads the file header to identify the TRUE file type, regardless of what the extension claims.**

---

## 💡 The Solution

File Type Identifier analyzes the binary header (magic numbers) of files to detect:
- ✅ Executables disguised as images
- ✅ Malware renamed with innocent extensions  
- ✅ Scripts hiding as text files
- ✅ Any file type mismatch that could indicate an attack

**60+ file type signatures** | **Instant analysis** | **No installation required**

---

## 🚀 Quick Start

### Requirements
- Python 3.8 or higher
- **No external dependencies!** Uses only Python standard library

### Installation

```bash
# 1. Download the files
git clone https://github.com/yourusername/file-type-identifier.git
cd file-type-identifier

# 2. That's it! No pip install needed.

# 3. Run the interactive terminal interface
python file_analyzer_interactive.py
```

### First Analysis (10 seconds)

```bash
# Launch interactive menu
python file_analyzer_interactive.py

# Choose option 1: Analyze a single file
# Drag & drop a file into the terminal
# Press Enter
# See instant results!
```

---

## ✨ Features

### 🖥️ **Interactive Terminal Interface**
- Beautiful menu-driven interface
- Drag & drop file support
- Real-time analysis feedback
- Color-coded threat levels
- Export results to reports

### ⚡ **Command Line Power**
```bash
# Analyze single file
python file_analyzer_interactive.py suspicious.exe

# Scan entire folder
python file_analyzer_interactive.py -d /downloads

# Recursive folder scan
python file_analyzer_interactive.py -d /downloads -r

# Export report
python file_analyzer_interactive.py -d /downloads -o report.txt

# Quiet mode (only suspicious files)
python file_analyzer_interactive.py -d /downloads -q
```

### 🔍 **Comprehensive Detection**

**60+ File Type Signatures:**
- **Executables:** Windows PE, Linux ELF, macOS Mach-O
- **Archives:** ZIP, RAR, 7z, Gzip, Bzip2
- **Images:** JPEG, PNG, GIF, BMP, TIFF, WebP, ICO
- **Documents:** PDF, RTF, MS Office (old & new)
- **Media:** MP3, MP4, AVI, WAV, OGG, FLAC
- **Scripts:** Python, Shell, Bash
- **Databases:** SQLite
- **And more...**

### 🎯 **Smart Threat Detection**

The tool automatically classifies findings:

**✅ Safe** - Extension matches actual file type
```
✓ document.pdf
  Detected Type: PDF Document
  Status: SAFE
```

**⚠️ Type Mismatch** - Extension doesn't match (investigate)
```
⚠️ archive.exe
  Detected Type: ZIP Archive
  Status: TYPE MISMATCH
```

**🚨 Suspicious** - Executable disguised as benign file
```
🚨 vacation_photo.jpg
  Detected Type: PE32 Executable
  Status: SUSPICIOUS - DO NOT OPEN!
```

---

## 📖 Usage

### Interactive Mode (Recommended)

```bash
python file_analyzer_interactive.py
```

**Menu Options:**
1. **Analyze a single file** - Drag & drop or enter path
2. **Analyze multiple files** - Batch processing
3. **Analyze all files in a folder** - Scan directory
4. **View recent results** - Review previous scans
5. **Export results to file** - Generate reports
6. **View signature database** - See all 60+ signatures
7. **Clear results** - Reset session
8. **Exit**

### Command Line Mode (Advanced)

```bash
# Basic syntax
python file_analyzer_interactive.py [OPTIONS] [FILES]

# Examples
python file_analyzer_interactive.py file.exe                    # Single file
python file_analyzer_interactive.py file1.jpg file2.pdf         # Multiple files
python file_analyzer_interactive.py -d /path/to/folder          # Scan folder
python file_analyzer_interactive.py -d /folder -r               # Recursive scan
python file_analyzer_interactive.py -d /folder -o report.txt    # Save report
python file_analyzer_interactive.py -d /folder -q               # Quiet mode
```

**Command Line Options:**
- `-d, --directory PATH` - Analyze all files in directory
- `-r, --recursive` - Include subdirectories
- `-o, --output FILE` - Export results to file
- `-q, --quiet` - Only show suspicious files
- `-h, --help` - Show help message

---

## 💻 Examples

### Example 1: Check Suspicious Email Attachment

**Scenario:** You received "invoice.pdf" via email. Is it really a PDF?

```bash
python file_analyzer_interactive.py invoice.pdf
```

**Output:**
```
🚨 SUSPICIOUS - invoice.pdf: PE32 Executable
```

**Result:** The file claiming to be a PDF is actually a Windows executable. **Delete immediately!**

---

### Example 2: Scan Downloads Folder

**Scenario:** Weekly security audit of your Downloads folder

```bash
python file_analyzer_interactive.py -d C:\Users\YourName\Downloads -r -o weekly_scan.txt
```

**Output:**
```
🔍 Found 47 files. Analyzing...

[1/47] document.pdf... ✓
[2/47] photo.jpg... ✓
[3/47] game_installer.exe... ✓
[4/47] crack.exe... 🚨
[5/47] vacation.jpg... 🚨
...

ANALYSIS SUMMARY
Total Files Analyzed:  47
✓ Safe Files:          43
⚠️ Type Mismatches:     2
🚨 Suspicious Files:    2

🚨 WARNING: Suspicious files detected!

Suspicious Files:
  • crack.exe (PE32 Executable disguised as .jpg)
  • vacation.jpg (PE32 Executable)
```

**Result:** Report saved to `weekly_scan.txt` with full details.

---

### Example 3: Verify USB Drive Files

**Scenario:** Before opening files from a USB drive (common malware vector)

```bash
python file_analyzer_interactive.py -d E:\ -r
```

Interactive menu guides you through the process, flagging any suspicious files.

---

### Example 4: Batch Check Multiple Files

**Scenario:** You have several files to verify

**Interactive Mode:**
```bash
python file_analyzer_interactive.py
# Choose option 2
# Drag & drop files one by one
# Press Enter twice when done
```

**Command Line Mode:**
```bash
python file_analyzer_interactive.py file1.exe file2.pdf file3.jpg file4.zip
```

Both show individual results for each file.

---

## 🛠️ How It Works

### Magic Numbers Explained

Every file format has a unique "signature" at the beginning of the file called a **magic number**:

| File Type | Magic Bytes (Hex) | ASCII |
|-----------|-------------------|-------|
| Windows EXE | `4D 5A` | MZ |
| PDF | `25 50 44 46` | %PDF |
| PNG | `89 50 4E 47 0D 0A 1A 0A` | .PNG |
| JPEG | `FF D8 FF` | (binary) |
| ZIP | `50 4B 03 04` | PK.. |

### Detection Process

1. **Read file header** (first 8KB of file)
2. **Compare against database** (60+ known signatures)
3. **Match magic bytes** to identify actual type
4. **Compare with extension** to detect mismatches
5. **Classify threat level** (Safe/Mismatch/Suspicious)
6. **Report findings** to user

### Why This Matters

**Operating systems trust the extension:**
```
photo.jpg → Opens in image viewer (trusted)
```

**But if the actual content is executable:**
```
photo.jpg (actually malware.exe) → Runs malicious code!
```

**This tool prevents that by revealing the truth.**

---

## 🎓 Technical Details

### File Signature Database

**Executables (High Risk):**
- PE32/PE64 (Windows .exe, .dll, .sys)
- ELF (Linux/Unix executables)
- Mach-O (macOS executables)
- Java Class files

**Archives (Can Hide Malware):**
- ZIP (also used by .docx, .xlsx, .jar, .apk)
- RAR, 7z, Gzip, Bzip2

**Images (Common Disguise):**
- JPEG, PNG, GIF, BMP, TIFF, WebP, ICO

**Documents (Trusted Extensions):**
- PDF, RTF, MS Office (OLE format)

**Media Files:**
- MP3, MP4, AVI, WAV, OGG, FLAC

**Scripts (Dangerous):**
- Python, Shell, Bash (with shebang)

**Databases:**
- SQLite

### Threat Classification Logic

```python
if detected_type == "Executable" and extension in [".jpg", ".pdf", ".txt"]:
    status = "SUSPICIOUS"  # Critical threat
    
elif detected_type != expected_type:
    status = "MISMATCH"    # Investigate
    
else:
    status = "SAFE"        # All good
```

### Code Architecture

```
file_type_identifier.py
├── FileSignature (dataclass)
├── MagicNumberDatabase
│   └── 60+ file signatures
├── FileTypeAnalyzer
│   ├── read_file_header()
│   ├── analyze_file()
│   └── generate_report()

file_analyzer_interactive.py
├── InteractiveAnalyzer
│   ├── Interactive menu system
│   ├── Command line interface
│   ├── Batch processing
│   └── Report generation
```

---

## 📊 Project Files

```
file-type-identifier/
├── file_type_identifier.py          # Core analyzer (340 lines)
├── file_analyzer_interactive.py     # Terminal interface (550+ lines)
├── README.md                         # This file
├── TERMINAL_USAGE_GUIDE.md          # Detailed usage guide
└── MAGIC_NUMBERS_REFERENCE.md       # Magic numbers reference
```

**Total Lines of Code:** 900+  
**External Dependencies:** 0  
**Supported Platforms:** Windows, Linux, macOS

---

## 🔧 Advanced Features

### Create Desktop Shortcut (Windows)

1. Right-click Desktop → New → Shortcut
2. Location:
   ```
   C:\Program Files\Python311\python.exe "C:\path\to\file_analyzer_interactive.py"
   ```
3. Name it "File Type Analyzer"
4. Double-click to run anytime!

### Add to Windows Right-Click Menu

Create `analyze.reg`:
```reg
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\*\shell\AnalyzeFile]
@="Analyze File Type"

[HKEY_CLASSES_ROOT\*\shell\AnalyzeFile\command]
@="\"C:\\Python311\\python.exe\" \"C:\\path\\to\\file_analyzer_interactive.py\" \"%1\""
```

Double-click to install. Now right-click any file → "Analyze File Type"

### Automate Daily Scans

**Windows (Task Scheduler):**
Create `daily_scan.bat`:
```batch
@echo off
python C:\Tools\file_analyzer_interactive.py -d C:\Users\%USERNAME%\Downloads -r -q -o C:\Reports\daily_%date:~-4,4%%date:~-10,2%%date:~-7,2%.txt
```

Schedule in Task Scheduler to run daily.

**Linux/Mac (Cron):**
```bash
# Add to crontab
0 9 * * * python3 /path/to/file_analyzer_interactive.py -d ~/Downloads -r -q -o ~/reports/daily_$(date +\%Y\%m\%d).txt
```

---

## 🎯 Use Cases

### 1. **Personal Security**
- Verify email attachments before opening
- Scan downloads folder weekly
- Check files before running them
- Audit USB drives

### 2. **IT Security Teams**
- Initial malware triage
- File upload validation
- Incident response
- User education

### 3. **Digital Forensics**
- File type verification
- Malware analysis
- Evidence collection
- Attack vector identification

### 4. **SOC Operations**
- Automated file scanning
- Integration with SIEM
- Threat detection pipeline
- Security monitoring

### 5. **Compliance**
- File upload validation
- Security awareness training
- Audit trail generation
- Policy enforcement

---

## 🚨 Real-World Attack Examples

### Attack 1: Phishing Email
```
Email: "Please review this invoice immediately"
Attachment: invoice.pdf (actually malware.exe)

Detection: 🚨 SUSPICIOUS
Action: Delete email, report to security team
```

### Attack 2: USB Drop Attack
```
USB stick left in parking lot with files:
- confidential_data.xlsx (actually backdoor.exe)
- company_photos.jpg (actually keylogger.exe)

Detection: 🚨 SUSPICIOUS on both files
Action: Do not plug in USB, report to security
```

### Attack 3: Software Crack
```
Downloaded from torrent site:
- photoshop_crack.exe (legitimate .exe)
- readme.txt (actually python script)

Detection: 🚨 SUSPICIOUS on readme.txt
Action: Delete all files, scan system for malware
```

---

## 📚 Documentation

### Included Documentation

- **README.md** - This file (project overview)
- **TERMINAL_USAGE_GUIDE.md** - Complete usage guide with examples
- **MAGIC_NUMBERS_REFERENCE.md** - Reference guide to file signatures

### Additional Resources

- **Magic Number Database:** https://www.garykessler.net/library/file_sigs.html
- **File Format Specifications:** https://en.wikipedia.org/wiki/List_of_file_signatures
- **PE Format:** https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- **ELF Format:** https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

---

## 🎓 Educational Value

### Skills Demonstrated

**Technical Skills:**
- Binary file analysis
- Pattern matching algorithms
- File system operations
- Command-line interface design
- Data structures (dataclasses, lists, dicts)
- Error handling and validation

**Cybersecurity Skills:**
- Malware detection techniques
- File signature analysis
- Threat classification
- Attack vector understanding
- Digital forensics basics

**Software Engineering:**
- Modular code architecture
- User interface design (CLI)
- Comprehensive documentation
- Testing and validation
- Cross-platform compatibility

### Learning Outcomes

After using/studying this project, you'll understand:
- How files are structured at the binary level
- How operating systems identify file types
- How malware evades detection through renaming
- How to implement a signature-based detection system
- How to build professional command-line tools

---

## 🤝 Contributing

This is an educational project. Suggestions for improvement:

1. **Add more file signatures** - Expand the database
2. **Deep file analysis** - Scan beyond headers
3. **GUI interface** - Desktop application
4. **API integration** - VirusTotal, etc.
5. **Performance optimization** - Multi-threading
6. **Machine learning** - Pattern detection
7. **Report formats** - HTML, CSV, JSON

---

## ⚠️ Limitations

**What This Tool Does:**
- ✅ Identifies file types by magic numbers
- ✅ Detects extension mismatches
- ✅ Flags suspicious disguises
- ✅ Provides initial triage

**What This Tool Does NOT Do:**
- ❌ Scan for viruses (use antivirus)
- ❌ Detect polymorphic malware
- ❌ Analyze file contents deeply
- ❌ Remove or clean malware
- ❌ Replace professional AV software

**Use in combination with:**
- Antivirus software
- Firewall protection
- Email filtering
- Safe browsing practices
- Security awareness training

---

## 📄 License

This project is for **educational purposes only**.

**Permitted Uses:**
- Personal file verification
- Security research and learning
- Educational demonstrations
- Portfolio projects

**Disclaimer:**
- This tool does not guarantee complete malware detection
- Always use professional antivirus software
- Exercise caution with suspicious files
- The author is not responsible for misuse

---

## 🙏 Acknowledgments

- File signature database based on public resources
- Inspired by real-world malware analysis needs
- Built for cybersecurity education and awareness

---

## 📞 Support

### Getting Help

1. **Read the documentation** - Check TERMINAL_USAGE_GUIDE.md
2. **Check examples** - See the Examples section above
3. **Review magic numbers** - See MAGIC_NUMBERS_REFERENCE.md
4. **Test with known files** - Verify tool behavior

### Reporting Issues

If you find a file that's incorrectly identified:
- Note the file type and extension
- Check the magic numbers manually
- Consider if it's a new file format
- Suggest adding it to the database

---

<div align="center">

## 🎯 Remember

**Your best defense against malware is not trusting file extensions.**

**Always verify before you open.**

---

**Built with 🔒 security in mind**

*File Type Identifier - Because extensions lie, but magic numbers don't.*

</div>
