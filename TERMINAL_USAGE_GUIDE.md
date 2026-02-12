# File Type Identifier - Terminal Interface

## 🎯 No Web Interface - Just Terminal!

This version runs directly in your terminal/command prompt. No web browser needed!

## 🚀 Two Ways to Use It

### Method 1: Interactive Menu (Easiest)

```bash
python file_analyzer_interactive.py
```

You'll see a menu:
```
╔═══════════════════════════════════════════════════════════╗
║       File Type Identifier - Terminal Interface          ║
║        Detect malware disguised with fake extensions      ║
╚═══════════════════════════════════════════════════════════╝

MAIN MENU
============================================================
1. Analyze a single file
2. Analyze multiple files
3. Analyze all files in a folder
4. View recent results
5. Export results to file
6. View signature database
7. Clear results
8. Exit
============================================================
```

**Just type a number and press Enter!**

### Method 2: Command Line (Advanced)

```bash
# Analyze single file
python file_analyzer_interactive.py myfile.jpg

# Analyze multiple files
python file_analyzer_interactive.py file1.exe file2.pdf file3.jpg

# Analyze entire folder
python file_analyzer_interactive.py -d /path/to/folder

# Analyze folder + subfolders
python file_analyzer_interactive.py -d /path/to/folder -r

# Save results to file
python file_analyzer_interactive.py file.exe -o report.txt

# Quiet mode (only show suspicious files)
python file_analyzer_interactive.py -d Downloads -q
```

---

## 📋 Step-by-Step Examples

### Example 1: Analyze a Suspicious File

1. Run the program:
   ```bash
   python file_analyzer_interactive.py
   ```

2. Choose option `1` (Analyze single file)

3. Enter file path or **drag & drop the file** into terminal:
   ```
   Enter file path: C:\Users\HP\Downloads\suspicious.jpg
   ```
   Or just drag the file from Windows Explorer!

4. See instant results:
   ```
   ──────────────────────────────────────────────────────────
   🚨 suspicious.jpg
   ──────────────────────────────────────────────────────────
   Claimed Extension:  .jpg
   Detected Type:      PE32 Executable
   Expected Extension: .exe
   File Size:          2.45 MB
   
   🚨 VERDICT: SUSPICIOUS - Potential malware detected!
      This file appears to be an executable disguised with a fake extension.
      ⚠️  DO NOT OPEN THIS FILE!
   ```

### Example 2: Scan Downloads Folder

1. Run program, choose option `3`

2. Enter your Downloads folder path:
   ```
   C:\Users\HP\Downloads
   ```

3. Choose to scan subfolders: `n`

4. Watch it scan:
   ```
   🔍 Found 15 files. Analyzing...
   
   [1/15] document.pdf... ✓
   [2/15] photo.jpg... ✓
   [3/15] invoice.pdf... 🚨
   [4/15] game.exe... ✓
   ...
   ```

5. See summary:
   ```
   ANALYSIS SUMMARY
   ============================================================
   Total Files Analyzed:  15
   ✓ Safe Files:          12
   ⚠️  Type Mismatches:     2
   🚨 Suspicious Files:    1
   
   🚨 WARNING: Suspicious files detected!
   
   Suspicious Files:
     • invoice.pdf (PE32 Executable)
   ```

### Example 3: Batch Check Email Attachments

1. Save all email attachments to a folder

2. Run program, choose option `2` (Analyze multiple files)

3. Enter each file path (or drag & drop):
   ```
   Enter file paths (one per line, press Enter twice when done):
   File 1: C:\Temp\attachment1.pdf
     ✓ Added: attachment1.pdf
   File 2: C:\Temp\invoice.docx
     ✓ Added: invoice.docx
   File 3: [press Enter to finish]
   ```

4. See results for all files

5. Export report when asked

### Example 4: Quick Command Line Check

From terminal directly:

```bash
# Quick check of one file
python file_analyzer_interactive.py "C:\Users\HP\Desktop\suspicious.exe"
```

Output:
```
✓ SAFE - suspicious.exe: PE32 Executable
```

Or if malicious:
```
🚨 SUSPICIOUS - photo.jpg: PE32 Executable
```

---

## 💡 Tips & Tricks

### Windows: Drag & Drop Files

1. Open Command Prompt or PowerShell
2. Type: `python file_analyzer_interactive.py`
3. Press Enter, choose option 1
4. **Drag the file from Windows Explorer into the terminal**
5. Press Enter - done!

### Scan Multiple Files Fast

**Command line is faster for multiple files:**

```bash
# Windows
python file_analyzer_interactive.py *.exe *.dll

# Linux/Mac
python file_analyzer_interactive.py /downloads/*
```

### Create Desktop Shortcut (Windows)

1. Right-click on Desktop → New → Shortcut
2. Location: 
   ```
   C:\Program Files\Python311\python.exe "C:\path\to\file_analyzer_interactive.py"
   ```
3. Name it: "File Type Analyzer"
4. Double-click to run!

### Add to Right-Click Menu (Windows)

Create file: `analyze.reg`
```reg
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\*\shell\AnalyzeFile]
@="Analyze File Type"

[HKEY_CLASSES_ROOT\*\shell\AnalyzeFile\command]
@="\"C:\\Program Files\\Python311\\python.exe\" \"C:\\path\\to\\file_analyzer_interactive.py\" \"%1\""
```

Double-click to install. Now you can right-click any file → "Analyze File Type"!

---

## 📊 Understanding Results

### Safe File ✓
```
✓ document.pdf
Claimed Extension:  .pdf
Detected Type:      PDF Document
Expected Extension: .pdf

✓ VERDICT: SAFE
  File extension matches the detected type.
```
**Action:** File is what it claims to be. Safe to open.

### Type Mismatch ⚠️
```
⚠️ archive.exe
Claimed Extension:  .exe
Detected Type:      ZIP Archive
Expected Extension: .zip

⚠️ VERDICT: TYPE MISMATCH
   File extension doesn't match the actual file type.
   This may be intentional or indicate a problem.
```
**Action:** Investigate why the extension is wrong. May be benign (renamed file) or suspicious.

### Suspicious File 🚨
```
🚨 vacation_photo.jpg
Claimed Extension:  .jpg
Detected Type:      PE32 Executable
Expected Extension: .exe

🚨 VERDICT: SUSPICIOUS - Potential malware detected!
   This file appears to be an executable disguised with a fake extension.
   ⚠️  DO NOT OPEN THIS FILE!
```
**Action:** DO NOT OPEN! This is likely malware. Delete or quarantine immediately.

---

## 🛠️ Command Line Reference

### Basic Usage
```bash
python file_analyzer_interactive.py [OPTIONS] [FILES]
```

### Options
```
-d, --directory PATH    Analyze all files in directory
-r, --recursive         Include subdirectories
-o, --output FILE       Export results to file
-q, --quiet            Only show suspicious files
-h, --help             Show help message
```

### Examples
```bash
# Interactive mode
python file_analyzer_interactive.py

# Single file
python file_analyzer_interactive.py suspicious.exe

# Multiple files
python file_analyzer_interactive.py file1.jpg file2.pdf file3.exe

# Folder (non-recursive)
python file_analyzer_interactive.py -d C:\Downloads

# Folder + subfolders
python file_analyzer_interactive.py -d C:\Downloads -r

# Export to CSV
python file_analyzer_interactive.py -d C:\Downloads -o results.csv

# Quiet mode (only suspicious)
python file_analyzer_interactive.py -d C:\Downloads -q

# Combine options
python file_analyzer_interactive.py -d C:\Downloads -r -o report.txt -q
```

---

## 📁 File Management

### Where Results Are Saved

When you export results, they're saved in the current directory:
```
analysis_report_20240205_143022.txt
```

### Sample Report Format

```
============================================================
FILE TYPE ANALYSIS REPORT
============================================================
Generated: 2024-02-05 14:30:22
Total Files: 15
============================================================

SUMMARY
------------------------------------------------------------
Safe Files:        12
Type Mismatches:   2
Suspicious Files:  1

DETAILED RESULTS
============================================================

1. document.pdf
   Status: SAFE
   Claimed Extension: .pdf
   Detected Type: PDF Document
   Expected Extension: .pdf
   File Size: 245.67 KB

2. invoice.pdf
   Status: SUSPICIOUS
   Claimed Extension: .pdf
   Detected Type: PE32 Executable
   Expected Extension: .exe
   File Size: 2.45 MB
   Description: Windows PE executable
```

---

## 🚨 Common Use Cases

### 1. Email Attachment Verification
```bash
# Save all attachments to a folder, then:
python file_analyzer_interactive.py -d C:\Temp\Attachments
```

### 2. USB Drive Scan
```bash
# Before opening files from USB:
python file_analyzer_interactive.py -d E:\ -r
```

### 3. Downloads Folder Audit
```bash
# Weekly scan of downloads:
python file_analyzer_interactive.py -d %USERPROFILE%\Downloads -o weekly_scan.txt
```

### 4. Quick Single File Check
```bash
# Drag & drop file onto terminal:
python file_analyzer_interactive.py "dragged_file.exe"
```

### 5. Automated Scanning (Windows Task Scheduler)
Create batch file: `daily_scan.bat`
```batch
@echo off
cd C:\FileAnalyzer
python file_analyzer_interactive.py -d C:\Users\HP\Downloads -r -o daily_scan_%date:~-4,4%%date:~-10,2%%date:~-7,2%.txt -q
```

Schedule to run daily.

---

## 💻 System Requirements

- Python 3.8 or higher
- Windows, Linux, or macOS
- No additional packages needed!
- Works completely offline

---

## ✅ Quick Start Checklist

- [ ] Download `file_type_identifier.py` (core analyzer)
- [ ] Download `file_analyzer_interactive.py` (terminal interface)
- [ ] Put both files in same folder
- [ ] Open terminal in that folder
- [ ] Run: `python file_analyzer_interactive.py`
- [ ] Choose option 1 and drag a file to test!

---

**That's it! No web server, no installation, just pure terminal power!** 🚀
