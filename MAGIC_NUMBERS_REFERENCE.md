# Magic Numbers Quick Reference Guide

## What are Magic Numbers?

Magic numbers (also called file signatures) are specific byte sequences at the beginning of files that identify their format. Operating systems and applications use these to determine how to handle files, regardless of the file extension.

## Why Hackers Exploit This

**The Attack Vector:**
1. OS relies primarily on file extension for handling decisions
2. Magic numbers determine actual file type
3. Mismatch between extension and magic number = disguised malware

**Example Attack:**
```
Filename: "vacation_photo.jpg"
Extension: .jpg (looks like image)
Magic number: 4D 5A (PE executable!)
Result: User opens "image", runs malware
```

## Common Magic Numbers Reference

### Executables (High Risk When Disguised)

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **PE32** | `4D 5A` | MZ | Windows .exe, .dll, .sys |
| **ELF** | `7F 45 4C 46` | .ELF | Linux/Unix executables |
| **Mach-O (32)** | `FE ED FA CE` | - | macOS executable |
| **Mach-O (64)** | `FE ED FA CF` | - | macOS executable |
| **Java Class** | `CA FE BA BE` | - | Java bytecode |

### Archives (Can Hide Malware)

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **ZIP** | `50 4B 03 04` | PK.. | ZIP, JAR, APK, DOCX |
| **ZIP (empty)** | `50 4B 05 06` | PK.. | Empty ZIP |
| **RAR** | `52 61 72 21 1A 07` | Rar! | RAR archive |
| **7-Zip** | `37 7A BC AF 27 1C` | 7z.. | 7z archive |
| **Gzip** | `1F 8B` | - | Gzip compressed |
| **Bzip2** | `42 5A 68` | BZh | Bzip2 compressed |

### Images (Common Disguise Extensions)

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **JPEG** | `FF D8 FF` | - | JPEG image |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | .PNG | PNG image |
| **GIF 87a** | `47 49 46 38 37 61` | GIF87a | GIF image |
| **GIF 89a** | `47 49 46 38 39 61` | GIF89a | GIF image |
| **BMP** | `42 4D` | BM | Windows Bitmap |
| **TIFF (LE)** | `49 49 2A 00` | II*. | TIFF little-endian |
| **TIFF (BE)** | `4D 4D 00 2A` | MM.* | TIFF big-endian |
| **ICO** | `00 00 01 00` | - | Windows icon |
| **WebP** | `52 49 46 46` | RIFF | WebP image |

### Documents (Trusted Extensions)

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **PDF** | `25 50 44 46` | %PDF | Adobe PDF |
| **RTF** | `7B 5C 72 74 66` | {\rtf | Rich Text Format |
| **MS Office** | `D0 CF 11 E0 A1 B1 1A E1` | - | Old Office (OLE) |
| **DOCX/XLSX** | `50 4B 03 04` | PK.. | Office (actually ZIP) |

### Media Files

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **MP3 (ID3v2)** | `49 44 33` | ID3 | MP3 with ID3 tag |
| **MP3 (MPEG)** | `FF FB` | - | MP3 MPEG-1 Layer 3 |
| **MP4** | `00 00 00 18 66 74 79 70` | ...ftyp | MP4 video |
| **AVI** | `52 49 46 46` | RIFF | AVI video |
| **WAV** | `52 49 46 46` | RIFF | WAV audio |
| **OGG** | `4F 67 67 53` | OggS | Ogg Vorbis |
| **FLAC** | `66 4C 61 43` | fLaC | FLAC audio |

### Scripts (Dangerous When Disguised)

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **Python** | `23 21 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E` | #!/usr/bin/python | Python script |
| **Shell** | `23 21 2F 62 69 6E 2F 73 68` | #!/bin/sh | Shell script |
| **Bash** | `23 21 2F 62 69 6E 2F 62 61 73 68` | #!/bin/bash | Bash script |

### Databases

| Format | Magic Bytes (Hex) | ASCII | Description |
|--------|-------------------|-------|-------------|
| **SQLite 3** | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite format 3 | SQLite database |

## Detection Patterns

### High-Risk Scenarios

🚨 **CRITICAL THREATS** (Immediate action required):
```
Executable disguised as image:
  malware.jpg → Magic: 4D 5A (PE32 .exe)
  trojan.png  → Magic: 7F 45 4C 46 (ELF)

Executable disguised as document:
  invoice.pdf → Magic: 4D 5A (PE32 .exe)
  resume.doc  → Magic: 7F 45 4C 46 (ELF)

Script disguised as text:
  readme.txt  → Magic: 23 21 2F (shebang script)
```

⚠️ **MEDIUM RISK** (Review required):
```
Archive with wrong extension:
  file.exe → Magic: 50 4B 03 04 (ZIP)
  
Office document as ZIP:
  report.zip → Magic: 50 4B 03 04 (could be .docx)
```

✅ **BENIGN MISMATCHES**:
```
Office files (DOCX/XLSX/PPTX are ZIP archives):
  document.docx → Magic: 50 4B 03 04 (ZIP) ✓
  
Media files with generic extension:
  audio.dat → Magic: 49 44 33 (MP3) ℹ️
```

## Reading Magic Numbers

### Using Hexdump (Linux/Mac)
```bash
# View first 16 bytes in hex
hexdump -C file.jpg | head -n 1

# View first 32 bytes
xxd -l 32 file.jpg
```

### Using Python
```python
with open('file.jpg', 'rb') as f:
    header = f.read(16)
    print(header.hex())  # Hex representation
    print(header)        # Bytes representation
```

### Using Windows PowerShell
```powershell
# View first 16 bytes
Format-Hex file.jpg -Count 16
```

## Real-World Attack Examples

### 1. Email Attachment Attack
```
Filename: Invoice_2024.pdf
Actual type: PE32 Executable
Magic: 4D 5A
Attack: Phishing email with "invoice"
```

### 2. USB Drive Malware
```
Filename: vacation_photos.jpg
Actual type: ELF Executable
Magic: 7F 45 4C 46
Attack: Autorun malware on USB
```

### 3. Download Trojan
```
Filename: game_installer.exe
Actual type: ZIP Archive containing malware
Magic: 50 4B 03 04
Attack: Malicious installer
```

## Defensive Strategies

1. **Never trust file extensions**
   - Always verify magic numbers
   - Use this tool before opening suspicious files

2. **Scan all downloads**
   - Check magic numbers of all downloaded files
   - Use antivirus + magic number verification

3. **Email attachment rules**
   - Reject executables disguised as documents
   - Scan all attachments with multiple tools

4. **USB security**
   - Scan all USB drives before use
   - Disable autorun features

5. **User education**
   - Train users to recognize suspicious files
   - Implement "verify before open" policy

## Integration Ideas

### 1. Email Gateway
```python
# Scan all attachments
for attachment in email.attachments:
    result = analyzer.analyze_file(attachment)
    if result['suspicious']:
        quarantine_email()
```

### 2. File Upload Handler
```python
# Web application upload validation
def validate_upload(uploaded_file):
    result = analyzer.analyze_file(uploaded_file)
    if result['mismatch']:
        return "Invalid file type"
```

### 3. Directory Monitor
```python
# Real-time file system monitoring
# Alert on suspicious file creation
```

## Further Reading

- **File Signatures Database**: https://www.garykessler.net/library/file_sigs.html
- **PE Format Specification**: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- **ELF Specification**: http://www.skyfree.org/linux/references/ELF_Format.pdf
- **MIME Types**: https://www.iana.org/assignments/media-types/media-types.xhtml

---

**Remember**: File extensions are just names. Magic numbers reveal the truth.
