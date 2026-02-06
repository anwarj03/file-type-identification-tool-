#!/usr/bin/env python3
"""
Test file generator for File Type Identifier
Creates legitimate files and malicious mismatches for testing
"""

import os
from pathlib import Path


def create_test_files():
    """Create test files with various magic numbers and extensions"""
    
    test_dir = Path("test_files")
    test_dir.mkdir(exist_ok=True)
    
    print("Creating test files...")
    
    # 1. Legitimate files (correct extension)
    # PNG image
    png_header = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    with open(test_dir / "legitimate_image.png", 'wb') as f:
        f.write(png_header)
    print("✓ Created legitimate PNG image")
    
    # JPEG image
    jpeg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF' + b'\x00' * 100
    with open(test_dir / "legitimate_photo.jpg", 'wb') as f:
        f.write(jpeg_header)
    print("✓ Created legitimate JPEG image")
    
    # PDF document
    pdf_header = b'%PDF-1.4\n' + b'Sample PDF content' + b'\x00' * 100
    with open(test_dir / "legitimate_document.pdf", 'wb') as f:
        f.write(pdf_header)
    print("✓ Created legitimate PDF document")
    
    # ZIP archive
    zip_header = b'PK\x03\x04' + b'\x00' * 100
    with open(test_dir / "legitimate_archive.zip", 'wb') as f:
        f.write(zip_header)
    print("✓ Created legitimate ZIP archive")
    
    # 2. Suspicious files (MALWARE SIMULATION - executables with wrong extensions)
    # Windows PE executable disguised as JPEG
    pe_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff' + b'\x00' * 100
    with open(test_dir / "malware.jpg", 'wb') as f:
        f.write(pe_header)
    print("⚠️  Created SUSPICIOUS: Windows executable disguised as JPG")
    
    # Windows PE executable disguised as PNG
    with open(test_dir / "trojan.png", 'wb') as f:
        f.write(pe_header)
    print("⚠️  Created SUSPICIOUS: Windows executable disguised as PNG")
    
    # ELF executable disguised as PDF
    elf_header = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100
    with open(test_dir / "backdoor.pdf", 'wb') as f:
        f.write(elf_header)
    print("⚠️  Created SUSPICIOUS: Linux executable disguised as PDF")
    
    # 3. Benign mismatches (not necessarily malicious)
    # Office document with .zip extension (DOCX files are ZIP archives)
    with open(test_dir / "document.zip", 'wb') as f:
        f.write(zip_header)
    print("ℹ️  Created MISMATCH: ZIP file (could be DOCX/XLSX)")
    
    # Text file with wrong extension
    text_content = b'This is a plain text file\n' * 10
    with open(test_dir / "readme.dat", 'wb') as f:
        f.write(text_content)
    print("ℹ️  Created MISMATCH: Text file with .dat extension")
    
    # 4. Python script disguised as text file
    python_script = b'#!/usr/bin/python\nimport os\nprint("Hello")\n'
    with open(test_dir / "script.txt", 'wb') as f:
        f.write(python_script)
    print("⚠️  Created SUSPICIOUS: Python script disguised as TXT")
    
    print(f"\n✅ Test files created in: {test_dir.absolute()}")
    print(f"   Total files: {len(list(test_dir.glob('*')))}")
    
    return test_dir


if __name__ == '__main__':
    test_dir = create_test_files()
    print(f"\nRun the analyzer with:")
    print(f"  python file_type_identifier.py {test_dir}")
