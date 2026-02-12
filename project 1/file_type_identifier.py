#!/usr/bin/env python3
"""
File Type Identifier - Magic Number Analysis Tool
Detects file type mismatches by analyzing file headers (magic numbers)
Useful for malware analysis and forensics
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class FileSignature:
    """Represents a file type signature"""
    file_type: str
    extensions: List[str]
    magic_bytes: bytes
    offset: int = 0  # Offset from start of file where magic bytes appear
    description: str = ""


class MagicNumberDatabase:
    """Database of known file signatures"""
    
    def __init__(self):
        self.signatures = self._build_signature_database()
    
    def _build_signature_database(self) -> List[FileSignature]:
        """Build comprehensive database of file signatures"""
        return [
            # Executables
            FileSignature("PE32 Executable", [".exe", ".dll", ".sys"], b"MZ", 0, "Windows PE executable"),
            FileSignature("ELF Executable", [".elf", ".so"], b"\x7fELF", 0, "Linux/Unix executable"),
            FileSignature("Mach-O Executable", [".o", ".dylib"], b"\xfe\xed\xfa\xce", 0, "macOS executable (32-bit)"),
            FileSignature("Mach-O Executable", [".o", ".dylib"], b"\xfe\xed\xfa\xcf", 0, "macOS executable (64-bit)"),
            
            # Archives
            FileSignature("ZIP Archive", [".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx"], b"PK\x03\x04", 0, "ZIP compressed archive"),
            FileSignature("ZIP Archive (empty)", [".zip"], b"PK\x05\x06", 0, "Empty ZIP archive"),
            FileSignature("RAR Archive", [".rar"], b"Rar!\x1a\x07", 0, "RAR compressed archive"),
            FileSignature("7-Zip Archive", [".7z"], b"7z\xbc\xaf\x27\x1c", 0, "7-Zip compressed archive"),
            FileSignature("Gzip Archive", [".gz", ".tar.gz"], b"\x1f\x8b", 0, "Gzip compressed file"),
            FileSignature("Bzip2 Archive", [".bz2"], b"BZh", 0, "Bzip2 compressed file"),
            
            # Images
            FileSignature("JPEG Image", [".jpg", ".jpeg"], b"\xff\xd8\xff", 0, "JPEG image"),
            FileSignature("PNG Image", [".png"], b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
            FileSignature("GIF Image", [".gif"], b"GIF87a", 0, "GIF image (87a)"),
            FileSignature("GIF Image", [".gif"], b"GIF89a", 0, "GIF image (89a)"),
            FileSignature("BMP Image", [".bmp"], b"BM", 0, "Windows Bitmap image"),
            FileSignature("TIFF Image", [".tif", ".tiff"], b"II\x2a\x00", 0, "TIFF image (little-endian)"),
            FileSignature("TIFF Image", [".tif", ".tiff"], b"MM\x00\x2a", 0, "TIFF image (big-endian)"),
            FileSignature("ICO Image", [".ico"], b"\x00\x00\x01\x00", 0, "Windows icon file"),
            FileSignature("WebP Image", [".webp"], b"RIFF", 0, "WebP image"),
            
            # Documents
            FileSignature("PDF Document", [".pdf"], b"%PDF", 0, "Adobe PDF document"),
            FileSignature("RTF Document", [".rtf"], b"{\\rtf", 0, "Rich Text Format document"),
            FileSignature("MS Office Document", [".doc", ".xls", ".ppt"], b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "Microsoft Office document (OLE)"),
            
            # Media
            FileSignature("MP3 Audio", [".mp3"], b"ID3", 0, "MP3 audio with ID3v2 tag"),
            FileSignature("MP3 Audio", [".mp3"], b"\xff\xfb", 0, "MP3 audio (MPEG-1 Layer 3)"),
            FileSignature("MP4 Video", [".mp4", ".m4v"], b"\x00\x00\x00\x18ftypmp4", 0, "MP4 video"),
            FileSignature("AVI Video", [".avi"], b"RIFF", 0, "AVI video"),
            FileSignature("WAV Audio", [".wav"], b"RIFF", 0, "WAV audio"),
            FileSignature("OGG Audio", [".ogg"], b"OggS", 0, "Ogg Vorbis audio"),
            FileSignature("FLAC Audio", [".flac"], b"fLaC", 0, "FLAC audio"),
            
            # Scripts and Code
            FileSignature("Python Script", [".py"], b"#!/usr/bin/python", 0, "Python script with shebang"),
            FileSignature("Shell Script", [".sh"], b"#!/bin/sh", 0, "Shell script with shebang"),
            FileSignature("Bash Script", [".sh"], b"#!/bin/bash", 0, "Bash script with shebang"),
            
            # Other
            FileSignature("SQLite Database", [".db", ".sqlite", ".sqlite3"], b"SQLite format 3\x00", 0, "SQLite 3 database"),
            FileSignature("Java Class", [".class"], b"\xca\xfe\xba\xbe", 0, "Java compiled class file"),
            FileSignature("ISO Image", [".iso"], b"CD001", 0x8001, "ISO 9660 CD/DVD image"),
            FileSignature("VMDK Image", [".vmdk"], b"# Disk DescriptorFile", 0, "VMware disk image"),
        ]
    
    def identify(self, file_header: bytes, offset_limit: int = 8192) -> Optional[FileSignature]:
        """
        Identify file type based on magic bytes
        
        Args:
            file_header: First bytes of the file
            offset_limit: Maximum offset to check for signatures
            
        Returns:
            FileSignature if match found, None otherwise
        """
        for signature in self.signatures:
            # Only check signatures within the offset limit
            if signature.offset > offset_limit:
                continue
                
            # Check if we have enough bytes
            end_pos = signature.offset + len(signature.magic_bytes)
            if len(file_header) < end_pos:
                continue
            
            # Extract the relevant bytes and compare
            file_bytes = file_header[signature.offset:end_pos]
            if file_bytes == signature.magic_bytes:
                return signature
        
        return None


class FileTypeAnalyzer:
    """Analyzes files and detects type mismatches"""
    
    def __init__(self):
        self.db = MagicNumberDatabase()
        self.header_size = 8192  # Read first 8KB for analysis
    
    def read_file_header(self, filepath: Path) -> Optional[bytes]:
        """Read file header for analysis"""
        try:
            with open(filepath, 'rb') as f:
                return f.read(self.header_size)
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return None
    
    def get_file_extension(self, filepath: Path) -> str:
        """Get file extension in lowercase"""
        return filepath.suffix.lower()
    
    def analyze_file(self, filepath: Path) -> Dict:
        """
        Analyze a single file for type mismatch
        
        Returns:
            Dictionary with analysis results
        """
        result = {
            'filepath': str(filepath),
            'filename': filepath.name,
            'claimed_extension': self.get_file_extension(filepath),
            'file_size': filepath.stat().st_size if filepath.exists() else 0,
            'detected_type': None,
            'detected_extension': None,
            'mismatch': False,
            'suspicious': False,
            'description': '',
            'timestamp': datetime.now().isoformat()
        }
        
        # Read file header
        header = self.read_file_header(filepath)
        if header is None:
            result['error'] = 'Could not read file'
            return result
        
        # Identify actual file type
        signature = self.db.identify(header)
        
        if signature:
            result['detected_type'] = signature.file_type
            result['detected_extension'] = signature.extensions[0] if signature.extensions else None
            result['description'] = signature.description
            
            # Check for mismatch
            claimed_ext = result['claimed_extension']
            if claimed_ext and claimed_ext not in signature.extensions:
                result['mismatch'] = True
                result['suspicious'] = self._is_suspicious_mismatch(signature, claimed_ext)
        else:
            result['detected_type'] = 'Unknown'
            result['description'] = 'File type not recognized'
        
        return result
    
    def _is_suspicious_mismatch(self, signature: FileSignature, claimed_ext: str) -> bool:
        """
        Determine if a mismatch is suspicious (e.g., executable disguised as image)
        """
        dangerous_types = ['PE32 Executable', 'ELF Executable', 'Mach-O Executable']
        benign_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.txt', '.pdf', '.doc', '.docx']
        
        # Executable disguised as benign file type
        if signature.file_type in dangerous_types and claimed_ext in benign_extensions:
            return True
        
        # Script with wrong extension
        if 'Script' in signature.file_type and claimed_ext not in ['.py', '.sh', '.bash', '.ps1']:
            return True
        
        return False
    
    def scan_directory(self, directory: Path, recursive: bool = False) -> List[Dict]:
        """
        Scan directory for files and analyze them
        
        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories
            
        Returns:
            List of analysis results
        """
        results = []
        
        try:
            if recursive:
                files = directory.rglob('*')
            else:
                files = directory.glob('*')
            
            for filepath in files:
                if filepath.is_file():
                    result = self.analyze_file(filepath)
                    results.append(result)
        
        except Exception as e:
            print(f"Error scanning directory {directory}: {e}")
        
        return results
    
    def generate_report(self, results: List[Dict]) -> str:
        """Generate a formatted report of analysis results"""
        report = []
        report.append("=" * 80)
        report.append("FILE TYPE IDENTIFICATION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total files analyzed: {len(results)}")
        report.append("")
        
        # Count statistics
        mismatches = [r for r in results if r.get('mismatch')]
        suspicious = [r for r in results if r.get('suspicious')]
        
        report.append(f"Files with type mismatch: {len(mismatches)}")
        report.append(f"Suspicious files detected: {len(suspicious)}")
        report.append("")
        
        # Suspicious files first
        if suspicious:
            report.append("⚠️  SUSPICIOUS FILES (HIGH PRIORITY)")
            report.append("-" * 80)
            for result in suspicious:
                report.append(f"\nFile: {result['filename']}")
                report.append(f"  Path: {result['filepath']}")
                report.append(f"  Claimed extension: {result['claimed_extension']}")
                report.append(f"  Detected type: {result['detected_type']}")
                report.append(f"  Expected extension: {result['detected_extension']}")
                report.append(f"  Description: {result['description']}")
                report.append(f"  ⚠️  WARNING: Potentially malicious file masquerading!")
            report.append("")
        
        # Regular mismatches
        regular_mismatches = [r for r in mismatches if not r.get('suspicious')]
        if regular_mismatches:
            report.append("ℹ️  TYPE MISMATCHES (REVIEW RECOMMENDED)")
            report.append("-" * 80)
            for result in regular_mismatches:
                report.append(f"\nFile: {result['filename']}")
                report.append(f"  Path: {result['filepath']}")
                report.append(f"  Claimed extension: {result['claimed_extension']}")
                report.append(f"  Detected type: {result['detected_type']}")
                report.append(f"  Expected extension: {result['detected_extension']}")
            report.append("")
        
        # Matching files summary
        matching = [r for r in results if not r.get('mismatch') and r.get('detected_type') != 'Unknown']
        if matching:
            report.append(f"✓ {len(matching)} files have matching extensions")
            report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='File Type Identifier - Detect file type mismatches using magic numbers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s file.exe                    # Analyze single file
  %(prog)s /path/to/directory          # Analyze directory
  %(prog)s /path/to/directory -r       # Recursively scan directory
  %(prog)s /path/to/directory -o report.txt  # Save report to file
        """
    )
    
    parser.add_argument('path', help='File or directory to analyze')
    parser.add_argument('-r', '--recursive', action='store_true', 
                       help='Recursively scan subdirectories')
    parser.add_argument('-o', '--output', help='Output report to file')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Only show suspicious files')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = FileTypeAnalyzer()
    path = Path(args.path)
    
    if not path.exists():
        print(f"Error: Path '{path}' does not exist")
        sys.exit(1)
    
    # Analyze
    if path.is_file():
        results = [analyzer.analyze_file(path)]
    else:
        print(f"Scanning {'recursively' if args.recursive else 'directory'}: {path}")
        results = analyzer.scan_directory(path, args.recursive)
    
    # Generate report
    report = analyzer.generate_report(results)
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
    else:
        print(report)
    
    # Exit code based on findings
    suspicious_count = sum(1 for r in results if r.get('suspicious'))
    sys.exit(1 if suspicious_count > 0 else 0)


if __name__ == '__main__':
    main()
