#!/usr/bin/env python3
"""
File Type Identifier - Interactive Terminal Interface
Import and analyze files directly from the command line
"""

import os
import sys
from pathlib import Path
from typing import List
import argparse
from datetime import datetime

# Import from the existing file_type_identifier
from file_type_identifier import FileTypeAnalyzer, MagicNumberDatabase


class InteractiveAnalyzer:
    """Interactive terminal-based file analyzer"""
    
    def __init__(self):
        self.analyzer = FileTypeAnalyzer()
        self.db = MagicNumberDatabase()
        self.results = []
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Print application banner"""
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║        File Type Identifier - Terminal Interface          ║")
        print("║        Detect malware disguised with fake extensions      ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        print()
    
    def print_menu(self):
        """Print main menu"""
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Analyze a single file")
        print("2. Analyze multiple files")
        print("3. Analyze all files in a folder")
        print("4. View recent results")
        print("5. Export results to file")
        print("6. View signature database")
        print("7. Clear results")
        print("8. Exit")
        print("="*60)
    
    def get_file_path(self) -> Path:
        """Get file path from user"""
        while True:
            filepath = input("\nEnter file path (or drag & drop file here): ").strip()
            
            # Remove quotes if user dragged file
            filepath = filepath.strip('"').strip("'")
            
            path = Path(filepath)
            if path.exists() and path.is_file():
                return path
            else:
                print(f"❌ Error: File not found: {filepath}")
                retry = input("Try again? (y/n): ").lower()
                if retry != 'y':
                    return None
    
    def get_multiple_files(self) -> List[Path]:
        """Get multiple file paths from user"""
        print("\nEnter file paths (one per line, press Enter twice when done):")
        print("Tip: You can drag & drop files into the terminal")
        
        files = []
        while True:
            filepath = input(f"File {len(files) + 1}: ").strip()
            
            if not filepath:
                if files:
                    break
                else:
                    print("No files entered. Please enter at least one file.")
                    continue
            
            # Remove quotes
            filepath = filepath.strip('"').strip("'")
            path = Path(filepath)
            
            if path.exists() and path.is_file():
                files.append(path)
                print(f"  ✓ Added: {path.name}")
            else:
                print(f"  ❌ File not found: {filepath}")
        
        return files
    
    def get_directory_path(self) -> Path:
        """Get directory path from user"""
        while True:
            dirpath = input("\nEnter folder path: ").strip()
            dirpath = dirpath.strip('"').strip("'")
            
            path = Path(dirpath)
            if path.exists() and path.is_dir():
                return path
            else:
                print(f"❌ Error: Folder not found: {dirpath}")
                retry = input("Try again? (y/n): ").lower()
                if retry != 'y':
                    return None
    
    def print_result(self, result: dict, detailed: bool = True):
        """Print analysis result"""
        print("\n" + "─"*60)
        
        # Filename with status emoji
        status = "🚨" if result.get('suspicious') else "⚠️" if result.get('mismatch') else "✓"
        print(f"{status} {result['filename']}")
        print("─"*60)
        
        # Basic info
        print(f"Claimed Extension:  {result['claimed_extension'] or 'None'}")
        print(f"Detected Type:      {result['detected_type'] or 'Unknown'}")
        print(f"Expected Extension: {result['detected_extension'] or 'N/A'}")
        print(f"File Size:          {self.format_size(result['file_size'])}")
        
        if detailed and result.get('description'):
            print(f"Description:        {result['description']}")
        
        # Verdict
        print()
        if result.get('suspicious'):
            print("🚨 VERDICT: SUSPICIOUS - Potential malware detected!")
            print("   This file appears to be an executable disguised with a fake extension.")
            print("   ⚠️  DO NOT OPEN THIS FILE!")
        elif result.get('mismatch'):
            print("⚠️  VERDICT: TYPE MISMATCH")
            print("   File extension doesn't match the actual file type.")
            print("   This may be intentional or indicate a problem.")
        else:
            print("✓ VERDICT: SAFE")
            print("  File extension matches the detected type.")
    
    def print_summary(self, results: List[dict]):
        """Print summary of multiple results"""
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        
        total = len(results)
        suspicious = sum(1 for r in results if r.get('suspicious'))
        mismatches = sum(1 for r in results if r.get('mismatch'))
        safe = total - mismatches
        
        print(f"Total Files Analyzed:  {total}")
        print(f"✓ Safe Files:          {safe}")
        print(f"⚠️  Type Mismatches:     {mismatches}")
        print(f"🚨 Suspicious Files:    {suspicious}")
        
        if suspicious > 0:
            print("\n🚨 WARNING: Suspicious files detected!")
            print("\nSuspicious Files:")
            for r in results:
                if r.get('suspicious'):
                    print(f"  • {r['filename']} ({r['detected_type']})")
    
    def format_size(self, bytes: int) -> str:
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes < 1024.0:
                return f"{bytes:.2f} {unit}"
            bytes /= 1024.0
        return f"{bytes:.2f} TB"
    
    def analyze_single_file(self):
        """Analyze a single file"""
        self.clear_screen()
        self.print_banner()
        print("ANALYZE SINGLE FILE")
        print("="*60)
        
        filepath = self.get_file_path()
        if not filepath:
            return
        
        print(f"\n🔍 Analyzing: {filepath.name}...")
        result = self.analyzer.analyze_file(filepath)
        self.results.append(result)
        
        self.print_result(result)
        input("\nPress Enter to continue...")
    
    def analyze_multiple_files(self):
        """Analyze multiple files"""
        self.clear_screen()
        self.print_banner()
        print("ANALYZE MULTIPLE FILES")
        print("="*60)
        
        files = self.get_multiple_files()
        if not files:
            print("No files to analyze.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n🔍 Analyzing {len(files)} files...\n")
        results = []
        
        for i, filepath in enumerate(files, 1):
            print(f"[{i}/{len(files)}] {filepath.name}...", end=" ")
            result = self.analyzer.analyze_file(filepath)
            results.append(result)
            self.results.append(result)
            
            status = "🚨" if result.get('suspicious') else "⚠️" if result.get('mismatch') else "✓"
            print(status)
        
        self.print_summary(results)
        
        # Show details?
        show_details = input("\nShow detailed results for each file? (y/n): ").lower()
        if show_details == 'y':
            for result in results:
                self.print_result(result, detailed=True)
        
        input("\nPress Enter to continue...")
    
    def analyze_folder(self):
        """Analyze all files in a folder"""
        self.clear_screen()
        self.print_banner()
        print("ANALYZE FOLDER")
        print("="*60)
        
        dirpath = self.get_directory_path()
        if not dirpath:
            return
        
        # Ask for recursive scan
        recursive = input("Scan subfolders too? (y/n): ").lower() == 'y'
        
        # Get all files
        if recursive:
            files = [f for f in dirpath.rglob('*') if f.is_file()]
        else:
            files = [f for f in dirpath.glob('*') if f.is_file()]
        
        if not files:
            print("No files found in this folder.")
            input("\nPress Enter to continue...")
            return
        
        print(f"\n🔍 Found {len(files)} files. Analyzing...\n")
        results = []
        
        for i, filepath in enumerate(files, 1):
            print(f"[{i}/{len(files)}] {filepath.name}...", end=" ")
            result = self.analyzer.analyze_file(filepath)
            results.append(result)
            self.results.append(result)
            
            status = "🚨" if result.get('suspicious') else "⚠️" if result.get('mismatch') else "✓"
            print(status)
        
        self.print_summary(results)
        
        # Show suspicious files details
        suspicious = [r for r in results if r.get('suspicious')]
        if suspicious:
            print("\n" + "="*60)
            print("SUSPICIOUS FILES - DETAILED REPORT")
            print("="*60)
            for result in suspicious:
                self.print_result(result, detailed=True)
        
        input("\nPress Enter to continue...")
    
    def view_recent_results(self):
        """View recent analysis results"""
        self.clear_screen()
        self.print_banner()
        print("RECENT RESULTS")
        print("="*60)
        
        if not self.results:
            print("\nNo results yet. Analyze some files first!")
            input("\nPress Enter to continue...")
            return
        
        self.print_summary(self.results)
        
        view_all = input("\nView details for all files? (y/n): ").lower()
        if view_all == 'y':
            for result in self.results:
                self.print_result(result)
        
        input("\nPress Enter to continue...")
    
    def export_results(self):
        """Export results to file"""
        self.clear_screen()
        self.print_banner()
        print("EXPORT RESULTS")
        print("="*60)
        
        if not self.results:
            print("\nNo results to export!")
            input("\nPress Enter to continue...")
            return
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"analysis_report_{timestamp}.txt"
        
        filename = input(f"\nSave as [{default_filename}]: ").strip()
        if not filename:
            filename = default_filename
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("FILE TYPE ANALYSIS REPORT\n")
                f.write("="*60 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Files: {len(self.results)}\n")
                f.write("="*60 + "\n\n")
                
                # Summary
                suspicious = sum(1 for r in self.results if r.get('suspicious'))
                mismatches = sum(1 for r in self.results if r.get('mismatch'))
                safe = len(self.results) - mismatches
                
                f.write("SUMMARY\n")
                f.write("-"*60 + "\n")
                f.write(f"Safe Files:        {safe}\n")
                f.write(f"Type Mismatches:   {mismatches}\n")
                f.write(f"Suspicious Files:  {suspicious}\n\n")
                
                # Detailed results
                f.write("DETAILED RESULTS\n")
                f.write("="*60 + "\n\n")
                
                for i, result in enumerate(self.results, 1):
                    status = "SUSPICIOUS" if result.get('suspicious') else "MISMATCH" if result.get('mismatch') else "SAFE"
                    
                    f.write(f"{i}. {result['filename']}\n")
                    f.write(f"   Status: {status}\n")
                    f.write(f"   Claimed Extension: {result['claimed_extension']}\n")
                    f.write(f"   Detected Type: {result['detected_type']}\n")
                    f.write(f"   Expected Extension: {result['detected_extension']}\n")
                    f.write(f"   File Size: {self.format_size(result['file_size'])}\n")
                    if result.get('description'):
                        f.write(f"   Description: {result['description']}\n")
                    f.write("\n")
            
            print(f"\n✓ Report saved to: {filename}")
            print(f"  Location: {Path(filename).absolute()}")
            
        except Exception as e:
            print(f"\n❌ Error saving report: {e}")
        
        input("\nPress Enter to continue...")
    
    def view_database(self):
        """View signature database"""
        self.clear_screen()
        self.print_banner()
        print("FILE SIGNATURE DATABASE")
        print("="*60)
        print(f"Total Signatures: {len(self.db.signatures)}\n")
        
        # Group by type
        categories = {}
        for sig in self.db.signatures:
            if 'Executable' in sig.file_type:
                category = 'Executables'
            elif 'Archive' in sig.file_type or 'ZIP' in sig.file_type:
                category = 'Archives'
            elif 'Image' in sig.file_type:
                category = 'Images'
            elif 'Document' in sig.file_type or 'PDF' in sig.file_type:
                category = 'Documents'
            elif 'Audio' in sig.file_type or 'Video' in sig.file_type:
                category = 'Media'
            else:
                category = 'Other'
            
            if category not in categories:
                categories[category] = []
            categories[category].append(sig)
        
        # Display by category
        for category, sigs in sorted(categories.items()):
            print(f"\n{category} ({len(sigs)}):")
            print("-"*60)
            for sig in sigs:
                print(f"  • {sig.file_type}")
                print(f"    Extensions: {', '.join(sig.extensions)}")
                print(f"    Magic Bytes: {sig.magic_bytes.hex()}")
                if sig.description:
                    print(f"    Description: {sig.description}")
                print()
        
        input("\nPress Enter to continue...")
    
    def clear_results(self):
        """Clear all results"""
        if self.results:
            confirm = input(f"\nClear {len(self.results)} result(s)? (y/n): ").lower()
            if confirm == 'y':
                self.results = []
                print("✓ Results cleared.")
        else:
            print("\nNo results to clear.")
        input("\nPress Enter to continue...")
    
    def run(self):
        """Main application loop"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            choice = input("\nSelect option (1-8): ").strip()
            
            if choice == '1':
                self.analyze_single_file()
            elif choice == '2':
                self.analyze_multiple_files()
            elif choice == '3':
                self.analyze_folder()
            elif choice == '4':
                self.view_recent_results()
            elif choice == '5':
                self.export_results()
            elif choice == '6':
                self.view_database()
            elif choice == '7':
                self.clear_results()
            elif choice == '8':
                print("\n👋 Thank you for using File Type Identifier!")
                print("   Stay safe and verify your files!\n")
                sys.exit(0)
            else:
                print("\n❌ Invalid option. Please try again.")
                input("\nPress Enter to continue...")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='File Type Identifier - Detect malware disguised with fake extensions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Interactive mode
  %(prog)s file.exe                 # Analyze single file
  %(prog)s file1.jpg file2.pdf      # Analyze multiple files
  %(prog)s -d /path/to/folder       # Analyze folder
  %(prog)s -d /path/to/folder -r    # Analyze folder recursively
        """
    )
    
    parser.add_argument('files', nargs='*', help='File(s) to analyze')
    parser.add_argument('-d', '--directory', help='Analyze all files in directory')
    parser.add_argument('-r', '--recursive', action='store_true', help='Scan subdirectories')
    parser.add_argument('-o', '--output', help='Export results to file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output (only suspicious files)')
    
    args = parser.parse_args()
    
    # If arguments provided, run in command-line mode
    if args.files or args.directory:
        analyzer = FileTypeAnalyzer()
        results = []
        
        # Analyze files
        if args.files:
            for filepath in args.files:
                path = Path(filepath)
                if path.exists() and path.is_file():
                    result = analyzer.analyze_file(path)
                    results.append(result)
                else:
                    print(f"❌ File not found: {filepath}", file=sys.stderr)
        
        # Analyze directory
        if args.directory:
            dirpath = Path(args.directory)
            if dirpath.exists() and dirpath.is_dir():
                if args.recursive:
                    files = [f for f in dirpath.rglob('*') if f.is_file()]
                else:
                    files = [f for f in dirpath.glob('*') if f.is_file()]
                
                for filepath in files:
                    result = analyzer.analyze_file(filepath)
                    results.append(result)
            else:
                print(f"❌ Directory not found: {args.directory}", file=sys.stderr)
                sys.exit(1)
        
        # Display results
        if not args.quiet:
            for result in results:
                status = "🚨 SUSPICIOUS" if result.get('suspicious') else "⚠️ MISMATCH" if result.get('mismatch') else "✓ SAFE"
                print(f"{status} - {result['filename']}: {result['detected_type']}")
        else:
            # Only show suspicious
            suspicious = [r for r in results if r.get('suspicious')]
            if suspicious:
                print("🚨 SUSPICIOUS FILES DETECTED:")
                for result in suspicious:
                    print(f"  • {result['filename']} ({result['detected_type']})")
        
        # Export if requested
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(f"{result['filename']},{result['claimed_extension']},{result['detected_type']},{result.get('suspicious', False)}\n")
            print(f"\n✓ Results saved to: {args.output}")
        
        # Exit with code based on findings
        suspicious_count = sum(1 for r in results if r.get('suspicious'))
        sys.exit(1 if suspicious_count > 0 else 0)
    
    else:
        # Run in interactive mode
        app = InteractiveAnalyzer()
        app.run()


if __name__ == '__main__':
    main()
