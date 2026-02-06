#!/usr/bin/env python3
"""
Advanced Example: Using File Type Identifier as a Library
Demonstrates programmatic usage for integration into other tools
"""

from pathlib import Path
import json
from file_type_identifier import FileTypeAnalyzer, MagicNumberDatabase


def example_1_basic_analysis():
    """Example 1: Analyze a single file"""
    print("=" * 60)
    print("Example 1: Basic File Analysis")
    print("=" * 60)
    
    analyzer = FileTypeAnalyzer()
    
    # Analyze a suspicious file
    result = analyzer.analyze_file(Path("test_files/malware.jpg"))
    
    print(f"File: {result['filename']}")
    print(f"Claimed extension: {result['claimed_extension']}")
    print(f"Detected type: {result['detected_type']}")
    print(f"Mismatch: {result['mismatch']}")
    print(f"Suspicious: {result['suspicious']}")
    print(f"Description: {result['description']}")
    print()


def example_2_batch_analysis():
    """Example 2: Batch analyze multiple files"""
    print("=" * 60)
    print("Example 2: Batch Analysis with Filtering")
    print("=" * 60)
    
    analyzer = FileTypeAnalyzer()
    results = analyzer.scan_directory(Path("test_files"))
    
    # Filter suspicious files
    suspicious_files = [r for r in results if r.get('suspicious')]
    
    print(f"Total files scanned: {len(results)}")
    print(f"Suspicious files found: {len(suspicious_files)}")
    print()
    
    for sf in suspicious_files:
        print(f"  🚨 {sf['filename']}: {sf['detected_type']} disguised as {sf['claimed_extension']}")
    print()


def example_3_export_json():
    """Example 3: Export results to JSON for other tools"""
    print("=" * 60)
    print("Example 3: Export Results to JSON")
    print("=" * 60)
    
    analyzer = FileTypeAnalyzer()
    results = analyzer.scan_directory(Path("test_files"))
    
    # Export to JSON
    output_file = "scan_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results exported to: {output_file}")
    print(f"Total records: {len(results)}")
    print()


def example_4_custom_filtering():
    """Example 4: Custom threat detection logic"""
    print("=" * 60)
    print("Example 4: Custom Threat Detection")
    print("=" * 60)
    
    analyzer = FileTypeAnalyzer()
    results = analyzer.scan_directory(Path("test_files"))
    
    # Custom filter: Find all executables
    executables = [
        r for r in results 
        if r.get('detected_type') and 'Executable' in r['detected_type']
    ]
    
    print("Detected Executables:")
    for exe in executables:
        status = "⚠️ DISGUISED" if exe['mismatch'] else "✓ Normal"
        print(f"  {status}: {exe['filename']} ({exe['detected_type']})")
    print()


def example_5_signature_database():
    """Example 5: Query the signature database"""
    print("=" * 60)
    print("Example 5: Signature Database Query")
    print("=" * 60)
    
    db = MagicNumberDatabase()
    
    print(f"Total signatures in database: {len(db.signatures)}")
    print()
    
    # Find all executable signatures
    print("Executable Signatures:")
    for sig in db.signatures:
        if 'Executable' in sig.file_type:
            print(f"  - {sig.file_type}: {sig.magic_bytes.hex()} ({sig.description})")
    print()
    
    # Find all image signatures
    print("Image Signatures:")
    for sig in db.signatures:
        if 'Image' in sig.file_type:
            print(f"  - {sig.file_type}: {sig.magic_bytes.hex()[:20]}... ({sig.extensions})")
    print()


def example_6_threat_scoring():
    """Example 6: Implement custom threat scoring"""
    print("=" * 60)
    print("Example 6: Threat Scoring System")
    print("=" * 60)
    
    analyzer = FileTypeAnalyzer()
    results = analyzer.scan_directory(Path("test_files"))
    
    def calculate_threat_score(result):
        """Calculate a threat score from 0-100"""
        score = 0
        
        # Base score for any mismatch
        if result.get('mismatch'):
            score += 30
        
        # High score for suspicious files
        if result.get('suspicious'):
            score += 50
        
        # Extra points for executables
        if result.get('detected_type') and 'Executable' in result['detected_type']:
            score += 20
        
        # Reduce score for known benign mismatches (e.g., ZIP files)
        if result.get('detected_type') == 'ZIP Archive':
            score = max(0, score - 20)
        
        return min(100, score)  # Cap at 100
    
    # Score all files
    scored_results = [
        (result, calculate_threat_score(result))
        for result in results
    ]
    
    # Sort by threat score (highest first)
    scored_results.sort(key=lambda x: x[1], reverse=True)
    
    print("Files sorted by threat score:")
    for result, score in scored_results:
        if score > 0:
            risk_level = "🔴 CRITICAL" if score >= 80 else "🟡 MEDIUM" if score >= 40 else "🟢 LOW"
            print(f"  {risk_level} [{score:3d}/100] {result['filename']}")
    print()


def example_7_realtime_monitoring():
    """Example 7: Monitor a directory for new files"""
    print("=" * 60)
    print("Example 7: Real-time Monitoring Concept")
    print("=" * 60)
    
    print("This example shows how to implement real-time monitoring:")
    print("""
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    
    class MalwareDetectionHandler(FileSystemEventHandler):
        def __init__(self):
            self.analyzer = FileTypeAnalyzer()
        
        def on_created(self, event):
            if not event.is_directory:
                result = self.analyzer.analyze_file(Path(event.src_path))
                if result.get('suspicious'):
                    alert_security_team(result)
                    quarantine_file(event.src_path)
    
    # Usage:
    observer = Observer()
    observer.schedule(MalwareDetectionHandler(), '/path/to/monitor', recursive=True)
    observer.start()
    """)
    print()
    print("Note: Requires 'watchdog' package: pip install watchdog")
    print()


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("FILE TYPE IDENTIFIER - ADVANCED USAGE EXAMPLES")
    print("=" * 60 + "\n")
    
    example_1_basic_analysis()
    example_2_batch_analysis()
    example_3_export_json()
    example_4_custom_filtering()
    example_5_signature_database()
    example_6_threat_scoring()
    example_7_realtime_monitoring()
    
    print("=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == '__main__':
    main()
