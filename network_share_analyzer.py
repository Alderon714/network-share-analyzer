# Project 1's main()
# Daniel S Cochran
# https://github.com/Alderon714/network_share_analyzer
#
# June 27, 2025 


#!/usr/bin/env python3
"""
Network Share Analysis Agent
Analyzes directory structure and security settings of network shares
"""

import os
import stat
import json
import csv
from pathlib import Path
from datetime import datetime
import argparse
import logging
from collections import defaultdict, Counter
import pandas as pd

class NetworkShareAnalyzer:
    def __init__(self, share_path, output_dir="analysis_output"):
        self.share_path = Path(share_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize data structures
        self.directory_structure = {}
        self.file_inventory = []
        self.security_issues = []
        self.statistics = {
            'total_files': 0,
            'total_directories': 0,
            'total_size': 0,
            'file_types': Counter(),
            'permission_issues': 0,
            'empty_directories': 0,
            'large_files': [],
            'duplicate_names': defaultdict(list)
        }
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_file = self.output_dir / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def analyze_permissions(self, file_path):
        """Analyze file/directory permissions"""
        try:
            stat_info = file_path.stat()
            mode = stat_info.st_mode
            
            permissions = {
                'owner_read': bool(mode & stat.S_IRUSR),
                'owner_write': bool(mode & stat.S_IWUSR),
                'owner_execute': bool(mode & stat.S_IXUSR),
                'group_read': bool(mode & stat.S_IRGRP),
                'group_write': bool(mode & stat.S_IWGRP),
                'group_execute': bool(mode & stat.S_IXGRP),
                'other_read': bool(mode & stat.S_IROTH),
                'other_write': bool(mode & stat.S_IWOTH),
                'other_execute': bool(mode & stat.S_IXOTH),
                'octal': oct(mode)[-3:]
            }
            
            # Check for potential security issues
            if permissions['other_write']:
                self.security_issues.append({
                    'path': str(file_path),
                    'issue': 'World-writable',
                    'risk': 'High',
                    'description': 'File/directory is writable by everyone'
                })
                self.statistics['permission_issues'] += 1
                
            if file_path.is_file() and permissions['other_execute']:
                self.security_issues.append({
                    'path': str(file_path),
                    'issue': 'World-executable file',
                    'risk': 'Medium',
                    'description': 'Executable file accessible by everyone'
                })
                
            return permissions
            
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Cannot access permissions for {file_path}: {e}")
            return None
            
    def scan_directory(self, path, max_depth=None, current_depth=0):
        """Recursively scan directory structure"""
        if max_depth and current_depth > max_depth:
            return None
            
        try:
            items = list(path.iterdir())
            
            # Check for empty directory
            if not items:
                self.statistics['empty_directories'] += 1
                
            structure = {
                'path': str(path),
                'permissions': self.analyze_permissions(path),
                'subdirectories': {},
                'files': [],
                'created': datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                'size': 0
            }
            
            self.statistics['total_directories'] += 1
            
            for item in items:
                try:
                    if item.is_dir():
                        # Recursively scan subdirectories
                        subdir_structure = self.scan_directory(item, max_depth, current_depth + 1)
                        if subdir_structure:
                            structure['subdirectories'][item.name] = subdir_structure
                            structure['size'] += subdir_structure['size']
                    else:
                        # Process file
                        file_info = self.process_file(item)
                        if file_info:
                            structure['files'].append(file_info)
                            structure['size'] += file_info['size']
                            
                except (PermissionError, OSError) as e:
                    self.logger.warning(f"Cannot access {item}: {e}")
                    continue
                    
            return structure
            
        except (PermissionError, OSError) as e:
            self.logger.error(f"Cannot scan directory {path}: {e}")
            return None
            
    def process_file(self, file_path):
        """Process individual file and extract metadata"""
        try:
            stat_info = file_path.stat()
            
            file_info = {
                'name': file_path.name,
                'path': str(file_path),
                'size': stat_info.st_size,
                'extension': file_path.suffix.lower(),
                'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat_info.st_atime).isoformat(),
                'permissions': self.analyze_permissions(file_path)
            }
            
            # Update statistics
            self.statistics['total_files'] += 1
            self.statistics['total_size'] += stat_info.st_size
            self.statistics['file_types'][file_path.suffix.lower()] += 1
            
            # Track large files (>100MB)
            if stat_info.st_size > 100 * 1024 * 1024:
                self.statistics['large_files'].append({
                    'path': str(file_path),
                    'size': stat_info.st_size,
                    'size_mb': round(stat_info.st_size / 1024 / 1024, 2)
                })
                
            # Track potential duplicates by name
            self.statistics['duplicate_names'][file_path.name].append(str(file_path))
            
            # Add to file inventory
            self.file_inventory.append(file_info)
            
            return file_info
            
        except (PermissionError, OSError) as e:
            self.logger.warning(f"Cannot process file {file_path}: {e}")
            return None
            
    def find_duplicates(self):
        """Find potential duplicate files based on name and size"""
        duplicates = []
        
        # Group files by name and size
        file_groups = defaultdict(list)
        for file_info in self.file_inventory:
            key = (file_info['name'], file_info['size'])
            file_groups[key].append(file_info)
            
        # Find groups with multiple files
        for (name, size), files in file_groups.items():
            if len(files) > 1:
                duplicates.append({
                    'name': name,
                    'size': size,
                    'count': len(files),
                    'paths': [f['path'] for f in files]
                })
                
        return duplicates
        
    def generate_reports(self):
        """Generate analysis reports"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 1. Directory structure JSON
        structure_file = self.output_dir / f"directory_structure_{timestamp}.json"
        with open(structure_file, 'w') as f:
            json.dump(self.directory_structure, f, indent=2)
            
        # 2. File inventory CSV
        inventory_file = self.output_dir / f"file_inventory_{timestamp}.csv"
        if self.file_inventory:
            df = pd.DataFrame(self.file_inventory)
            df.to_csv(inventory_file, index=False)
            
        # 3. Security issues report
        security_file = self.output_dir / f"security_issues_{timestamp}.json"
        with open(security_file, 'w') as f:
            json.dump(self.security_issues, f, indent=2)
            
        # 4. Statistics summary
        stats_file = self.output_dir / f"statistics_{timestamp}.json"
        
        # Convert Counter to dict for JSON serialization
        stats_copy = self.statistics.copy()
        stats_copy['file_types'] = dict(stats_copy['file_types'])
        
        # Add duplicate analysis
        duplicates = self.find_duplicates()
        stats_copy['potential_duplicates'] = len(duplicates)
        stats_copy['duplicate_details'] = duplicates
        
        # Calculate storage efficiency
        if stats_copy['total_size'] > 0:
            stats_copy['size_gb'] = round(stats_copy['total_size'] / 1024 / 1024 / 1024, 2)
            
        with open(stats_file, 'w') as f:
            json.dump(stats_copy, f, indent=2)
            
        # 5. Generate summary report
        self.generate_summary_report(timestamp)
        
        return {
            'structure_file': structure_file,
            'inventory_file': inventory_file,
            'security_file': security_file,
            'statistics_file': stats_file
        }
        
    def generate_summary_report(self, timestamp):
        """Generate human-readable summary report"""
        report_file = self.output_dir / f"summary_report_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("NETWORK SHARE ANALYSIS SUMMARY\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Share Path: {self.share_path}\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Basic statistics
            f.write("BASIC STATISTICS\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Files: {self.statistics['total_files']:,}\n")
            f.write(f"Total Directories: {self.statistics['total_directories']:,}\n")
            f.write(f"Total Size: {self.statistics['total_size'] / 1024 / 1024 / 1024:.2f} GB\n")
            f.write(f"Empty Directories: {self.statistics['empty_directories']:,}\n\n")
            
            # File types
            f.write("TOP FILE TYPES\n")
            f.write("-" * 15 + "\n")
            for ext, count in self.statistics['file_types'].most_common(10):
                f.write(f"{ext or 'No extension'}: {count:,}\n")
            f.write("\n")
            
            # Security issues
            f.write("SECURITY ISSUES\n")
            f.write("-" * 15 + "\n")
            f.write(f"Total Permission Issues: {self.statistics['permission_issues']}\n")
            
            high_risk = [issue for issue in self.security_issues if issue['risk'] == 'High']
            f.write(f"High Risk Issues: {len(high_risk)}\n")
            
            if high_risk:
                f.write("\nHigh Risk Files/Directories:\n")
                for issue in high_risk[:10]:  # Show first 10
                    f.write(f"  - {issue['path']}: {issue['description']}\n")
            f.write("\n")
            
            # Large files
            f.write("LARGE FILES (>100MB)\n")
            f.write("-" * 20 + "\n")
            f.write(f"Count: {len(self.statistics['large_files'])}\n")
            for large_file in sorted(self.statistics['large_files'], 
                                  key=lambda x: x['size'], reverse=True)[:10]:
                f.write(f"  - {large_file['path']}: {large_file['size_mb']} MB\n")
            f.write("\n")
            
            # Potential duplicates
            duplicates = self.find_duplicates()
            f.write("POTENTIAL DUPLICATES\n")
            f.write("-" * 20 + "\n")
            f.write(f"Files with same name/size: {len(duplicates)}\n")
            for dup in duplicates[:5]:  # Show first 5
                f.write(f"  - {dup['name']} ({dup['count']} copies)\n")
            
    def run_analysis(self, max_depth=None):
        """Run the complete analysis"""
        self.logger.info(f"Starting analysis of {self.share_path}")
        
        if not self.share_path.exists():
            raise FileNotFoundError(f"Share path does not exist: {self.share_path}")
            
        # Scan directory structure
        self.logger.info("Scanning directory structure...")
        self.directory_structure = self.scan_directory(self.share_path, max_depth)
        
        # Generate reports
        self.logger.info("Generating reports...")
        report_files = self.generate_reports()
        
        self.logger.info("Analysis complete!")
        self.logger.info(f"Reports generated in: {self.output_dir}")
        
        return report_files
