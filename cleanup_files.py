#!/usr/bin/env python3
"""
Standalone cleanup script for expired files.
This script can be run via cron to automatically clean up files older than 24 hours.

Usage:
    python3 cleanup_files.py
"""

import sys
import os

# Add the current directory to the path so we can import from main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from main import cleanup_old_files, init_db
    
    if __name__ == '__main__':
        # Ensure database is initialized
        init_db()
        
        # Run cleanup
        print("Starting file cleanup...")
        cleanup_old_files()
        print("Cleanup completed.")
        
except Exception as e:
    print(f"ERROR: Cleanup script failed: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
