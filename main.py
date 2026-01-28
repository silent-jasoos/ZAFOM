#!/usr/bin/env python3
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
ZAFOM - Zee's Analyzer For Online Monitoring
Main Application Entry Point
Author: Zeeshan
Version: 2.1
===========================================
"""

import sys
import platform
import os
import tkinter as tk
from Banner import show_banner, get_app_info
from ui import ZAFOMInterface


def check_privileges():
    """Check if running with required privileges."""
    system = platform.system()
    has_privileges = True
    
    if system in ["Linux", "Darwin"]:  # Unix-like systems
        if os.geteuid() != 0:
            print("\n[WARNING] Not running as root!")
            print("[WARNING] Packet capture may fail without proper privileges")
            print("[INFO] Run with: sudo python3 main.py")
            has_privileges = False
    elif system == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("\n[WARNING] Not running as Administrator!")
                print("[WARNING] Packet capture may fail without proper privileges")
                print("[INFO] Right-click and 'Run as Administrator'")
                has_privileges = False
        except Exception:
            print("\n[WARNING] Could not verify administrator privileges")
            has_privileges = False
    
    return has_privileges


def check_requirements():
    """Check if system meets requirements."""
    print(f"Python Version: {sys.version}")
    print(f"Platform: {platform.system()} {platform.release()}")
    
    all_ok = True
    
    try:
        import scapy
        print(f"Scapy: ✓ (version {scapy.__version__})")
    except ImportError:
        print("Scapy: ✗ (NOT INSTALLED)")
        print("\nPlease install scapy:")
        print("  pip install scapy")
        all_ok = False
    
    try:
        import colorama
        print("Colorama: ✓")
    except ImportError:
        print("Colorama: ✗ (NOT INSTALLED)")
        print("\nPlease install colorama:")
        print("  pip install colorama")
        all_ok = False
    
    if all_ok:
        print("\n✓ All requirements met!")
    
    return all_ok


def main():
    """Main application entry point."""
    # Display CLI banner
    show_banner()
    
    # Check requirements
    if not check_requirements():
        print("\n[ERROR] Missing required dependencies. Please install and try again.")
        sys.exit(1)
    
    # Check privileges
    has_privileges = check_privileges()
    
    # Platform-specific notes
    system = platform.system()
    if system == "Linux":
        print("\n[INFO] Running on Linux")
        if not has_privileges:
            print("[INFO] Limited functionality without root privileges")
    elif system == "Windows":
        print("\n[INFO] Running on Windows")
        print("[INFO] Ensure WinPcap or Npcap is installed")
        if not has_privileges:
            print("[INFO] Limited functionality without Administrator privileges")
    elif system == "Darwin":
        print("\n[INFO] Running on macOS")
        if not has_privileges:
            print("[INFO] Limited functionality without root privileges")
    
    # Get app info
    app_info = get_app_info()
    print(f"\nStarting {app_info['name']} v{app_info['version']}...")
    print("-" * 50)
    
    try:
        # Create main window
        root = tk.Tk()
        
        # Initialize application
        app = ZAFOMInterface(root)
        
        print("[SUCCESS] GUI initialized successfully!")
        print("[INFO] Application is running. Close window to exit.")
        
        # Start main loop
        root.mainloop()
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Application failed to start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()