#!/usr/bin/env python3
import os
import sys
import grp
import getpass

def check_python_version():
    print("[*] Checking Python version...")
    major, minor = sys.version_info.major, sys.version_info.minor
    print(f"    Current: {sys.version}")
    if major == 3 and minor >= 8:
        print("    [+] Python version OK.")
        return True
    else:
        print("    [-] Python 3.8+ required.")
        return False

def check_dependencies():
    print("[*] Checking library dependencies...")
    libs = ['psutil', 'evdev', 'yaml', 'requests', 'fastapi', 'uvicorn', 'google.genai']
    all_ok = True
    for lib in libs:
        try:
            if lib == 'yaml':
                __import__('yaml')
            elif lib == 'google.genai':
                import google.genai
            else:
                __import__(lib)
            print(f"    [+] {lib}: Available.")
        except ImportError:
            print(f"    [-] {lib}: Missing.")
            all_ok = False
    return all_ok

def check_input_subsystem():
    print("[*] Checking /dev/input keyboard devices...")
    input_dir = "/dev/input"
    if not os.path.exists(input_dir):
        print("    [-] /dev/input directory does not exist. (Non-Linux system?)")
        return False

    events = [os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.startswith("event")]
    if not events:
        print("    [-] No input event character devices found in /dev/input/.")
        return False

    print(f"    [+] Found {len(events)} event devices.")
    
    # Test read permissions on at least one device
    accessible = 0
    for ev in events:
        try:
            with open(ev, 'rb') as f:
                accessible += 1
        except PermissionError:
            pass

    print(f"    [+] Readable event devices: {accessible} / {len(events)}")
    
    # User permissions detail
    user = getpass.getuser()
    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    try:
        user_gid_name = grp.getgrgid(os.getgid()).gr_name
        groups.append(user_gid_name)
    except KeyError:
        pass
        
    print(f"    [*] Current User: {user} | Member of: {', '.join(set(groups))}")
    
    if accessible > 0:
        print("    [+] Input subsystem access OK.")
        return True
    else:
        print("    [-] Cannot read input events. Run as root/sudo or add user to 'input' group.")
        return False

def main():
    print("=" * 60)
    print("SecureShield AI - Environmental Verification Utility")
    print("=" * 60)
    
    py_ok = check_python_version()
    print("-" * 60)
    deps_ok = check_dependencies()
    print("-" * 60)
    input_ok = check_input_subsystem()
    print("=" * 60)
    
    if py_ok and deps_ok and input_ok:
        print("[SUCCESS] Environment fully configured for SecureShield AI.")
        sys.exit(0)
    else:
        print("[WARNING] Verification failed. Please check missing items above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
