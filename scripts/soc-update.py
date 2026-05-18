#!/usr/bin/env python3
import subprocess

def main():
    print("Fetching latest updates...")
    subprocess.run(["git", "pull", "origin", "main"])
    
    print("Re-installing the system...")
    subprocess.run(["chmod", "+x", "install.py"])
    subprocess.run(["sudo", "python3", "./install.py"])
    
    print("Update complete! Services have been restarted.")

if __name__ == "__main__":
    main()
