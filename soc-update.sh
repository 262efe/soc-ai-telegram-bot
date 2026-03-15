#!/bin/bash
# SOC Bot Update Script

echo "Fetching latest updates..."
git pull origin main

echo "Re-installing the system..."
chmod +x install.sh
sudo ./install.sh

echo "Update complete! Services have been restarted."
