#!/bin/bash
# Create the necessary directories under Documents
mkdir -p ~/Documents/Apps ~/Documents/Boxes ~/Documents/Tools ~/Documents/VPNs

# Download Obsidian AppImage (update the URL if you need a newer version)
echo "Downloading Obsidian AppImage..."
wget -O ~/Documents/Apps/obsidian.AppImage "https://github.com/obsidianmd/obsidian-releases/releases/download/v1.1.16/Obsidian-1.1.16.AppImage"

# Download Caido AppImage using the provided URL
echo "Downloading Caido AppImage..."
wget -O ~/Documents/Apps/caido.AppImage "https://caido.download/releases/v0.46.0/caido-desktop-v0.46.0-linux-x86_64.AppImage"

# Give execute permission to both AppImages
echo "Setting execute permissions for downloaded AppImages..."
chmod +x ~/Documents/Apps/obsidian.AppImage
chmod +x ~/Documents/Apps/caido.AppImage

# Update system package lists and upgrade packages
echo "Updating and upgrading the system..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install Files
echo "Installing Files and Wordlists"
sudo apt -y install seclists

echo "Setup complete."
