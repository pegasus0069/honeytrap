!/bin/bash

# Path to the Python script
PYTHON_SCRIPT="ukcs/bin/python"
SERVER_SCRIPT="server.py"

# Prompt the user for the sudo password
read -s -p "Enter your sudo password: " SUDO_PASSWORD
echo

# Run the Python script with sudo
echo "$SUDO_PASSWORD" | sudo -S "$PYTHON_SCRIPT" "$SERVER_SCRIPT"

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "Server script executed successfully."
else
    echo "Failed to execute the server script."
fi