# PrintNightmare-Patcher
This tool resolves the PrintNightmare vulnerability that occurs to print spooler service for Windows machines [CVE-2021-34527]. In addition, it checks if your system has the relevant security update for it or not. 

# Usage
python printnightmare-patcher.py

# Installation
git clone https://github.com/0xIrison/PrintNightmare-Patcher.git

# Dependencies
No dependencies required

# Features
- Check if the windows system is vulnerable to PrintNightmare or not.
- Check if the Print Spooler service is running or not, and disable it if running.
- Check if the system has an update for PrintNightmare vulnerability "Hotfix-id: KB5004954", and try it to install it if it is not already installed.
- Changing the registry key 'PointAndPrint' settings as Microsoft suggests.

# Does it require elevated privileges?
Yes, it requires administrative privileges

# References
- Windows Print Spooler Remote Code Execution Vulnerability by [Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- Windwos Security Update 'KB5004954' by [Microsoft](https://support.microsoft.com/en-us/topic/july-6-2021-kb5004954-monthly-rollup-out-of-band-8e7742b6-8a42-41ab-86dd-0dd0b36b4139)

# Screenshot
![alt text](https://i.imgur.com/AJpJbz7.png)
