# PrinterNightmare-Patcher
A patch for PrintNightmare vulnerability that occurs to print spooler service for Windows machines [CVE-2021-34527]

# Dependencies:
No dependencies required

# Does it need elevated privielges?
yes, it needs

# Features:
- Check if the windows machine is vulnerable or not.
- check if the Print Spooler service is running or not, and disable it if running.
- check if the system has an update for PrinterNightmare vulnerability "Hotfix-id: KB5004954", and try it to install it if it is not already installed.
- changing the registry key 'PointAndPrint' settings as Microsoft suggests.

# References:
- Windows Print Spooler Remote Code Execution Vulnerability by [Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- Windwos Security Update 'KB5004954' by [Microsoft](https://support.microsoft.com/en-us/topic/july-6-2021-kb5004954-monthly-rollup-out-of-band-8e7742b6-8a42-41ab-86dd-0dd0b36b4139)
