#!/usr/bin/python3
#Patch for: CVE-2021-34527 'PrintNightmare'
#Dev-Date: 12-07-2021
import platform, winreg, subprocess, os, ctypes


def is_system_vulnerable():
    system = (platform.system() + " " + platform.release()).lower()
    if system.find("windows") < 0:
        print("[+] This system is NOT vulnerable to PrintNightmare")
        return False
    try:
        security_update = subprocess.check_output('powershell.exe Get-Hotfix KB5004954', shell=True).decode("UTF-8")
        if security_update.lower().find("hotfixid") >= 0:
            print("[+] PrintNightmare Vulnerability Patch: KB5004945 update is already Installed")
            print("[+] This system is NOT vulnerable to PrintNightmare")
            return False
    except:
        print("[!] PrintNightmare Vulnerability Patch: KB5004945 update is NOT Installed!")
        updating_system()
    try:
        access_registry_item = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        registry_key = winreg.OpenKey(access_registry_item, REG_PATH)
        access_key_handler = int(registry_key)
        winreg.CloseKey(registry_key)
        if access_key_handler >= 0:
            print("[!] This system is Vulnerable to PrintNightmare")
            return True
    except FileNotFoundError:
        print("[+] PointAndPrint Registry key does NOT exist")
        print("[+] This system is NOT vulnerable to PrintNightmare")
        return False


def updating_system():
    try:
        PS_version = int(subprocess.check_output('powershell.exe $PSVersionTable.PSVersion.major', shell=True).decode("UTF-8"))
        if PS_version > 4:
            print("[+] Trying to install the patch ...")
            try:
                subprocess.check_output('powershell.exe Get-WindowsUpdate -Install -KBArticleID "KB5004945"', shell=True).decode("UTF-8")
                print("[+] Patch is installed successfully")
            except:
                print("[-] Powershell could not recognize Get-WindowsUpdate, Patch is NOT installed")
                print("[!] Please install the security update {KB5004945} manually ")

    except:
        print("[-] Powershell version could NOT be identified")


def is_spooler_running():
    try:
        spooler_status = subprocess.check_output('powershell.exe Get-Service -Name Spooler', shell=True).decode("UTF-8")
        if spooler_status.lower().find("running") >= 0:
            print("[!] Print Spooler service is running")
            return True
    except:
        print("[-] I could not identify if the Print Spooler service is running or not")
        return False


def disable_printspooler():
    try:
        subprocess.check_output('powershell.exe Stop-Service -Name Spooler -Force', shell=True)
        print("[+] The Print Spooler service is stopped")
    except:
        print("[-] The Print Spooler service cannot be stopped on this computer")
    try:
        subprocess.check_output('powershell.exe Set-Service -Name Spooler -StartupType Disabled', shell=True)
        print("[+] The Print Spooler service is disabled on startup")
    except:
        print("[-] Something went wrong, I could not disable the service on startup")


def get_printer_reg(NoWarning,UpdatePromptSettings,RestrictDriver):
    values = []
    registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ)
    value1, regtype = winreg.QueryValueEx(registry_key, NoWarning)
    value2, regtype = winreg.QueryValueEx(registry_key, UpdatePromptSettings)
    value3, regtype = winreg.QueryValueEx(registry_key, RestrictDriver)
    values.append(value1)
    values.append(value2)
    values.append(value3)
    winreg.CloseKey(registry_key)
    return values


def set_printer_reg():
    try:
        values = get_printer_reg("NoWarningNoElevationOnInstall", "UpdatePromptSettings","RestrictDriverInstallationToAdministrators")
        NoWarning= int(values[0])
        UpdatePromptSettings= int(values[1])
        RestrictDriver = int(values[2])
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_WRITE)
        if NoWarning == 1:
            winreg.SetValueEx(registry_key,"NoWarningNoElevationOnInstall", 0 ,winreg.REG_SZ, "0")
        if UpdatePromptSettings == 1:
            winreg.SetValueEx(registry_key, "UpdatePromptSettings", 0, winreg.REG_SZ, "0")
        if RestrictDriver == 0:
            winreg.SetValueEx(registry_key, "RestrictDriverInstallationToAdministrators", 0, winreg.REG_SZ, "1")
        winreg.CloseKey(registry_key)
        print("[+] Registry key has been updated successfully")
    except:
        print("[-] Something went wrong, I could not check the registry key")


def check_admin_priv():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin


def banner():
    print('''    
 ___       _        _    _ _  _       _     _                         
| . \ _ _ <_>._ _ _| |_ | \ |<_> ___ | |_ _| |_ ._ _ _  ___  _ _  ___ 
|  _/| '_>| || ' | | |  |   || |/ . || . | | |  | ' ' |<_> || '_>/ ._>
|_|  |_|  |_||_|_| |_|  |_\_||_|\_. ||_|_| |_|  |_|_|_|<___||_|  \___.
                                <___'                                 
 ___        _        _             
| . \ ___ _| |_ ___ | |_  ___  _ _ 
|  _/<_> | | | / | '| . |/ ._>| '_>
|_|  <___| |_| \_|_.|_|_|\___.|_|  

==========================
PrintNightmare Patcher v1.0
Author: irison
GitHub: https://github.com/0xirison
*._.* __ _ ._ 
|[  |_) (_)[ )
==========================                                   
    ''')

if __name__ == '__main__':
    REG_PATH = r'SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    banner()
    amiadmin = check_admin_priv()
    if not amiadmin:
        print("[-] Please run the script with elevated privileges")
        exit(0)
    is_vulnerable = is_system_vulnerable()
    is_spooler_running = is_spooler_running()
    if is_spooler_running:
        disable_printspooler()
    if is_vulnerable or is_spooler_running:
        set_printer_reg()
