import socket
import time

from rich.console import Console

console = Console()

# Fixed "ShadowScope" banner - cleaner font, ensuring W is visible
BANNER_ART = r"""
[bold cyan]
   _____ __               __               _____
  / ___// /_  ____ ______/ /___ _      __ / ___/_________  ____  ___
  \__ \/ __ \/ __ `/ __  / __ \ | /| / / \__ \/ ___/ __ \/ __ \/ _ \
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ / ___/ / /__/ /_/ / /_/ /  __/
/____/_/ /_/\__,_/\__,_/\____/|__/|__/ /____/\___/\____/ .___/\___/
                                                      /_/
[/bold cyan]
"""

def check_internet():
    """
    Checks for internet connection by trying to connect to 8.8.8.8:53.
    """
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def show_satellite_animation():
    """
    Simulates a satellite connection sequence with real internet check.
    """
    console.print(BANNER_ART)

    steps = [
        "Initializing orbital trajectory...",
        "Acquiring signal from KH-11...",
        "Handshaking with ground station...",
        "Decrypting secure feed..."
    ]

    connected = False
    with console.status("[bold green]Establishing Secure Uplink...[/bold green]", spinner="dots12") as status:
        for _ in range(2):
            for text in steps:
                time.sleep(0.2)
                status.update(f"[bold green]{text}[/bold green]")

        status.update("[bold yellow]Verifying Uplink Integrity...[/bold yellow]")
        connected = check_internet()
        time.sleep(0.5)

    if connected:
        console.print("[bold green][+] Secure Uplink Established[/bold green]\n")
        return True
    else:
        console.print("[bold red][!] Uplink Failed: No Connection Detected[/bold red]\n")
        return False

def show():
    return show_satellite_animation()
