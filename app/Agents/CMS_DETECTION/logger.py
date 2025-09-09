
from rich.console import Console
from rich.panel import Panel

console = Console()

class Logger:
    """Advanced logging with Rich styling"""
    
    @staticmethod
    def banner():
        ascii_art = """[bold bright_cyan]
 ██████╗███╗   ███╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔════╝████╗ ████║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║     ██╔████╔██║███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║     ██║╚██╔╝██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚██████╗██║ ╚═╝ ██║███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═════╝╚═╝     ╚═╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold bright_cyan]"""
        
        subtitle_text = "[bright_magenta]Professional CMS Security Analysis Platform[/bright_magenta]"
        version_info = "[dim white]v2.1.0 | Advanced Reconnaissance & Vulnerability Assessment[/dim white]"
        
        console.print(ascii_art)
        console.print(f"\n{subtitle_text.center(88)}")
        console.print(f"{version_info.center(88)}")
        console.print("[bright_yellow]" + "═" * 88 + "[/bright_yellow]")
    
    @staticmethod
    def info(message: str):
        console.print(f"[blue][INFO][/blue] {message}")
    
    @staticmethod
    def success(message: str):
        console.print(f"[green]✓ {message}[/green]")
    
    @staticmethod
    def warning(message: str):
        console.print(f"[yellow]⚠ {message}[/yellow]")
    
    @staticmethod
    def error(message: str):
        console.print(f"[red]✗ {message}[/red]")
    
    @staticmethod
    def critical(message: str):
        console.print(f"[bold red]🚨 {message}[/bold red]")

logger = Logger()