import sys
import asyncio
from cms_scanner_agent import CMSScannerAgent
from logger import logger

from rich.console import Console

console = Console()

async def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        logger.banner()
        console.print("""
[bold cyan]USAGE:[/bold cyan]
  python cms_scanner.py <target>

[bold cyan]EXAMPLES:[/bold cyan]
  python cms_scanner.py example.com
  python cms_scanner.py https://example.com
  python cms_scanner.py www.example.com

[bold cyan]SUPPORTED PLATFORMS:[/bold cyan]
  • WordPress, Joomla, Drupal (Traditional CMS)
  • Wix, Shopify, Squarespace (SaaS Platforms)
  • Custom and unknown platforms

[bold cyan]TROUBLESHOOTING:[/bold cyan]
  • If SSL errors occur, the scanner will try HTTP fallback automatically
  • If 'example.com' fails, try 'www.example.com' 
  • Some sites block automated requests - this is normal
  • Government sites may have strict security policies

[bold red]⚠️ WARNING: FOR AUTHORIZED SECURITY TESTING ONLY ⚠️[/bold red]
""")
        sys.exit(1)
    
    target = sys.argv[1]
    agent = CMSScannerAgent()
    
    try:
        console.print(f"[bold bright_cyan]INITIATING SCAN SEQUENCE FOR:[/bold bright_cyan] [bright_white]{target}[/bright_white]")
        report = await agent.run_cms_scan(target)
        
        if report.get('status') == 'COMPLETED':
            logger.success("CMS security assessment completed successfully")
        else:
            logger.error("CMS security assessment completed with issues")
            
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        await agent.cms_recon.close()
        sys.exit(1)
    except Exception as e:
        logger.error(f"CMS scan failed: {str(e)}")
        await agent.cms_recon.close()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())