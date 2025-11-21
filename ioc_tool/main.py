import os
from dotenv import load_dotenv
from ioc_tool.ui import cli
import sys

def main():
    # Load environment variables
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
    
    # Run CLI
    try:
        cli.main()
    except KeyboardInterrupt:
        print("\n\n[!] ShadowScope connection terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
