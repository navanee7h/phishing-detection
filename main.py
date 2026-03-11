"""
Phishing Website Detection - Main Entry Point
CLI interface for generating data, training models, and detecting phishing URLs.

Usage:
    python main.py generate              Generate synthetic dataset
    python main.py train                 Train ML models
    python main.py detect <url>          Classify a URL
    python main.py detect               Interactive mode (enter URLs one by one)
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_generator import generate_dataset
from train_model import train
from detector import detect, PhishingDetector

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""


BANNER = f"""
{'='*70}

   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██████╗ ███████╗████████╗
   ██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔══██╗██╔════╝╚══██╔══╝
   ██████╔╝███████║██║███████╗███████║    ██║  ██║█████╗     ██║   
   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██║  ██║██╔══╝     ██║   
   ██║     ██║  ██║██║███████║██║  ██║    ██████╔╝███████╗   ██║   
   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚══════╝   ╚═╝   

   Phishing Website Detection System
   ML-powered URL classification using URL & domain-based features

{'='*70}
"""


def print_usage():
    """Print usage instructions."""
    print(BANNER)
    print(f"  {Style.BRIGHT}COMMANDS:{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}python main.py generate{Style.RESET_ALL}         Generate synthetic dataset")
    print(f"    {Fore.CYAN}python main.py train{Style.RESET_ALL}            Train ML models")
    print(f"    {Fore.CYAN}python main.py detect <url>{Style.RESET_ALL}     Classify a specific URL")
    print(f"    {Fore.CYAN}python main.py detect{Style.RESET_ALL}           Interactive detection mode")
    print()


def interactive_mode():
    """Run interactive detection mode where users can enter URLs one by one."""
    print(BANNER)
    print(f"  {Style.BRIGHT}INTERACTIVE DETECTION MODE{Style.RESET_ALL}")
    print(f"  Enter URLs to classify. Type 'quit' or 'exit' to stop.\n")

    detector = PhishingDetector()

    while True:
        try:
            url = input(f"  {Fore.CYAN}Enter URL ▸ {Style.RESET_ALL}").strip()
            if not url:
                continue
            if url.lower() in ("quit", "exit", "q"):
                print(f"\n  {Fore.GREEN}Goodbye!{Style.RESET_ALL}\n")
                break
            result = detector.predict(url)
            detector.display_result(result)
        except KeyboardInterrupt:
            print(f"\n\n  {Fore.GREEN}Goodbye!{Style.RESET_ALL}\n")
            break
        except Exception as e:
            print(f"\n  {Fore.RED}Error: {e}{Style.RESET_ALL}\n")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1].lower()

    if command == "generate":
        print(BANNER)
        print(f"  {Style.BRIGHT}GENERATING DATASET{Style.RESET_ALL}\n")
        num_samples = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
        generate_dataset(num_samples=num_samples)

    elif command == "train":
        print(BANNER)
        dataset_path = sys.argv[2] if len(sys.argv) > 2 else "phishing_dataset.csv"
        if not os.path.exists(dataset_path):
            print(f"  {Fore.RED}❌ Dataset not found: {dataset_path}")
            print(f"  {Fore.YELLOW}   Run 'python main.py generate' first.\n")
            return
        train(dataset_path)

    elif command == "detect":
        if len(sys.argv) > 2:
            url = sys.argv[2]
            detect(url)
        else:
            interactive_mode()

    else:
        print(f"\n  {Fore.RED}❌ Unknown command: {command}{Style.RESET_ALL}")
        print_usage()


if __name__ == "__main__":
    main()
