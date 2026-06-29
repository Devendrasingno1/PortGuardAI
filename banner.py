from config import APP_NAME, APP_VERSION, DEVELOPER


def show_banner() -> None:
    print("=" * 60)
    print(f"        {APP_NAME} - Intelligent Network Analyzer")
    print(f"        Version: {APP_VERSION}")
    print(f"        Developed by {DEVELOPER}")
    print("=" * 60)