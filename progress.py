import sys

BAR_LENGTH = 35

def show_progress(current: int, total: int) -> None:
    percent = current / total
    filled = int(BAR_LENGTH * percent)
    bar = "█" * filled + "░" * (BAR_LENGTH - filled)

    sys.stdout.write(f"\rScanning [{bar}] {percent * 100:5.1f}%")
    sys.stdout.flush()

    if current == total:
        print()