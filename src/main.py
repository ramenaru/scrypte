import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))

from cli import run  

if __name__ == "__main__":
    run()
