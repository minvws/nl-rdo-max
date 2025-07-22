import os, sys
from pathlib import Path

# Create absolute resolved path from first argument.
key_file = Path(sys.argv[1]).resolve().as_posix()

# Change to project_dir and add as PYTHONPATH entry.
project_dir = Path(__file__).parent.parent.as_posix()
os.chdir(project_dir)
sys.path.append(project_dir)

# After which we can load modules..
from app.misc.utils import load_jwk

# And use functions therein..
sys.stdout.write(load_jwk(key_file).export())
