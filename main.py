"""CLI entrypoint for WardGuard."""
import argparse
import os
from pathlib import Path
import sys
import yaml

from wardguard.pipeline import run


def load_policy(config_path: Path) -> dict:
    """Load policy configuration."""
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def main() -> None:
    parser = argparse.ArgumentParser(description="WardGuard: Hospital Records Privacy Firewall")
    parser.add_argument("--input", "-i", type=Path, default=None, help="Input directory")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Output directory")
    args = parser.parse_args()

    input_dir = args.input or (Path(os.environ["RAKSHA_INPUT"]) if "RAKSHA_INPUT" in os.environ else None)
    output_dir = args.output or (Path(os.environ["RAKSHA_OUTPUT"]) if "RAKSHA_OUTPUT" in os.environ else None)

    if not input_dir or not output_dir:
        sys.stderr.write("Error: --input and --output (or RAKSHA_INPUT and RAKSHA_OUTPUT) are required.\n")
        sys.exit(2)

    try:
        if output_dir.resolve().is_relative_to(input_dir.resolve()):
            sys.stderr.write("Error: --output cannot be inside --input.\n")
            sys.exit(2)
    except OSError:
        pass

    secret_str = os.environ.get("RAKSHA_SECRET")
    if not secret_str:
        sys.stderr.write("Error: RAKSHA_SECRET environment variable is required.\n")
        sys.exit(2)

    policy_file = Path(__file__).resolve().parent / "config" / "policy.yaml"
    policy = load_policy(policy_file)

    exit_code = run(
        input_dir=input_dir,
        output_dir=output_dir,
        secret=secret_str.encode("utf-8"),
        policy=policy,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
