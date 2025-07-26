#!/usr/bin/env bash

''':' ; exec "$(command -v python)" "$0" "$@"
'''

import os
import subprocess
import sys

from pathlib import Path

sample_path = os.environ.get("SAMPLE_PATH")
if not sample_path:
    print("Error: SAMPLE_PATH environment variable is required")
    sys.exit(1)
sample = Path(sample_path)

q_script_env = os.environ.get("Q_SCRIPT")
if not q_script_env:
    print("Error: Q_SCRIPT environment variable is required")
    sys.exit(1)
q_script = Path(q_script_env)

# Set Path env
kernel_path_env = os.environ.get("KERNEL_PATH")
if not kernel_path_env:
    print("Error: KERNEL_PATH environment variable is required")
    sys.exit(1)
kernel_path = Path(kernel_path_env)


def main():
    os.chdir(kernel_path)
    test_path = sample.joinpath("runtest.py")
    cmd = " ".join([str(q_script), "-t", str(test_path)])
    try:
        # print(cmd)
        subprocess.run(
            cmd, timeout=180, shell=True, capture_output=True, text=True
        )
        output = subprocess.run(
            "cat auto_grade.txt | grep success",
            capture_output=True,
            text=True,
            shell=True,
        )
        if output.stdout.strip() != "success":
            print("", end="\x1b[1K\r")
            print("   \033[91mFailed\033[0m  %s" % sample.name)
            exit(1)

    except Exception:
        print(f"{sample.name} test run failed", file=sys.stderr)
        subprocess.run("pkill qemu-system-x86", shell=True)
    finally:
        subprocess.run("rm auto_grade.txt", shell=True, check=True)


if __name__ == "__main__":
    main()
