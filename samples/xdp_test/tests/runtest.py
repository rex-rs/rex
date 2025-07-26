#!/usr/bin/env python3

import socket
import subprocess
import sys
import threading
import time
from pathlib import Path


def count_bpf_programs():
    """Count currently loaded BPF programs"""
    try:
        result = subprocess.run(
            "bpftool prog show",
            capture_output=True,
            shell=True,
            text=True,
        )

        if result.stdout:
            output = result.stdout.strip().split("\n")
            programs = [line for line in output if "name" in line]
            return len(programs)
        else:
            return 0
    except FileNotFoundError:
        print("bpftool is not installed or not found in the PATH.")
        return 0
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0


def generate_traffic():
    """Generate some network traffic on loopback to trigger XDP program"""
    try:
        # Create a UDP socket and send data to localhost
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"test packet", ("127.0.0.1", 12345))
        sock.close()

        # TCP attempt
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect(("127.0.0.1", 12346))
        except (socket.error, ConnectionRefusedError):
            pass  # Connection will likely fail, but that's okay
        sock.close()

        time.sleep(0.1)  # Small delay to ensure packets are processed

    except Exception as e:
        print(f"Error generating traffic: {e}")
        raise e


def get_trace_log():
    """Monitor trace logs for XDP activity"""
    xdp_activity = []
    keywords = ("IP saddr", "IP daddr", "TCP packet", "UDP packet")

    try:
        with open("/sys/kernel/debug/tracing/trace", "r") as f:
            for line in f:
                if any(k in line for k in keywords):
                    s = line.rstrip("\n")
                    xdp_activity.append(s)
                    print(f"XDP trace: {s}")
    except Exception as e:
        print(f"Error reading trace logs: {e}")

    return xdp_activity


def test_xdp_program():
    """Main test function for XDP program"""
    print("Starting XDP program sanity test in QEMU environment...")

    # Check if we're in the right directory
    if not Path("./entry").exists():
        print("Error: entry executable not found. Checking current directory...")
        print(f"Current directory: {Path.cwd()}")
        print(f"Directory contents: {list(Path('.').iterdir())}")
        return False

    # Count programs before
    old_prog_count = count_bpf_programs()
    print(f"BPF programs before: {old_prog_count}")

    # Start XDP program in background
    print("Starting XDP program on loopback interface...")
    xdp_process = None
    try:
        xdp_process = subprocess.Popen(
            ["./entry", "1"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"XDP process started with PID: {xdp_process.pid}")

        # Wait for program to load
        time.sleep(3)

        # Check if new programs were loaded
        new_prog_count = count_bpf_programs()
        print(f"BPF programs after: {new_prog_count}")

        if new_prog_count <= old_prog_count:
            print("Warning: No new BPF programs detected")

        # Generate traffic to trigger XDP
        print("Generating test traffic...")
        for i in range(10):
            generate_traffic()
            time.sleep(0.3)
            if i % 3 == 0:
                print(f"Generated {i+1} traffic bursts...")

        # Wait a bit more for logs to appear
        time.sleep(2)

        # Start get trace logs
        print("Starting trace log retrieving...")
        xdp_activity = get_trace_log()

        # Check results
        program_loaded = new_prog_count > old_prog_count
        has_activity = len(xdp_activity) > 0

        print(f"Program loaded: {program_loaded}")
        print(f"XDP activity detected: {has_activity}")
        print(f"Total XDP log entries: {len(xdp_activity)}")

        if has_activity:
            print("SUCCESS: XDP program is processing packets")
            return True
        else:
            print("FAILURE: XDP program did not load or show activity")
            return False

    except Exception as e:
        print(f"Error during test: {e}")
        return False

    finally:
        # Clean up
        print("Cleaning up...")
        if xdp_process:
            try:
                # Send SIGTERM first
                xdp_process.terminate()
                xdp_process.wait(timeout=3)
                print("XDP process terminated gracefully")
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't respond
                xdp_process.kill()
                print("XDP process force killed")
            except Exception as e:
                print(f"Error during cleanup: {e}")


def main():
    """Main function"""
    success = test_xdp_program()

    # Write result to grade file
    with open("auto_grade.txt", "w") as f:
        f.write("success" if success else "fail")

    print(f"\nXDP program sanity test {'PASSED' if success else 'FAILED'}")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
