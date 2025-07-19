#!/usr/bin/env python3

import socket
import subprocess
import sys
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


def run_xdp_program():
    """Run the XDP program on loopback interface"""
    try:
        # Run the XDP program on loopback interface (index 1)
        process = subprocess.Popen(
            ["./entry", "1"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return process
    except Exception as e:
        print(f"Error starting XDP program: {e}")
        return None


def generate_traffic():
    """Generate some network traffic on loopback to trigger XDP program"""
    try:
        # Create a simple UDP socket and send some data to localhost
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"test packet", ("127.0.0.1", 12345))
        sock.close()

        # Create a TCP connection attempt
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect(("127.0.0.1", 12346))
        except:
            pass  # Connection will likely fail, but that's okay
        sock.close()

        time.sleep(0.1)  # Small delay to ensure packets are processed

    except Exception as e:
        print(f"Error generating traffic: {e}")


def check_trace_logs():
    """Check for XDP program output in trace logs"""
    try:
        # Read from trace pipe for a short time
        with open("/sys/kernel/debug/tracing/trace_pipe", "r") as f:
            start_time = time.time()
            logs = []
            while time.time() - start_time < 2:  # Read for 2 seconds
                line = f.readline()
                if line:
                    logs.append(line.strip())
                if len(logs) > 100:  # Limit log collection
                    break

            # Look for our XDP program output
            xdp_logs = [
                log
                for log in logs
                if "IP saddr" in log
                or "IP daddr" in log
                or "TCP packet" in log
                or "UDP packet" in log
            ]
            return len(xdp_logs) > 0

    except PermissionError:
        print("Permission denied reading trace logs. Try running as root.")
        return False
    except Exception as e:
        print(f"Error reading trace logs: {e}")
        return False


def test_xdp_program():
    """Main test function for XDP program"""
    print("Starting XDP program sanity test...")

    # Check if we're in the right directory
    if not Path("./entry").exists():
        print("Error: entry executable not found. Run 'make' first.")
        return False

    # Count programs before
    old_prog_count = count_bpf_programs()
    print(f"BPF programs before: {old_prog_count}")

    # Start XDP program
    xdp_process = run_xdp_program()
    if not xdp_process:
        print("Failed to start XDP program")
        return False

    try:
        # Wait for program to load
        time.sleep(2)

        # Check if new programs were loaded
        new_prog_count = count_bpf_programs()
        print(f"BPF programs after: {new_prog_count}")

        if new_prog_count <= old_prog_count:
            print("Warning: No new BPF programs detected")

        # Generate traffic to trigger XDP
        print("Generating test traffic...")
        for i in range(5):
            generate_traffic()
            time.sleep(0.2)

        # Check for XDP program activity in logs
        print("Checking trace logs for XDP activity...")
        has_activity = check_trace_logs()

        if has_activity:
            print("SUCCESS: XDP program is processing packets")
            return True
        else:
            print("WARNING: No XDP activity detected in logs")
            # Still consider it a success if the program loaded
            return new_prog_count > old_prog_count

    finally:
        # Clean up
        print("Cleaning up...")
        try:
            xdp_process.terminate()
            xdp_process.wait(timeout=5)
        except:
            xdp_process.kill()


def main():
    """Main function"""
    success = test_xdp_program()

    # Write result to grade file
    with open("auto_grade.txt", "w") as f:
        f.write("success" if success else "fail")

    if success:
        print("\nXDP program sanity test PASSED")
        sys.exit(0)
    else:
        print("\nXDP program sanity test FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()

