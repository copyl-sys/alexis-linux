#!/usr/bin/env python3
"""
Ternary System: TritJS-CISA-Optimized Utility with Kernel Module Interaction (Python Version)
-----------------------------------------------------------------------------------------------
This program implements an interactive ternary calculator with advanced arithmetic operations,
a built-in help system, and an interface to interact with the Axion kernel module via IOCTL calls.
Our IOCTL constants have been updated to match our unified kernel source definitions.

IMPORTANT:
  - The Axion kernel module must be loaded, and its device file (default: /dev/axion_opt) must exist.
  - IOCTL command values are computed using Linux's _IOC macros and now align with our source.
  
Features:
  • Ternary arithmetic: conversion, addition, subtraction, multiplication, division, factorial, exponentiation.
  • Interactive help (type "help" for a full command list).
  • Module interaction:
      - Get/set register, load TBIN binary, execute a TBIN step, retrieve TBIN state.
      - Package management and natural language commands.
  • Uses Python's fcntl and struct modules to perform IOCTL calls.
  
Usage:
  - Run: ./tritjs_module_utility.py
  - Type "help" at the prompt for details.
"""

import os
import sys
import fcntl
import struct
import math

# -------------------------------------------------------------------
# Ternary Conversion Functions
# -------------------------------------------------------------------
def ternary_to_int(ternary_str):
    """
    Convert an unbalanced ternary string (base-3) to its integer value.
    """
    s = ternary_str.strip()
    if not s:
        raise ValueError("Empty string is not a valid ternary number.")
    negative = s[0] == '-'
    if negative:
        s = s[1:]
    if any(ch not in '012' for ch in s):
        raise ValueError("Invalid ternary digit found. Only 0, 1, 2 are allowed.")
    return -int(s, 3) if negative else int(s, 3)

def int_to_ternary(n):
    """
    Convert an integer to its unbalanced ternary (base-3) string representation.
    """
    if n == 0:
        return "0"
    negative = n < 0
    n = abs(n)
    digits = []
    while n:
        digits.append(str(n % 3))
        n //= 3
    digits.reverse()
    result = "".join(digits)
    return "-" + result if negative else result

# -------------------------------------------------------------------
# Arithmetic Operations
# -------------------------------------------------------------------
def add_ternary(a, b):
    return int_to_ternary(ternary_to_int(a) + ternary_to_int(b))

def subtract_ternary(a, b):
    return int_to_ternary(ternary_to_int(a) - ternary_to_int(b))

def multiply_ternary(a, b):
    return int_to_ternary(ternary_to_int(a) * ternary_to_int(b))

def divide_ternary(a, b):
    numerator = ternary_to_int(a)
    denominator = ternary_to_int(b)
    if denominator == 0:
        raise ZeroDivisionError("Division by zero is not allowed.")
    quotient, remainder = divmod(numerator, denominator)
    return int_to_ternary(quotient), int_to_ternary(remainder)

def factorial_ternary(a):
    n = ternary_to_int(a)
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers.")
    return int_to_ternary(math.factorial(n))

def power_ternary(base, exponent):
    exp_val = ternary_to_int(exponent)
    if exp_val < 0:
        raise ValueError("Negative exponents are not supported.")
    return int_to_ternary(pow(ternary_to_int(base), exp_val))

# -------------------------------------------------------------------
# Axion Module Interface using IOCTL
# -------------------------------------------------------------------
class AxionModuleInterface:
    """
    Provides an interface to the Axion kernel module using IOCTL calls.
    Adjusted IOCTL constants now align with our kernel module's definitions.
    Device file is assumed to be "/dev/axion_opt".
    """

    # Updated IOCTL command constants computed from our unified source:
    IOCTL_SET_REGISTER      = 0x40086101  # _IOW('a', 1, uint64_t)
    IOCTL_GET_REGISTER      = 0x80086102  # _IOR('a', 2, uint64_t)
    IOCTL_TBIN_LOAD         = 0x40016103  # _IOW('a', 3, struct tbin_header) where sizeof(header)==16
    IOCTL_TBIN_STEP         = 0x6104      # _IO('a', 4) with no size (0 bytes)
    IOCTL_TBIN_GET_STATE    = 0x802F6105  # _IOR('a', 5, struct tbin_state) where size==47 bytes
    IOCTL_GET_SUGGESTION    = 0x81006106  # _IOR('a', 6, char[256])
    IOCTL_INSTALL_PKG       = 0x40206107  # _IOW('a', 7, char[32])
    IOCTL_UPDATE_PKG        = 0x40206108  # _IOW('a', 8, char[32])
    IOCTL_SET_BINARY        = 0x40046109  # _IOW('a', 9, int)
    IOCTL_ROLLBACK          = 0x4020610A  # _IOW('a', 10, char[32])
    IOCTL_NL_COMMAND        = 0x4100610B  # _IOW('a', 11, char[256])
    IOCTL_GET_PERF_FEEDBACK = 0x8004610C  # _IOR('a', 12, int)
    
    def __init__(self, device_path="/dev/axion_opt"):
        """
        Open the device file.
        """
        try:
            self.fd = os.open(device_path, os.O_RDWR)
        except Exception as e:
            print(f"Error opening {device_path}: {e}")
            self.fd = None
    
    def close(self):
        """
        Close the device file.
        """
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
    
    def get_register(self):
        """
        Get the module's register (uint64_t).
        """
        if self.fd is None:
            return None
        buf = bytearray(8)
        fcntl.ioctl(self.fd, self.IOCTL_GET_REGISTER, buf, True)
        return struct.unpack("Q", buf)[0]
    
    def set_register(self, value):
        """
        Set the module's register to 'value' (uint64_t).
        """
        if self.fd is None:
            return
        buf = struct.pack("Q", value)
        fcntl.ioctl(self.fd, self.IOCTL_SET_REGISTER, buf)
    
    def tbin_load(self, tbin_header):
        """
        Load a TBIN binary. tbin_header is a tuple of 4 integers:
        (magic, entry_point, code_size, data_size).
        """
        if self.fd is None:
            return
        buf = struct.pack("IIII", *tbin_header)
        fcntl.ioctl(self.fd, self.IOCTL_TBIN_LOAD, buf)
    
    def tbin_step(self):
        """
        Execute one step of TBIN execution.
        """
        if self.fd is None:
            return
        fcntl.ioctl(self.fd, self.IOCTL_TBIN_STEP)
    
    def get_tbin_state(self):
        """
        Get the current TBIN state.
        Assumes a structure of 47 bytes: 3 bytes for registers, 32 bytes for memory,
        4 bytes for ip, 4 bytes for code_size, and 4 bytes for running.
        """
        if self.fd is None:
            return None
        buf = bytearray(47)
        fcntl.ioctl(self.fd, self.IOCTL_TBIN_GET_STATE, buf, True)
        reg = struct.unpack("3b", buf[0:3])
        memory = list(buf[3:35])
        ip, code_size, running = struct.unpack("III", buf[35:47])
        return {"reg": reg, "memory": memory, "ip": ip, "code_size": code_size, "running": running}
    
    def get_suggestion(self):
        """
        Retrieve the AI suggestion string from the module.
        """
        if self.fd is None:
            return ""
        buf = bytearray(256)
        fcntl.ioctl(self.fd, self.IOCTL_GET_SUGGESTION, buf, True)
        return buf.split(b'\x00', 1)[0].decode('utf-8')
    
    def install_pkg(self, pkg_name):
        """
        Send an install package command for pkg_name (max 32 bytes).
        """
        if self.fd is None:
            return
        buf = pkg_name.encode('utf-8').ljust(32, b'\x00')
        fcntl.ioctl(self.fd, self.IOCTL_INSTALL_PKG, buf)
    
    def update_pkg(self, pkg_name):
        """
        Send an update package command for pkg_name.
        """
        if self.fd is None:
            return
        buf = pkg_name.encode('utf-8').ljust(32, b'\x00')
        fcntl.ioctl(self.fd, self.IOCTL_UPDATE_PKG, buf)
    
    def rollback_pkg(self, pkg_name):
        """
        Send a rollback package command for pkg_name.
        """
        if self.fd is None:
            return
        buf = pkg_name.encode('utf-8').ljust(32, b'\x00')
        fcntl.ioctl(self.fd, self.IOCTL_ROLLBACK, buf)
    
    def nl_command(self, cmd):
        """
        Send a natural language command to the module.
        """
        if self.fd is None:
            return
        buf = cmd.encode('utf-8').ljust(256, b'\x00')
        fcntl.ioctl(self.fd, self.IOCTL_NL_COMMAND, buf)
    
    def get_perf_feedback(self):
        """
        Retrieve the performance feedback metric (uint32_t).
        """
        if self.fd is None:
            return None
        buf = bytearray(4)
        fcntl.ioctl(self.fd, self.IOCTL_GET_PERF_FEEDBACK, buf, True)
        return struct.unpack("I", buf)[0]

# -------------------------------------------------------------------
# Help System and Command Processing
# -------------------------------------------------------------------
def print_help():
    help_msg = """
--- TritJS-CISA-Optimized Utility Help ---
Arithmetic Commands:
  to_int <ternary>         : Convert a ternary string to an integer.
  to_ternary <int>         : Convert an integer to a ternary string.
  add <a> <b>              : Add two ternary numbers.
  sub <a> <b>              : Subtract second number from first.
  mul <a> <b>              : Multiply two ternary numbers.
  div <a> <b>              : Divide first by second (quotient and remainder).
  fact <a>               : Compute factorial of a ternary number.
  pow <base> <exp>         : Compute base raised to exponent.
  
Module Commands (requires Axion module):
  mod_get_reg            : Get the module's register value.
  mod_set_reg <value>    : Set the module's register to <value>.
  mod_tbin_load <magic> <entry> <code_size> <data_size>
                         : Load a TBIN binary into the module.
  mod_tbin_step          : Execute one TBIN step.
  mod_get_state          : Retrieve current TBIN execution state.
  mod_get_suggest        : Get AI-generated suggestion from the module.
  mod_install <pkg>      : Install a package.
  mod_update <pkg>       : Update a package.
  mod_rollback <pkg>     : Rollback a package.
  mod_nl <command>       : Send a natural language command to the module.
  mod_get_perf           : Get performance feedback metric.
  
General:
  help                   : Display this help message.
  exit                   : Exit the utility.
------------------------------------------------------
"""
    print(help_msg)

def process_command(cmd_line, axion_iface):
    tokens = cmd_line.strip().split()
    if not tokens:
        return
    cmd = tokens[0].lower()
    try:
        if cmd == "help":
            print_help()
        elif cmd == "exit":
            sys.exit(0)
        elif cmd == "to_int" and len(tokens) == 2:
            print("Integer value:", ternary_to_int(tokens[1]))
        elif cmd == "to_ternary" and len(tokens) == 2:
            print("Ternary representation:", int_to_ternary(int(tokens[1])))
        elif cmd == "add" and len(tokens) == 3:
            print("Result:", add_ternary(tokens[1], tokens[2]))
        elif cmd == "sub" and len(tokens) == 3:
            print("Result:", subtract_ternary(tokens[1], tokens[2]))
        elif cmd == "mul" and len(tokens) == 3:
            print("Result:", multiply_ternary(tokens[1], tokens[2]))
        elif cmd == "div" and len(tokens) == 3:
            q, r = divide_ternary(tokens[1], tokens[2])
            print("Quotient:", q)
            print("Remainder:", r)
        elif cmd == "fact" and len(tokens) == 2:
            print("Factorial:", factorial_ternary(tokens[1]))
        elif cmd == "pow" and len(tokens) == 3:
            print("Result:", power_ternary(tokens[1], tokens[2]))
        # Module commands:
        elif cmd == "mod_get_reg":
            reg_val = axion_iface.get_register()
            print("Module Register:", reg_val)
        elif cmd == "mod_set_reg" and len(tokens) == 2:
            val = int(tokens[1])
            axion_iface.set_register(val)
            print("Module register set to", val)
        elif cmd == "mod_tbin_load" and len(tokens) == 5:
            hdr = tuple(int(x) for x in tokens[1:5])
            axion_iface.tbin_load(hdr)
            print("TBIN loaded into module.")
        elif cmd == "mod_tbin_step":
            axion_iface.tbin_step()
            print("Executed one TBIN step.")
        elif cmd == "mod_get_state":
            state_info = axion_iface.get_tbin_state()
            print("TBIN State:", state_info)
        elif cmd == "mod_get_suggest":
            suggestion = axion_iface.get_suggestion()
            print("Module Suggestion:", suggestion)
        elif cmd == "mod_install" and len(tokens) == 2:
            axion_iface.install_pkg(tokens[1])
            print(f"Package '{tokens[1]}' installation command sent.")
        elif cmd == "mod_update" and len(tokens) == 2:
            axion_iface.update_pkg(tokens[1])
            print(f"Package '{tokens[1]}' update command sent.")
        elif cmd == "mod_rollback" and len(tokens) == 2:
            axion_iface.rollback_pkg(tokens[1])
            print(f"Package '{tokens[1]}' rollback command sent.")
        elif cmd == "mod_nl" and len(tokens) >= 2:
            nl_cmd = " ".join(tokens[1:])
            axion_iface.nl_command(nl_cmd)
            print("Natural language command sent to module.")
        elif cmd == "mod_get_perf":
            perf = axion_iface.get_perf_feedback()
            print("Module Performance Feedback:", perf)
        else:
            print("Unknown command. Type 'help' for available commands.")
    except Exception as e:
        print("Error processing command:", e)

# -------------------------------------------------------------------
# Main Interactive Loop
# -------------------------------------------------------------------
def main():
    print("TritJS-CISA-Optimized Ternary Calculator with Module Interaction (Python Version)")
    print("Type 'help' for a list of commands, or 'exit' to quit.")
    
    # Initialize the module interface
    axion_iface = AxionModuleInterface()
    if axion_iface.fd is None:
        print("Warning: Could not open Axion module device. Module commands will not work.")

    while True:
        try:
            cmd_line = input("> ")
            process_command(cmd_line, axion_iface)
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            break

    axion_iface.close()

if __name__ == "__main__":
    main()
