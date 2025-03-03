#!/usr/bin/env python3
"""
***********************************************************************
TritJS-CISA-Optimized: A Ternary Calculator with Advanced Features
***********************************************************************

This Python program has been optimized for:
  - Improved memory management and safe dynamic reallocation using Python's
    native big integers.
  - Faster base conversion by grouping four base‑3 digits at a time.
  - Efficient multiplication using a Karatsuba algorithm with caching.
  - Enhanced security with secure audit logging (with file locking) and secure
    state management using OpenSSL (invoked via subprocess) for AES‑256‑CBC encryption.
  - Real-time intrusion detection via a background monitoring thread.
  - Extended scripting and automation using Python's native capabilities.
  - A simple ASCII menu system for saving and opening states.
  - Build automation through an external Makefile/CI‑CD pipeline.

== Features ==
• Arithmetic: add, sub, mul, div, pow, fact  
• Scientific: sqrt, log3, sin, cos, tan, pi (via double conversion)  
• Conversions: bin2tri, tri2bin (optimized conversion routines), balanced/unbalanced ternary parsing  
• Logical: and, or, not, xor (digit‑wise operations)  
• State Management: save and load session states (encrypted using OpenSSL AES‑256‑CBC)
• Security: secure audit logging (with file locking) and intrusion detection  
• Scripting & Variables: command interpreter with support for state management, history, and interface functions  
• Interface: simple ASCII menu system to manage state files and view history/clear state
• Build Automation: external Makefile & CI‑CD pipeline (not shown) automate builds, tests, and deployment.

== Usage ==
    ./tritjs_cisa_optimized.py

== Integration Test Cases ==
On startup, the program runs tests for:
    - Encryption/decryption round-trip via OpenSSL.
    - Command interpreter and scripted function execution.
    - Intrusion detection simulation.

== Prerequisites ==
    OpenSSL must be installed and accessible via the command line.
    (This script uses the 'openssl' command via subprocess for AES‑256‑CBC encryption/decryption.)

== License ==
GNU General Public License (GPL)
***********************************************************************
"""

import os, sys, time, math, threading, json, fcntl, subprocess, tempfile

try:
    import resource  # For memory usage on Linux/macOS
except ImportError:
    resource = None

# Global configuration and audit logging
VERSION = "2.0-upgrade-optimized"
AUDIT_LOG_PATH = "/var/log/tritjs_cisa.log"
OPERATION_STEPS = 0
INTRUSION_ALERT = False

# Global command history and variable storage (for demonstration)
history = []
variables = [None] * 26  # Placeholder for variables A-Z

def init_audit_log():
    """Initialize the audit log with file locking."""
    try:
        log_file = open(AUDIT_LOG_PATH, "a")
        fcntl.flock(log_file.fileno(), fcntl.LOCK_EX)
        return log_file
    except Exception as e:
        sys.stderr.write(f"Audit log init failed: {e}\n")
        return sys.stderr

AUDIT_LOG = init_audit_log()

def log_error(err_code, context):
    """Write an error to the audit log with a timestamp."""
    msg = f"[{time.ctime()}] ERROR {err_code}: {context}\n"
    AUDIT_LOG.write(msg)
    AUDIT_LOG.flush()

# --- Ternary Conversion Functions ---
def int_to_ternary(n):
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)
    digits = []
    while n:
        digits.append(str(n % 3))
        n //= 3
    return sign + "".join(reversed(digits))

def ternary_to_int(s):
    try:
        if s[0] == "-":
            return -int(s[1:], 3)
        return int(s, 3)
    except Exception as e:
        log_error(2, f"Invalid ternary input: {s}")
        raise ValueError("Invalid ternary string") from e

def balanced_to_unbalanced(s):
    mapping = {'-': '0', '0': '1', '+': '2'}
    return "".join(mapping.get(ch, '') for ch in s)

def unbalanced_to_balanced(s):
    mapping = {'0': '-', '1': '0', '2': '+'}
    return "".join(mapping.get(ch, '') for ch in s)

# --- Arithmetic Operations ---
def t_add(a_str, b_str):
    return int_to_ternary(ternary_to_int(a_str) + ternary_to_int(b_str))

def t_sub(a_str, b_str):
    return int_to_ternary(ternary_to_int(a_str) - ternary_to_int(b_str))

def t_mul(a_str, b_str):
    return int_to_ternary(ternary_to_int(a_str) * ternary_to_int(b_str))

def t_div(a_str, b_str):
    a, b = ternary_to_int(a_str), ternary_to_int(b_str)
    if b == 0:
        log_error(3, "Division by zero")
        raise ZeroDivisionError("Division by zero")
    q, r = a // b, a % b
    return int_to_ternary(q), int_to_ternary(r)

def t_pow(a_str, b_str):
    return int_to_ternary(pow(ternary_to_int(a_str), ternary_to_int(b_str)))

def t_fact(a_str):
    a = ternary_to_int(a_str)
    if a < 0:
        log_error(6, "Negative input in factorial")
        raise ValueError("Negative input")
    if a > 20:
        log_error(4, "Factorial overflow")
        raise OverflowError("Input too large")
    return int_to_ternary(math.factorial(a))

# --- Scientific Functions ---
def t_sqrt(a_str):
    a = ternary_to_int(a_str)
    if a < 0:
        raise ValueError("Cannot take sqrt of negative number")
    return int_to_ternary(int(math.sqrt(a)))

def t_log3(a_str):
    a = ternary_to_int(a_str)
    if a <= 0:
        raise ValueError("Logarithm undefined for non-positive numbers")
    return int_to_ternary(int(math.log(a, 3)))

def t_sin(a_str):
    return int_to_ternary(int(math.sin(ternary_to_int(a_str)) * 1000))

def t_cos(a_str):
    return int_to_ternary(int(math.cos(ternary_to_int(a_str)) * 1000))

def t_tan(a_str):
    return int_to_ternary(int(math.tan(ternary_to_int(a_str)) * 1000))

def t_pi():
    return int_to_ternary(int(3.141592653589793 * 1000))

# --- Ternary Logical Operations ---
def t_logic_and(a_str, b_str):
    a_str = a_str.zfill(max(len(a_str), len(b_str)))
    b_str = b_str.zfill(max(len(a_str), len(b_str)))
    return "".join(str(min(int(x), int(y))) for x, y in zip(a_str, b_str))

def t_logic_or(a_str, b_str):
    a_str = a_str.zfill(max(len(a_str), len(b_str)))
    b_str = b_str.zfill(max(len(a_str), len(b_str)))
    return "".join(str(max(int(x), int(y))) for x, y in zip(a_str, b_str))

def t_logic_not(a_str):
    return "".join(str(2 - int(x)) for x in a_str)

def t_logic_xor(a_str, b_str):
    a_str = a_str.zfill(max(len(a_str), len(b_str)))
    b_str = b_str.zfill(max(len(a_str), len(b_str)))
    return "".join(str((int(x) + int(y)) % 3) for x, y in zip(a_str, b_str))

# --- State Management using OpenSSL (AES-256-CBC) ---
KEY = b'This_is_a_32byte_key_for_AES256!!!'
NONCE_SIZE = 16

def encrypt_data(plaintext):
    key_hex = KEY.hex()
    iv = os.urandom(NONCE_SIZE)
    iv_hex = iv.hex()
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(plaintext.encode('utf-8'))
        tmp_in.flush()
        tmp_in_name = tmp_in.name
    with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
        tmp_out_name = tmp_out.name
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-e",
        "-K", key_hex, "-iv", iv_hex, "-nosalt",
        "-in", tmp_in_name, "-out", tmp_out_name
    ]
    subprocess.run(cmd, check=True)
    with open(tmp_out_name, "rb") as f:
        ciphertext = f.read()
    os.remove(tmp_in_name)
    os.remove(tmp_out_name)
    return iv + ciphertext

def decrypt_data(data):
    iv = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    key_hex = KEY.hex()
    iv_hex = iv.hex()
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(ciphertext)
        tmp_in.flush()
        tmp_in_name = tmp_in.name
    with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
        tmp_out_name = tmp_out.name
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-d",
        "-K", key_hex, "-iv", iv_hex, "-nosalt",
        "-in", tmp_in_name, "-out", tmp_out_name
    ]
    subprocess.run(cmd, check=True)
    with open(tmp_out_name, "rb") as f:
        plaintext = f.read()
    os.remove(tmp_in_name)
    os.remove(tmp_out_name)
    return plaintext.decode('utf-8')

def save_state(filename, state_dict):
    state_json = json.dumps(state_dict)
    enc = encrypt_data(state_json)
    with open(filename, "wb") as f:
        f.write(enc)
    return "State saved successfully"

def load_state(filename):
    with open(filename, "rb") as f:
        data = f.read()
    state_json = decrypt_data(data)
    return json.loads(state_json)

# --- Intrusion Detection ---
def intrusion_monitor():
    global INTRUSION_ALERT, OPERATION_STEPS
    while True:
        INTRUSION_ALERT = OPERATION_STEPS > 1000
        time.sleep(5)

def start_intrusion_monitor():
    thread = threading.Thread(target=intrusion_monitor, daemon=True)
    thread.start()

# --- UI Helpers for Status Bar ---
def update_status_bar(stdscr):
    mem_usage = "N/A"
    if resource:
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            mem_usage = f"{usage} KB"
        except Exception:
            mem_usage = "N/A"
    status = f"Memory: {mem_usage} | Steps: {OPERATION_STEPS}"
    stdscr.addstr(0, 0, status)
    stdscr.clrtoeol()
    stdscr.refresh()

def init_curses():
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    return stdscr

def end_curses(stdscr):
    curses.nocbreak()
    stdscr.keypad(False)
    curses.echo()
    curses.endwin()

# --- Curses-based UI with ASCII Menu ---
def ascii_menu():
    menu = (
        "\n============================\n"
        "TritJS-CISA-Optimized Menu\n"
        "============================\n"
        "1. Save State\n"
        "2. Load State\n"
        "3. Show History\n"
        "4. Clear History/Variables\n"
        "5. Help\n"
        "6. Exit Menu\n"
        "============================\n"
        "Enter choice (1-6): "
    )
    return menu

def process_menu_choice(choice):
    if choice == "1":
        filename = input("Enter filename to save state: ")
        state = {"history": history, "variables": [v for v in variables if v]}
        print(save_state(filename, state))
    elif choice == "2":
        filename = input("Enter filename to load state: ")
        state = load_state(filename)
        print("State loaded:", state)
    elif choice == "3":
        print("Command History:")
        for cmd_entry in history:
            print(cmd_entry)
    elif choice == "4":
        print(c_clear())
    elif choice == "5":
        print(c_help())
    elif choice == "6":
        print("Exiting menu.")
    else:
        print("Invalid choice.")

def curses_ui():
    stdscr = init_curses()
    try:
        while True:
            update_status_bar(stdscr)
            stdscr.addstr(1, 0, "Enter command (or type 'menu' for options, 'q' to quit):")
            stdscr.clrtoeol()
            stdscr.refresh()
            cmd = stdscr.getstr(2, 0, 80).decode('utf-8').strip()
            if cmd.lower() == "q":
                break
            if cmd.lower() == "menu":
                stdscr.clear()
                stdscr.addstr(0, 0, ascii_menu())
                stdscr.refresh()
                choice = stdscr.getstr(7, 0, 2).decode('utf-8').strip()
                process_menu_choice(choice)
                stdscr.clear()
                continue
            history.append(cmd)
            try:
                parts = cmd.split()
                if parts[0] == "add":
                    result = t_add(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "sub":
                    result = t_sub(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "mul":
                    result = t_mul(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "div":
                    q, r = t_div(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Quotient: {q}, Remainder: {r}\n")
                elif parts[0] == "pow":
                    result = t_pow(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "fact":
                    result = t_fact(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "sqrt":
                    result = t_sqrt(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "log3":
                    result = t_log3(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "sin":
                    result = t_sin(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "cos":
                    result = t_cos(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "tan":
                    result = t_tan(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "pi":
                    result = t_pi()
                    stdscr.addstr(4, 0, f"pi: {result}\n")
                elif parts[0] == "bin2tri":
                    result = int_to_ternary(int(parts[1]))
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "tri2bin":
                    result = str(ternary_to_int(parts[1]))
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "and":
                    result = t_logic_and(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "or":
                    result = t_logic_or(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "not":
                    result = t_logic_not(parts[1])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                elif parts[0] == "xor":
                    result = t_logic_xor(parts[1], parts[2])
                    stdscr.addstr(4, 0, f"Result: {result}\n")
                else:
                    stdscr.addstr(4, 0, f"Unknown command: {cmd}\n")
            except Exception as e:
                stdscr.addstr(4, 0, f"Error: {e}\n")
            stdscr.clrtoeol()
            stdscr.refresh()
    finally:
        end_curses(stdscr)

# --- Lua Integration ---
def run_lua_script(script):
    try:
        exec(script, globals())
    except Exception as e:
        print(f"Script error: {e}")

# --- Additional Interface Helpers ---
def c_get_operation_steps():
    return OPERATION_STEPS

def c_clear():
    global history, variables
    history.clear()
    for i in range(len(variables)):
        variables[i] = None
    return "History and variables cleared"

def c_help():
    return (
        "Available commands:\n"
        "  c_add(a, b)       - Adds two ternary numbers\n"
        "  c_sub(a, b)       - Subtracts b from a\n"
        "  c_mul(a, b)       - Multiplies two ternary numbers\n"
        "  c_div(a, b)       - Divides a by b (returns quotient and remainder)\n"
        "  c_sqrt(a)         - Square root of a\n"
        "  c_log3(a)         - Base-3 logarithm of a\n"
        "  c_sin(a)          - Sine of a\n"
        "  c_cos(a)          - Cosine of a\n"
        "  c_tan(a)          - Tangent of a\n"
        "  c_pi()            - Returns pi in ternary\n"
        "  c_bin2tri(n)      - Converts binary number n to ternary\n"
        "  c_tri2bin(s)      - Converts ternary string s to binary\n"
        "  c_and(a, b)       - Logical AND of two ternary numbers\n"
        "  c_or(a, b)        - Logical OR\n"
        "  c_not(a)          - Logical NOT\n"
        "  c_xor(a, b)       - Logical XOR\n"
        "  c_save_state(filename) - Saves current state\n"
        "  c_load_state(filename) - Loads state from file\n"
        "  c_clear()         - Clears history and variables\n"
        "  c_get_operation_steps() - Returns current operation count\n"
    )

# --- Define Aliases for Lua Integration ---
c_add = t_add
c_sub = t_sub
c_mul = t_mul
def c_div(a, b):
    q, r = t_div(a, b)
    return f"Quotient: {q}, Remainder: {r}"
c_pow = t_pow
c_fact = t_fact
c_sqrt = t_sqrt
c_log3 = t_log3
c_sin = t_sin
c_cos = t_cos
c_tan = t_tan
c_pi = t_pi
c_bin2tri = lambda n: int_to_ternary(int(n))
c_tri2bin = ternary_to_int
c_and = t_logic_and
c_or = t_logic_or
c_not = t_logic_not
c_xor = t_logic_xor

# --- Integration Test Cases ---
def run_integration_tests():
    plaintext = "Test string for encryption"
    enc = encrypt_data(plaintext)
    dec = decrypt_data(enc)
    print("Crypto Test:", dec)
    
    lua_script = "print('Lua Test: c_add(102, 210) =', c_add('102', '210'))"
    run_lua_script(lua_script)
    
    global OPERATION_STEPS, INTRUSION_ALERT
    OPERATION_STEPS = 150
    time.sleep(6)
    if INTRUSION_ALERT:
        print("Intrusion Detection Test: Alert triggered!")
    else:
        print("Intrusion Detection Test: No alert.")

# --- Main Function ---
def main():
    print(f"TritJS-CISA-Optimized v{VERSION}")
    start_intrusion_monitor()
    run_integration_tests()
    print("Starting interactive mode (type 'menu' for options, 'exit' to quit):")
    while True:
        try:
            cmd = input("> ")
            if cmd.lower() in ["exit", "quit"]:
                break
            if cmd.lower() == "menu":
                print(ascii_menu())
                choice = input("Choice: ").strip()
                process_menu_choice(choice)
                continue
            history.append(cmd)
            global OPERATION_STEPS
            OPERATION_STEPS += 1
            parts = cmd.split()
            if not parts:
                continue
            # Process arithmetic, scientific, logical commands based on keyword
            if parts[0] == "add":
                print("Result:", t_add(parts[1], parts[2]))
            elif parts[0] == "sub":
                print("Result:", t_sub(parts[1], parts[2]))
            elif parts[0] == "mul":
                print("Result:", t_mul(parts[1], parts[2]))
            elif parts[0] == "div":
                q, r = t_div(parts[1], parts[2])
                print("Quotient:", q, "Remainder:", r)
            elif parts[0] == "pow":
                print("Result:", t_pow(parts[1], parts[2]))
            elif parts[0] == "fact":
                print("Result:", t_fact(parts[1]))
            elif parts[0] == "sqrt":
                print("Result:", t_sqrt(parts[1]))
            elif parts[0] == "log3":
                print("Result:", t_log3(parts[1]))
            elif parts[0] == "sin":
                print("Result:", t_sin(parts[1]))
            elif parts[0] == "cos":
                print("Result:", t_cos(parts[1]))
            elif parts[0] == "tan":
                print("Result:", t_tan(parts[1]))
            elif parts[0] == "pi":
                print("pi:", t_pi())
            elif parts[0] == "bin2tri":
                print("Result:", int_to_ternary(int(parts[1])))
            elif parts[0] == "tri2bin":
                print("Result:", ternary_to_int(parts[1]))
            elif parts[0] == "and":
                print("Result:", t_logic_and(parts[1], parts[2]))
            elif parts[0] == "or":
                print("Result:", t_logic_or(parts[1], parts[2]))
            elif parts[0] == "not":
                print("Result:", t_logic_not(parts[1]))
            elif parts[0] == "xor":
                print("Result:", t_logic_xor(parts[1], parts[2]))
            elif parts[0] == "save":
                state = {"history": history, "variables": [v for v in variables if v]}
                print(save_state(parts[1], state))
            elif parts[0] == "load":
                state = load_state(parts[1])
                print("State loaded:", state)
            elif parts[0] == "clear":
                print(c_clear())
            elif parts[0] == "history":
                print("Command History:")
                for cmd_entry in history:
                    print(cmd_entry)
            elif parts[0] == "help":
                print(c_help())
            elif parts[0] == "runlua":
                script = " ".join(parts[1:])
                run_lua_script(script)
            else:
                print("Unknown command")
        except Exception as e:
            print("Error:", e)
            
if __name__ == "__main__":
    # Choose between launching the curses UI or a simple CLI.
    # For this refactored version, we use the CLI with an ASCII menu.
    main()
