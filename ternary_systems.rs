/*=====================================================================
 Ternary Systems B02-RS: Cross-Platform Unified Ternary System in Rust
 Enhanced Version with Full TritJS-CISA Functionality
----------------------------------------------------------------------
 This Rust application provides:
 - Ternary arithmetic expression evaluation,
 - A Tower of Hanoi solver,
 - Comprehensive matrix operations (creation, setting values, addition,
   multiplication, serialization, and deserialization),
 - Discrete math-enhanced opcode encoding and validation.
 The interactive mode now supports all these features with an expanded help menu.
=====================================================================*/

/*=====================================================================
 Rust Main Module: main.rs
 This file implements all core functionality with detailed inline comments.
=====================================================================*/
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::env;
use std::process;

/// Enum representing errors during ternary arithmetic expression parsing.
#[derive(Debug)]
enum ParseError {
    InvalidDigit(char),
    UnexpectedChar(char),
    MissingClosingParen,
    DivisionByZero,
    EmptyExpression,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseError::InvalidDigit(c) => write!(f, "Invalid digit '{}': expected 0, 1, or 2", c),
            ParseError::UnexpectedChar(c) => write!(f, "Unexpected character '{}'", c),
            ParseError::MissingClosingParen => write!(f, "Missing closing parenthesis"),
            ParseError::DivisionByZero => write!(f, "Division by zero"),
            ParseError::EmptyExpression => write!(f, "Expression is empty"),
        }
    }
}

/// Struct for representing matrices in our ternary system.
#[derive(Debug)]
struct TMatrix {
    rows: usize,
    cols: usize,
    data: Vec<Vec<i32>>,
}

impl TMatrix {
    /// Creates a new matrix with given dimensions, initializing all elements to zero.
    fn new(rows: usize, cols: usize) -> TMatrix {
        let data = vec![vec![0; cols]; rows];
        TMatrix { rows, cols, data }
    }

    /// Adds two matrices; returns an error if dimensions do not match.
    fn add(&self, other: &TMatrix) -> Result<TMatrix, String> {
        if self.rows != other.rows || self.cols != other.cols {
            return Err("Matrix dimensions mismatch for addition".to_string());
        }
        let mut result = TMatrix::new(self.rows, self.cols);
        for i in 0..self.rows {
            for j in 0..self.cols {
                result.data[i][j] = self.data[i][j] + other.data[i][j];
            }
        }
        Ok(result)
    }

    /// Multiplies two matrices; returns an error if dimensions are incompatible.
    fn multiply(&self, other: &TMatrix) -> Result<TMatrix, String> {
        if self.cols != other.rows {
            return Err("Matrix dimensions mismatch for multiplication".to_string());
        }
        let mut result = TMatrix::new(self.rows, other.cols);
        for i in 0..self.rows {
            for j in 0..other.cols {
                let mut sum = 0;
                for k in 0..self.cols {
                    sum += self.data[i][k] * other.data[k][j];
                }
                result.data[i][j] = sum;
            }
        }
        Ok(result)
    }

    /// Serializes the matrix to a file in ternary format.
    fn serialize(&self, filename: &str) -> io::Result<()> {
        let mut file = File::create(filename)?;
        writeln!(file, "{} {}", self.rows, self.cols)?;
        for i in 0..self.rows {
            for j in 0..self.cols {
                let ternary = int_to_ternary(self.data[i][j]);
                write!(file, "{} ", ternary)?;
            }
            writeln!(file)?;
        }
        Ok(())
    }

    /// Deserializes a matrix from a file.
    fn deserialize(filename: &str) -> io::Result<TMatrix> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        // Read dimensions from the first line.
        let first_line = lines.next().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty file"))??;
        let dims: Vec<usize> = first_line.split_whitespace()
            .map(|s| s.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)))
            .collect::<Result<_, _>>()?;
        if dims.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid dimensions"));
        }
        let rows = dims[0];
        let cols = dims[1];

        // Read matrix data.
        let mut data = Vec::with_capacity(rows);
        for line in lines.take(rows) {
            let line = line?;
            let row: Vec<i32> = line.split_whitespace()
                .map(|s| parse_ternary(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())))
                .collect::<Result<_, _>>()?;
            if row.len() != cols {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Row length mismatch"));
            }
            data.push(row);
        }
        if data.len() != rows {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Insufficient rows"));
        }

        Ok(TMatrix { rows, cols, data })
    }
}

/// Evaluates a ternary arithmetic expression given as a string.
fn tritjs_eval_expression(expr: &str) -> Result<i32, ParseError> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err(ParseError::EmptyExpression);
    }
    let chars: Vec<char> = expr.chars().collect();
    let mut pos = 0;
    let result = parse_expr(&chars, &mut pos)?;
    // Ensure no extra characters remain.
    while pos < chars.len() {
        if !chars[pos].is_whitespace() {
            return Err(ParseError::UnexpectedChar(chars[pos]));
        }
        pos += 1;
    }
    Ok(result)
}

/// Parses an expression handling '+' and '-' operators.
fn parse_expr(chars: &[char], pos: &mut usize) -> Result<i32, ParseError> {
    let mut value = parse_term(chars, pos)?;
    while *pos < chars.len() {
        skip_whitespace(chars, pos);
        match chars.get(*pos) {
            Some('+') => {
                *pos += 1;
                value += parse_term(chars, pos)?;
            }
            Some('-') => {
                *pos += 1;
                value -= parse_term(chars, pos)?;
            }
            _ => break,
        }
    }
    Ok(value)
}

/// Parses a term handling '*' and '/' operators.
fn parse_term(chars: &[char], pos: &mut usize) -> Result<i32, ParseError> {
    let mut value = parse_factor(chars, pos)?;
    while *pos < chars.len() {
        skip_whitespace(chars, pos);
        match chars.get(*pos) {
            Some('*') => {
                *pos += 1;
                value *= parse_factor(chars, pos)?;
            }
            Some('/') => {
                *pos += 1;
                let next = parse_factor(chars, pos)?;
                if next == 0 {
                    return Err(ParseError::DivisionByZero);
                }
                value /= next;
            }
            _ => break,
        }
    }
    Ok(value)
}

/// Parses a factor, which can be either a parenthesized expression or a number.
fn parse_factor(chars: &[char], pos: &mut usize) -> Result<i32, ParseError> {
    skip_whitespace(chars, pos);
    if *pos >= chars.len() {
        return Err(ParseError::UnexpectedChar('\0'));
    }
    if chars[*pos] == '(' {
        *pos += 1;
        let value = parse_expr(chars, pos)?;
        skip_whitespace(chars, pos);
        if *pos >= chars.len() || chars[*pos] != ')' {
            return Err(ParseError::MissingClosingParen);
        }
        *pos += 1;
        Ok(value)
    } else {
        parse_number(chars, pos)
    }
}

/// Parses a number represented in ternary (base 3).
fn parse_number(chars: &[char], pos: &mut usize) -> Result<i32, ParseError> {
    skip_whitespace(chars, pos);
    if *pos >= chars.len() {
        return Err(ParseError::UnexpectedChar('\0'));
    }
    let mut value = 0;
    let mut has_digits = false;
    while *pos < chars.len() {
        let c = chars[*pos];
        if c >= '0' && c <= '2' {
            value = value * 3 + (c as i32 - '0' as i32);
            has_digits = true;
            *pos += 1;
        } else {
            break;
        }
    }
    if !has_digits {
        return Err(ParseError::InvalidDigit(chars[*pos]));
    }
    Ok(value)
}

/// Advances the parsing position past any whitespace.
fn skip_whitespace(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_whitespace() {
        *pos += 1;
    }
}

/// Converts an integer to its ternary (base 3) string representation.
fn int_to_ternary(n: i32) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut digits = Vec::new();
    let mut num = n.abs();
    while num > 0 {
        digits.push((num % 3) as u8 + b'0');
        num /= 3;
    }
    if n < 0 {
        digits.push(b'-');
    }
    String::from_utf8(digits.into_iter().rev().collect()).unwrap()
}

/// Parses a ternary string back into an integer.
fn parse_ternary(s: &str) -> Result<i32, ParseError> {
    let mut value = 0;
    let mut is_negative = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    if chars.is_empty() {
        return Err(ParseError::EmptyExpression);
    }
    if chars[0] == '-' {
        is_negative = true;
        i += 1;
    }
    while i < chars.len() {
        let c = chars[i];
        if c < '0' || c > '2' {
            return Err(ParseError::InvalidDigit(c));
        }
        value = value * 3 + (c as i32 - '0' as i32);
        i += 1;
    }
    Ok(if is_negative { -value } else { value })
}

/// Solves the Tower of Hanoi problem for n disks.
fn solve_hanoi(n: i32) {
    let mut state: Vec<i32> = vec![0; n as usize];
    println!("Initial state (all disks on peg 0):");
    print_state(&state);
    solve_hanoi_recursive(n, 0, 2, 1, &mut state);
}

/// Recursive helper for Tower of Hanoi solution.
fn solve_hanoi_recursive(n: i32, from: i32, to: i32, aux: i32, state: &mut Vec<i32>) {
    if n == 0 {
        return;
    }
    solve_hanoi_recursive(n - 1, from, aux, to, state);
    hanoi_move(n - 1, from, to, state);
    solve_hanoi_recursive(n - 1, aux, to, from, state);
}

/// Moves a disk in the Tower of Hanoi puzzle and prints the move.
fn hanoi_move(disk: i32, from: i32, to: i32, state: &mut Vec<i32>) {
    println!("Move disk {} from peg {} to peg {}", disk, from, to);
    state[disk as usize] = to;
    print_state(state);
}

/// Prints the current state of the Tower of Hanoi puzzle.
fn print_state(state: &[i32]) {
    print!("State: ");
    for &peg in state.iter().rev() {
        print!("{}", peg);
    }
    println!();
}

/// Encodes an opcode using ternary representation and appends a checksum.
fn discrete_opcode_encode(opcode: i32) -> String {
    let ternary = int_to_ternary(opcode);
    let checksum = ternary.chars()
        .filter(|&c| c >= '0' && c <= '2')
        .map(|c| (c as u32 - '0' as u32) as i32)
        .sum::<i32>() % 3;
    format!("{}{}", ternary, checksum)
}

/// Validates an encoded opcode by checking its checksum.
fn discrete_opcode_validate(encoded: &str) -> bool {
    if encoded.len() < 2 {
        return false;
    }
    let (code, checksum) = encoded.split_at(encoded.len() - 1);
    let checksum_digit = checksum.chars().next().unwrap();
    if checksum_digit < '0' || checksum_digit > '2' {
        return false;
    }
    let computed_sum = code.chars()
        .filter(|&c| c >= '0' && c <= '2')
        .map(|c| (c as u32 - '0' as u32) as i32)
        .sum::<i32>() % 3;
    computed_sum == (checksum_digit as u32 - '0' as u32) as i32
}

/// Prints a nicely formatted representation of a matrix.
fn print_matrix(mat: &TMatrix) {
    println!("Matrix ({}x{}):", mat.rows, mat.cols);
    for row in &mat.data {
        for val in row {
            print!("{}\t", val);
        }
        println!();
    }
}

/// Displays the help menu with available commands.
fn print_help() {
    println!("Ternary Systems B02-RS Utility (Rust Version)");
    println!("=================================================");
    println!("Usage:");
    println!("  ternary_system -expr \"expression\"    Evaluate a ternary expression");
    println!("  ternary_system -hanoi n               Solve Tower of Hanoi for n disks");
    println!("  ternary_system -opcode number         Encode and validate an opcode");
    println!("  ternary_system interactive            Launch interactive mode");
    println!();
    println!("Interactive Mode Commands:");
    println!("  expr <expression>                     Evaluate a ternary expression");
    println!("  hanoi <n>                           Solve Tower of Hanoi for n disks");
    println!("  opcode <number>                       Encode and validate an opcode");
    println!("  matrix new <rows> <cols>              Create a new matrix");
    println!("  matrix show                         Display the current matrix");
    println!("  matrix set <row> <col> <value>        Set a matrix element");
    println!("  matrix add <filename>                 Add current matrix to matrix from file");
    println!("  matrix multiply <filename>            Multiply current matrix with matrix from file");
    println!("  matrix serialize <filename>           Save the current matrix to file");
    println!("  matrix load <filename>                Load a matrix from file");
    println!("  help                                  Show this help menu");
    println!("  exit                                  Exit interactive mode");
    println!("=================================================");
}

/// Interactive mode: supports all utility commands including matrix operations.
fn interactive_mode() {
    let stdin = io::stdin();
    // Optional current matrix for matrix operations.
    let mut current_matrix: Option<TMatrix> = None;
    println!("Entering interactive mode. Type 'help' for commands, 'exit' to quit.");
    loop {
        print!("ts> ");
        io::stdout().flush().unwrap();
        let mut line = String::new();
        stdin.read_line(&mut line).unwrap();
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Tokenize the command by whitespace.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        match tokens[0] {
            "exit" => {
                println!("Exiting interactive mode.");
                break;
            }
            "help" => {
                print_help();
            }
            "expr" => {
                if tokens.len() < 2 {
                    println!("Usage: expr <expression>");
                } else {
                    let expression = &line[5..]; // Grab the full expression after "expr "
                    match tritjs_eval_expression(expression) {
                        Ok(result) => println!("Expression evaluated to (ternary): {}", int_to_ternary(result)),
                        Err(e) => println!("Error: {}", e),
                    }
                }
            }
            "hanoi" => {
                if tokens.len() < 2 {
                    println!("Usage: hanoi <number_of_disks>");
                } else if let Ok(n) = tokens[1].parse::<i32>() {
                    if n >= 0 {
                        solve_hanoi(n);
                    } else {
                        println!("Number of disks must be non-negative");
                    }
                } else {
                    println!("Invalid number for hanoi");
                }
            }
            "opcode" => {
                if tokens.len() < 2 {
                    println!("Usage: opcode <number>");
                } else if let Ok(opcode) = tokens[1].parse::<i32>() {
                    let encoded = discrete_opcode_encode(opcode);
                    println!("Opcode {} encoded as: {}", opcode, encoded);
                    println!("Encoded opcode is {}", if discrete_opcode_validate(&encoded) { "valid" } else { "invalid" });
                } else {
                    println!("Invalid opcode");
                }
            }
            "matrix" => {
                // Matrix operations subcommands.
                if tokens.len() < 2 {
                    println!("Matrix commands: new, show, set, add, multiply, serialize, load");
                    continue;
                }
                match tokens[1] {
                    "new" => {
                        if tokens.len() < 4 {
                            println!("Usage: matrix new <rows> <cols>");
                        } else if let (Ok(rows), Ok(cols)) = (tokens[2].parse::<usize>(), tokens[3].parse::<usize>()) {
                            current_matrix = Some(TMatrix::new(rows, cols));
                            println!("Created new matrix of size {}x{}", rows, cols);
                        } else {
                            println!("Invalid dimensions for matrix new");
                        }
                    }
                    "show" => {
                        if let Some(ref mat) = current_matrix {
                            print_matrix(mat);
                        } else {
                            println!("No current matrix. Create one using 'matrix new'");
                        }
                    }
                    "set" => {
                        if tokens.len() < 5 {
                            println!("Usage: matrix set <row> <col> <value>");
                        } else {
                            if let Some(ref mut mat) = current_matrix {
                                if let (Ok(r), Ok(c), Ok(value)) = (tokens[2].parse::<usize>(), tokens[3].parse::<usize>(), tokens[4].parse::<i32>()) {
                                    if r < mat.rows && c < mat.cols {
                                        mat.data[r][c] = value;
                                        println!("Set element ({}, {}) to {}", r, c, value);
                                    } else {
                                        println!("Index out of bounds");
                                    }
                                } else {
                                    println!("Invalid arguments for matrix set");
                                }
                            } else {
                                println!("No current matrix. Create one using 'matrix new'");
                            }
                        }
                    }
                    "add" => {
                        if tokens.len() < 3 {
                            println!("Usage: matrix add <filename>");
                        } else {
                            if let Some(ref mat) = current_matrix {
                                match TMatrix::deserialize(tokens[2]) {
                                    Ok(other) => {
                                        match mat.add(&other) {
                                            Ok(result) => {
                                                println!("Result of matrix addition:");
                                                print_matrix(&result);
                                            }
                                            Err(e) => println!("Error in addition: {}", e),
                                        }
                                    }
                                    Err(e) => println!("Error loading matrix from file: {}", e),
                                }
                            } else {
                                println!("No current matrix. Create one using 'matrix new'");
                            }
                        }
                    }
                    "multiply" => {
                        if tokens.len() < 3 {
                            println!("Usage: matrix multiply <filename>");
                        } else {
                            if let Some(ref mat) = current_matrix {
                                match TMatrix::deserialize(tokens[2]) {
                                    Ok(other) => {
                                        match mat.multiply(&other) {
                                            Ok(result) => {
                                                println!("Result of matrix multiplication:");
                                                print_matrix(&result);
                                            }
                                            Err(e) => println!("Error in multiplication: {}", e),
                                        }
                                    }
                                    Err(e) => println!("Error loading matrix from file: {}", e),
                                }
                            } else {
                                println!("No current matrix. Create one using 'matrix new'");
                            }
                        }
                    }
                    "serialize" => {
                        if tokens.len() < 3 {
                            println!("Usage: matrix serialize <filename>");
                        } else {
                            if let Some(ref mat) = current_matrix {
                                match mat.serialize(tokens[2]) {
                                    Ok(()) => println!("Matrix serialized to file {}", tokens[2]),
                                    Err(e) => println!("Error serializing matrix: {}", e),
                                }
                            } else {
                                println!("No current matrix. Create one using 'matrix new'");
                            }
                        }
                    }
                    "load" => {
                        if tokens.len() < 3 {
                            println!("Usage: matrix load <filename>");
                        } else {
                            match TMatrix::deserialize(tokens[2]) {
                                Ok(mat) => {
                                    current_matrix = Some(mat);
                                    println!("Matrix loaded from file {}", tokens[2]);
                                }
                                Err(e) => println!("Error loading matrix: {}", e),
                            }
                        }
                    }
                    _ => println!("Unknown matrix command. Available commands: new, show, set, add, multiply, serialize, load"),
                }
            }
            _ => {
                println!("Unknown command. Type 'help' for available commands.");
            }
        }
    }
}

/// Main entry point: routes command-line arguments or launches interactive mode.
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "interactive" {
        interactive_mode();
    } else if args[1] == "-expr" && args.len() > 2 {
        match tritjs_eval_expression(&args[2]) {
            Ok(result) => println!("Expression evaluated to (ternary): {}", int_to_ternary(result)),
            Err(e) => {
                println!("Error: {}", e);
                process::exit(1);
            }
        }
    } else if args[1] == "-hanoi" && args.len() > 2 {
        match args[2].parse::<i32>() {
            Ok(n) if n >= 0 => solve_hanoi(n),
            Ok(_) => {
                println!("Number of disks must be non-negative");
                process::exit(1);
            }
            Err(_) => {
                println!("Invalid number for hanoi");
                process::exit(1);
            }
        }
    } else if args[1] == "-opcode" && args.len() > 2 {
        match args[2].parse::<i32>() {
            Ok(opcode) => {
                let encoded = discrete_opcode_encode(opcode);
                println!("Opcode {} encoded as: {}", opcode, encoded);
                println!("Encoded opcode is {}", if discrete_opcode_validate(&encoded) { "valid" } else { "invalid" });
            }
            Err(_) => {
                println!("Invalid opcode");
                process::exit(1);
            }
        }
    } else {
        print_help();
        process::exit(1);
    }
}
