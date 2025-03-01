import java.io.*;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.MappedByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

/**
 * TritJS-CISA: Optimized ternary calculator for CISA cybersecurity applications.
 * Enhancements include efficient MappedByteBuffer usage for large trit arrays.
 * Date: March 01, 2025.
 */
public class TritJSCISA {
    private static final int TRIT_MAX = 3;
    private static final long MAX_MMAP_SIZE = 1024 * 1024; // 1MB limit
    private static RandomAccessFile auditLog;
    private static FileChannel sharedChannel; // Shared channel for reuse
    private static File tempFile; // Single temp file for all mappings

    enum TritError {
        OK("No error"), MEM("Memory allocation failed"), INPUT("Invalid input (trits 0-2 only)"),
        DIV_ZERO("Division by zero"), OVERFLOW("Overflow detected"), UNDEFINED("Operation undefined"),
        NEGATIVE("Negative input (complex handled)"), PRECISION("Precision limit exceeded"),
        MMAP("Memory mapping failed");

        private final String message;
        TritError(String message) { this.message = message; }
        public String getMessage() { return message; }
    }

    static {
        try {
            auditLog = new RandomAccessFile("/var/log/tritjs_cisa.log", "rw");
            auditLog.seek(auditLog.length());
            tempFile = File.createTempFile("tritjs_cisa_", ".tmp");
            sharedChannel = FileChannel.open(tempFile.toPath(), 
                    StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE);
        } catch (IOException e) {
            System.err.println("Initialization failed: " + e.getMessage());
        }
    }

    static void logError(TritError err, String context) {
        if (auditLog == null) return;
        try {
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            String log = String.format("[%s] Error %s: %s in %s%n", timestamp, err, err.getMessage(), context);
            auditLog.writeUTF(log);
        } catch (IOException e) {
            System.err.println("Error logging failed: " + e.getMessage());
        }
    }

    // Optimized TritBigInt with efficient MappedByteBuffer usage
    static class TritBigInt {
        boolean sign;
        int[] digits; // In-memory array for small data
        MappedByteBuffer mappedDigits; // Mapped buffer for large data
        long mappedSize; // Size in trits
        private static long offset = 0; // Shared offset for mapping regions

        // Small data constructor
        TritBigInt(int[] digits, boolean sign) throws TritError {
            if (digits == null || digits.length == 0) throw TritError.INPUT;
            for (int d : digits) if (d < 0 || d > 2) throw TritError.INPUT;
            this.sign = sign;
            this.digits = Arrays.copyOf(digits, digits.length);
            this.mappedDigits = null;
            this.mappedSize = 0;
        }

        // Large data constructor with optimized mapping
        TritBigInt(int[] digits, boolean sign, long size) throws TritError {
            if (digits == null || digits.length == 0) throw TritError.INPUT;
            long byteSize = size * Integer.BYTES;
            if (byteSize > MAX_MMAP_SIZE) throw TritError.OVERFLOW;
            this.sign = sign;
            this.digits = null;

            try {
                synchronized (sharedChannel) { // Ensure thread-safe mapping
                    if (offset + byteSize > sharedChannel.size()) {
                        sharedChannel.truncate(offset + byteSize); // Pre-allocate space
                    }
                    this.mappedDigits = sharedChannel.map(FileChannel.MapMode.READ_WRITE, offset, byteSize);
                    this.mappedSize = size;
                    offset += byteSize; // Increment offset for next mapping
                    for (int i = 0; i < digits.length; i++) {
                        if (digits[i] < 0 || digits[i] > 2) throw TritError.INPUT;
                        this.mappedDigits.putInt(i * Integer.BYTES, digits[i]);
                    }
                    // Pad remaining space with zeros
                    for (int i = digits.length; i < size; i++) {
                        this.mappedDigits.putInt(i * Integer.BYTES, 0);
                    }
                    this.mappedDigits.load(); // Preload into memory for faster access
                }
            } catch (IOException e) {
                throw TritError.MMAP;
            }
        }

        int[] getDigits() {
            if (mappedDigits != null) {
                int[] result = new int[(int)mappedSize];
                mappedDigits.rewind(); // Ensure position is at start
                for (int i = 0; i < mappedSize; i++) {
                    result[i] = mappedDigits.getInt();
                }
                return result;
            }
            return digits;
        }

        int length() {
            return mappedDigits != null ? (int)mappedSize : digits.length;
        }

        void force() { // Force writes to disk
            if (mappedDigits != null) mappedDigits.force();
        }
    }

    static class TritFloat {
        boolean sign;
        int[] integer;
        int[] fraction;

        TritFloat(TritBigInt bi) throws TritError {
            this.sign = bi.sign;
            this.integer = bi.getDigits();
            this.fraction = new int[0];
            bi.force(); // Ensure mapped data is written
        }

        TritFloat(int[] integer, int[] fraction, boolean sign) {
            this.sign = sign;
            this.integer = Arrays.copyOf(integer, integer.length);
            this.fraction = Arrays.copyOf(fraction, fraction.length);
        }
    }

    static class TritComplex {
        TritFloat real;
        TritFloat imag;

        TritComplex(TritFloat real, TritFloat imag) {
            this.real = real;
            this.imag = imag;
        }
    }

    static class TritDivResult {
        TritFloat quotient;
        TritFloat remainder;

        TritDivResult(TritFloat quotient, TritFloat remainder) {
            this.quotient = quotient;
            this.remainder = remainder;
        }
    }

    // Arithmetic operations (unchanged for brevity, optimized via TritBigInt)
    static TritBigInt add(TritBigInt a, TritBigInt b) throws TritError {
        if (a == null || b == null) throw TritError.INPUT;
        int[] aDigits = a.getDigits();
        int[] bDigits = b.getDigits();
        int maxLen = Math.max(aDigits.length, bDigits.length);
        int[] temp = new int[maxLen + 1];
        int carry = 0;

        if (a.sign == b.sign) {
            for (int i = maxLen - 1, pos = 0; i >= 0; i--, pos++) {
                int aTrit = (i < aDigits.length) ? aDigits[i] : 0;
                int bTrit = (i < bDigits.length) ? bDigits[i] : 0;
                int sum = aTrit + bTrit + carry;
                temp[maxLen - pos] = sum % TRIT_MAX;
                carry = sum / TRIT_MAX;
            }
            if (carry != 0) temp[0] = carry;
            int resultLen = carry != 0 ? maxLen + 1 : maxLen;
            int start = carry == 0 ? 1 : 0;
            return resultLen > 100 ? new TritBigInt(Arrays.copyOfRange(temp, start, resultLen + start), a.sign, resultLen)
                                  : new TritBigInt(Arrays.copyOfRange(temp, start, resultLen + start), a.sign);
        } else {
            TritBigInt bNeg = new TritBigInt(bDigits, !b.sign);
            return add(a, bNeg);
        }
    }

    static TritBigInt subtract(TritBigInt a, TritBigInt b) throws TritError {
        if (a == null || b == null) throw TritError.INPUT;
        TritBigInt bNeg = new TritBigInt(b.getDigits(), !b.sign);
        return add(a, bNeg);
    }

    static TritBigInt multiply(TritBigInt a, TritBigInt b) throws TritError {
        if (a == null || b == null) throw TritError.INPUT;
        int[] aDigits = a.getDigits();
        int[] bDigits = b.getDigits();
        int maxLen = aDigits.length + bDigits.length;
        int[] temp = new int[maxLen];
        for (int i = aDigits.length - 1; i >= 0; i--) {
            int carry = 0;
            for (int j = bDigits.length - 1; j >= 0; j--) {
                int pos = i + j + 1;
                int prod = aDigits[i] * bDigits[j] + temp[pos] + carry;
                temp[pos] = prod % TRIT_MAX;
                carry = prod / TRIT_MAX;
            }
            if (carry != 0) temp[i] += carry;
        }
        int start = 0;
        while (start < maxLen - 1 && temp[start] == 0) start++;
        int resultLen = maxLen - start;
        return resultLen > 100 ? new TritBigInt(Arrays.copyOfRange(temp, start, maxLen), a.sign != b.sign, resultLen)
                              : new TritBigInt(Arrays.copyOfRange(temp, start, maxLen), a.sign != b.sign);
    }

    static TritDivResult divide(TritBigInt a, TritBigInt b, int precision) throws TritError {
        if (a == null || b == null) throw TritError.INPUT;
        if (precision <= 0 || precision > 10) throw TritError.PRECISION;
        int[] bDigits = b.getDigits();
        boolean bIsZero = true;
        for (int d : bDigits) if (d != 0) { bIsZero = false; break; }
        if (bIsZero) {
            logError(TritError.DIV_ZERO, "divide");
            throw TritError.DIV_ZERO;
        }

        TritFloat dividend = new TritFloat(a);
        int[] aDigits = a.getDigits();
        int[] quotientInt = new int[aDigits.length];
        int[] quotientFrac = new int[precision];
        int[] remainder = Arrays.copyOf(aDigits, aDigits.length);

        for (int i = 0; i < aDigits.length; i++) {
            int digit = 0;
            for (int q = 2; q >= 0; q--) {
                TritBigInt multiple = new TritBigInt(new int[]{q}, false);
                TritBigInt prod = multiply(b, multiple);
                TritBigInt tempRem = new TritBigInt(remainder, a.sign);
                TritBigInt sub = subtract(tempRem, prod);
                if (!sub.sign) {
                    digit = q;
                    remainder = sub.getDigits();
                    break;
                }
            }
            quotientInt[i] = digit;
        }

        for (int i = 0; i < precision; i++) {
            TritBigInt three = new TritBigInt(new int[]{1}, false);
            TritBigInt tempRem = new TritBigInt(remainder, a.sign);
            TritBigInt tempMul = multiply(tempRem, three);
            remainder = tempMul.getDigits();
            int digit = 0;
            for (int q = 2; q >= 0; q--) {
                TritBigInt multiple = new TritBigInt(new int[]{q}, false);
                TritBigInt prod = multiply(b, multiple);
                TritBigInt sub = subtract(tempMul, prod);
                if (!sub.sign) {
                    digit = q;
                    remainder = sub.getDigits();
                    break;
                }
            }
            quotientFrac[i] = digit;
        }

        int start = 0;
        while (start < quotientInt.length - 1 && quotientInt[start] == 0) start++;
        quotientInt = Arrays.copyOfRange(quotientInt, start, quotientInt.length);
        return new TritDivResult(
            new TritFloat(quotientInt, quotientFrac, a.sign != b.sign),
            new TritFloat(new TritBigInt(remainder, a.sign))
        );
    }

    static TritBigInt power(TritBigInt base, TritBigInt exp) throws TritError {
        if (base == null || exp == null) throw TritError.INPUT;
        if (exp.sign) throw TritError.NEGATIVE;
        int[] expDigits = exp.getDigits();
        long expVal = 0;
        for (int d : expDigits) expVal = expVal * TRIT_MAX + d;
        if (expVal > 1000) throw TritError.OVERFLOW;
        TritBigInt result = new TritBigInt(new int[]{1}, false);
        boolean sign = base.sign && (expVal % 2 == 1);
        for (long i = 0; i < expVal; i++) {
            result = multiply(result, base);
        }
        result.sign = sign;
        return result;
    }

    static TritBigInt factorial(TritBigInt a) throws TritError {
        if (a == null) throw TritError.INPUT;
        if (a.sign) throw TritError.NEGATIVE;
        int[] aDigits = a.getDigits();
        long aVal = 0;
        for (int d : aDigits) aVal = aVal * TRIT_MAX + d;
        if (aVal > 20) throw TritError.OVERFLOW;
        TritBigInt result = new TritBigInt(new int[]{1}, false);
        for (long i = 1; i <= aVal; i++) {
            int[] iDigits = { (int)(i / TRIT_MAX), (int)(i % TRIT_MAX) };
            int len = i >= TRIT_MAX ? 2 : 1;
            TritBigInt iBi = new TritBigInt(Arrays.copyOfRange(iDigits, 2 - len, 2), false);
            result = multiply(result, iBi);
        }
        return result;
    }

    // Scientific operations (unchanged for brevity, rely on optimized TritBigInt)
    static TritComplex sqrt(TritBigInt a, int precision) throws TritError {
        if (a == null || precision <= 0 || precision > 10) throw TritError.PRECISION;
        int[] aDigits = a.getDigits();
        double aVal = 0;
        for (int d : aDigits) aVal = aVal * TRIT_MAX + d;
        aVal *= a.sign ? -1 : 1;
        if (aVal >= 0) {
            double sqrtVal = Math.sqrt(aVal);
            return toTritComplex(sqrtVal, 0, precision);
        } else {
            double sqrtVal = Math.sqrt(-aVal);
            return toTritComplex(0, sqrtVal, precision);
        }
    }

    static TritComplex log3(TritBigInt a, int precision) throws TritError {
        if (a == null || precision <= 0 || precision > 10) throw TritError.PRECISION;
        int[] aDigits = a.getDigits();
        double aVal = 0;
        for (int d : aDigits) aVal = aVal * TRIT_MAX + d;
        aVal *= a.sign ? -1 : 1;
        double mag = Math.sqrt(aVal * aVal);
        double arg = Math.atan2(0, aVal);
        double ln3 = Math.log(3.0);
        return toTritComplex(Math.log(mag) / ln3, arg / ln3, precision);
    }

    static TritComplex trig(TritBigInt a, int precision, String func) throws TritError {
        if (a == null || precision <= 0 || precision > 10) throw TritError.PRECISION;
        int[] aDigits = a.getDigits();
        double aVal = 0;
        for (int d : aDigits) aVal = aVal * TRIT_MAX + d;
        double piApprox = 3.1415926535;
        double angle = aVal * piApprox / 10.0 * (a.sign ? -1 : 1);
        double result;
        switch (func) {
            case "sin": result = Math.sin(angle); break;
            case "cos": result = Math.cos(angle); break;
            case "tan":
                result = Math.tan(angle);
                if (Math.abs(result) > 1000) throw TritError.UNDEFINED;
                break;
            default: throw TritError.UNDEFINED;
        }
        return toTritComplex(result, 0, precision);
    }

    static int[] pi() {
        return new int[]{1, 0, 0, 1, 0, 2, 2, 1};
    }

    static TritComplex toTritComplex(double real, double imag, int precision) throws TritError {
        int[] realInt = new int[1];
        int[] realFrac = new int[precision];
        int[] imagInt = new int[1];
        int[] imagFrac = new int[precision];
        boolean realSign = real < 0;
        boolean imagSign = imag < 0;
        double realAbs = Math.abs(real);
        double imagAbs = Math.abs(imag);

        realInt[0] = (int)realAbs;
        double rFrac = realAbs - realInt[0];
        for (int i = 0; i < precision; i++) {
            rFrac *= TRIT_MAX;
            realFrac[i] = (int)rFrac;
            rFrac -= (int)rFrac;
        }
        imagInt[0] = (int)imagAbs;
        double iFrac = imagAbs - imagInt[0];
        for (int i = 0; i < precision; i++) {
            iFrac *= TRIT_MAX;
            imagFrac[i] = (int)iFrac;
            iFrac -= (int)iFrac;
        }

        return new TritComplex(
            new TritFloat(realInt, realFrac, realSign),
            new TritFloat(imagInt, imagFrac, imagSign)
        );
    }

    // String conversion utilities (unchanged)
    static String toString(TritBigInt bi) throws TritError {
        if (bi == null) throw TritError.INPUT;
        int[] digits = bi.getDigits();
        StringBuilder sb = new StringBuilder(bi.sign ? "-" : "");
        for (int d : digits) sb.append(d);
        return sb.toString();
    }

    static String toString(TritFloat tf) throws TritError {
        if (tf == null || tf.integer.length == 0) throw TritError.INPUT;
        StringBuilder sb = new StringBuilder(tf.sign ? "-" : "");
        for (int d : tf.integer) sb.append(d);
        if (tf.fraction.length > 0) {
            sb.append(".");
            for (int d : tf.fraction) sb.append(d);
        }
        return sb.toString();
    }

    static String toString(TritComplex tc) throws TritError {
        String realStr = toString(tc.real);
        String imagStr = toString(tc.imag);
        boolean imagZero = tc.imag.integer.length == 1 && tc.imag.integer[0] == 0 && tc.imag.fraction.length == 0;
        return imagZero ? realStr : realStr + " " + imagStr + "i";
    }

    // CLI (unchanged except for MappedByteBuffer integration)
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("TritJS-CISA Ternary Calculator (quit to exit)");
        while (true) {
            System.out.print("> ");
            String input = scanner.nextLine().trim();
            if (auditLog != null) {
                try {
                    auditLog.writeUTF(String.format("[%tF %tT] Command: %s%n", new Date(), new Date(), input));
                } catch (IOException e) {
                    System.err.println("Audit log write failed");
                }
            }
            if ("quit".equals(input)) break;
            if ("help".equals(input)) {
                System.out.println("Commands: add, sub, mul, div, pow, fact, sqrt, log3, sin, cos, tan, pi, help, quit");
                continue;
            }

            String[] parts = input.split("\\s+");
            if (parts.length < 2) {
                System.out.println("Error: Invalid format");
                continue;
            }

            String op = parts[0];
            try {
                TritBigInt a = parseTritString(parts[1]);
                TritBigInt b = parts.length > 2 ? parseTritString(parts[2]) : null;

                switch (op) {
                    case "add":
                        if (b == null) throw TritError.INPUT;
                        System.out.println(toString(add(a, b)));
                        break;
                    case "sub":
                        if (b == null) throw TritError.INPUT;
                        System.out.println(toString(subtract(a, b)));
                        break;
                    case "mul":
                        if (b == null) throw TritError.INPUT;
                        System.out.println(toString(multiply(a, b)));
                        break;
                    case "div":
                        if (b == null) throw TritError.INPUT;
                        TritDivResult divResult = divide(a, b, 3);
                        System.out.println(toString(divResult.quotient) + " r " + toString(divResult.remainder));
                        break;
                    case "pow":
                        if (b == null) throw TritError.INPUT;
                        System.out.println(toString(power(a, b)));
                        break;
                    case "fact":
                        System.out.println(toString(factorial(a)));
                        break;
                    case "sqrt":
                        System.out.println(toString(sqrt(a, 3)));
                        break;
                    case "log3":
                        System.out.println(toString(log3(a, 3)));
                        break;
                    case "sin":
                        System.out.println(toString(trig(a, 3, "sin")));
                        break;
                    case "cos":
                        System.out.println(toString(trig(a, 3, "cos")));
                        break;
                    case "tan":
                        System.out.println(toString(trig(a, 3, "tan")));
                        break;
                    case "pi":
                        System.out.println(Arrays.toString(pi()).replaceAll("[\\[\\], ]", ""));
                        break;
                    default:
                        System.out.println("Error: Unknown command");
                }
            } catch (TritError e) {
                System.out.println("Error: " + e.getMessage());
                logError(e, op);
            }
        }
        try {
            if (auditLog != null) auditLog.close();
            if (sharedChannel != null) sharedChannel.close();
        } catch (IOException e) {
            System.err.println("Error closing resources");
        }
        scanner.close();
    }

    static TritBigInt parseTritString(String str) throws TritError {
        if (str == null || str.isEmpty()) throw TritError.INPUT;
        boolean sign = str.startsWith("-");
        String mag = sign ? str.substring(1) : str;
        int[] digits = new int[mag.length()];
        for (int i = 0; i < mag.length(); i++) {
            int d = mag.charAt(i) - '0';
            if (d < 0 || d > 2) throw TritError.INPUT;
            digits[i] = d;
        }
        return digits.length > 100 ? new TritBigInt(digits, sign, digits.length) : new TritBigInt(digits, sign);
    }
}
