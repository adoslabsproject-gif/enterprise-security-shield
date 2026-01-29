<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection\Parser;

/**
 * SQL Tokenizer - Real lexical analysis for SQL injection detection
 *
 * This is NOT regex matching. This is a real tokenizer that breaks SQL
 * into tokens for syntactic analysis. Handles:
 * - String literals (single/double quotes, escaping)
 * - Comments (dash-dash, block comments, hash)
 * - Operators and keywords
 * - Numeric literals (int, float, hex, binary)
 * - Identifiers and functions
 * - Encoded payloads (URL, hex, unicode)
 *
 * @version 1.0.0
 */
final class SQLTokenizer
{
    // Token types
    public const T_KEYWORD = 'KEYWORD';
    public const T_FUNCTION = 'FUNCTION';
    public const T_OPERATOR = 'OPERATOR';
    public const T_COMPARISON = 'COMPARISON';
    public const T_LOGICAL = 'LOGICAL';
    public const T_STRING = 'STRING';
    public const T_NUMBER = 'NUMBER';
    public const T_IDENTIFIER = 'IDENTIFIER';
    public const T_COMMENT = 'COMMENT';
    public const T_WHITESPACE = 'WHITESPACE';
    public const T_PUNCTUATION = 'PUNCTUATION';
    public const T_UNKNOWN = 'UNKNOWN';

    /**
     * SQL Keywords that indicate potential injection
     */
    private const SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'TRUNCATE', 'REPLACE', 'MERGE', 'CALL', 'EXEC', 'EXECUTE',
        'UNION', 'JOIN', 'FROM', 'WHERE', 'HAVING', 'GROUP', 'ORDER',
        'BY', 'LIMIT', 'OFFSET', 'INTO', 'VALUES', 'SET', 'TABLE',
        'DATABASE', 'SCHEMA', 'INDEX', 'VIEW', 'PROCEDURE', 'FUNCTION',
        'TRIGGER', 'GRANT', 'REVOKE', 'COMMIT', 'ROLLBACK', 'SAVEPOINT',
        'BEGIN', 'END', 'DECLARE', 'CASE', 'WHEN', 'THEN', 'ELSE',
        'IF', 'WHILE', 'LOOP', 'RETURN', 'NULL', 'TRUE', 'FALSE',
        'AS', 'ON', 'IN', 'EXISTS', 'BETWEEN', 'LIKE', 'RLIKE', 'REGEXP',
        'IS', 'NOT', 'ALL', 'ANY', 'SOME', 'DISTINCT', 'ASC', 'DESC',
        'INNER', 'OUTER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'NATURAL',
        'USING', 'PARTITION', 'OVER', 'WINDOW', 'ROWS', 'RANGE',
        'UNBOUNDED', 'PRECEDING', 'FOLLOWING', 'CURRENT', 'ROW',
        'FETCH', 'NEXT', 'FIRST', 'LAST', 'ONLY', 'WITH', 'RECURSIVE',
        'TEMPORARY', 'TEMP', 'LOCAL', 'GLOBAL', 'CASCADE', 'RESTRICT',
        'COLLATE', 'CHARACTER', 'CHARSET', 'BINARY', 'VARBINARY',
        'OUTFILE', 'DUMPFILE', 'LOAD', 'DATA', 'INFILE', 'TERMINATED',
        'ENCLOSED', 'ESCAPED', 'LINES', 'STARTING', 'IGNORE',
        'DUPLICATE', 'KEY', 'PRIMARY', 'FOREIGN', 'REFERENCES',
        'CONSTRAINT', 'CHECK', 'DEFAULT', 'AUTO_INCREMENT', 'UNSIGNED',
        'ZEROFILL', 'SERIAL', 'COMMENT', 'ENGINE', 'CHARSET',
    ];

    /**
     * Dangerous SQL functions
     */
    private const SQL_FUNCTIONS = [
        // String functions (often used in injection)
        'CONCAT', 'CONCAT_WS', 'GROUP_CONCAT', 'SUBSTRING', 'SUBSTR', 'MID',
        'LEFT', 'RIGHT', 'LENGTH', 'CHAR_LENGTH', 'CHARACTER_LENGTH',
        'CHAR', 'ASCII', 'ORD', 'HEX', 'UNHEX', 'BIN', 'OCT',
        'LOWER', 'LCASE', 'UPPER', 'UCASE', 'REVERSE', 'REPLACE',
        'INSERT', 'LPAD', 'RPAD', 'TRIM', 'LTRIM', 'RTRIM', 'SPACE',
        'REPEAT', 'FORMAT', 'QUOTE', 'SOUNDEX', 'CONVERT', 'CAST',

        // Information functions (data exfiltration)
        'DATABASE', 'SCHEMA', 'USER', 'CURRENT_USER', 'SYSTEM_USER',
        'SESSION_USER', 'VERSION', 'CONNECTION_ID', 'LAST_INSERT_ID',
        'ROW_COUNT', 'FOUND_ROWS',

        // Conditional functions (blind SQLi)
        'IF', 'IFNULL', 'NULLIF', 'COALESCE', 'CASE', 'IIF',
        'NVL', 'NVL2', 'DECODE', 'CHOOSE',

        // Time functions (time-based blind SQLi)
        'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY', 'PG_SLEEP',
        'DBMS_LOCK.SLEEP', 'UTL_INADDR.GET_HOST_ADDRESS',

        // File functions (file access)
        'LOAD_FILE', 'INTO_OUTFILE', 'INTO_DUMPFILE',

        // Math functions (used for encoding)
        'FLOOR', 'CEIL', 'CEILING', 'ROUND', 'TRUNCATE', 'MOD',
        'ABS', 'SIGN', 'RAND', 'POWER', 'POW', 'SQRT', 'EXP', 'LOG',

        // XML functions (XXE via SQL)
        'EXTRACTVALUE', 'UPDATEXML', 'XMLTYPE', 'XMLELEMENT',

        // Aggregate functions
        'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'STD', 'STDDEV',
        'VARIANCE', 'VAR_POP', 'VAR_SAMP',

        // PostgreSQL specific
        'PG_READ_FILE', 'PG_LS_DIR', 'PG_READ_BINARY_FILE',

        // SQL Server specific
        'XP_CMDSHELL', 'SP_EXECUTESQL', 'OPENROWSET', 'OPENDATASOURCE',
        'XP_REGREAD', 'XP_REGWRITE', 'XP_DIRTREE', 'XP_FILEEXIST',
        'SP_OACREATE', 'SP_OAMETHOD', 'OBJECT_ID', 'DB_NAME',

        // Oracle specific
        'UTL_HTTP', 'HTTPURITYPE', 'DBMS_PIPE', 'SYS_EVAL',
    ];

    /**
     * SQL Operators
     */
    private const SQL_OPERATORS = [
        '+', '-', '*', '/', '%', '&', '|', '^', '~',
        '<<', '>>', '||', '&&',
    ];

    /**
     * SQL Comparison operators
     */
    private const SQL_COMPARISONS = [
        '=', '!=', '<>', '<', '>', '<=', '>=', '<=>',
        'LIKE', 'RLIKE', 'REGEXP', 'IN', 'BETWEEN', 'IS',
    ];

    /**
     * Tokenize input string
     *
     * @param string $input Raw input (may be URL encoded, etc.)
     * @return array<int, array{type: string, value: string, position: int}>
     */
    public function tokenize(string $input): array
    {
        // Pre-process: decode common encodings
        $decoded = $this->decodeInput($input);

        $tokens = [];
        $length = strlen($decoded);
        $position = 0;

        while ($position < $length) {
            $token = $this->nextToken($decoded, $position, $length);
            if ($token !== null) {
                $tokens[] = $token;
                $position += strlen($token['value']);
            } else {
                // Skip unknown character
                $position++;
            }
        }

        return $tokens;
    }

    /**
     * Decode various input encodings
     */
    private function decodeInput(string $input): string
    {
        $decoded = $input;

        // URL decode (multiple passes for double encoding)
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = urldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }
            $decoded = $newDecoded;
        }

        // HTML entity decode
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Unicode escape sequences (\uXXXX)
        $decoded = preg_replace_callback(
            '/\\\\u([0-9a-fA-F]{4})/',
            fn($m) => mb_chr((int) hexdec($m[1])),
            $decoded
        ) ?? $decoded;

        // Hex escape sequences (0xXX)
        $decoded = preg_replace_callback(
            '/0x([0-9a-fA-F]{2})/',
            fn($m) => chr((int) hexdec($m[1])),
            $decoded
        ) ?? $decoded;

        // MySQL hex strings (X'...' or 0x...)
        $decoded = preg_replace_callback(
            "/X'([0-9a-fA-F]+)'/i",
            fn($m) => pack('H*', $m[1]),
            $decoded
        ) ?? $decoded;

        // Remove null bytes (bypass attempts)
        $decoded = str_replace("\x00", '', $decoded);

        // Normalize whitespace variations used in bypasses
        $decoded = preg_replace('/[\x09\x0A\x0B\x0C\x0D\x20\xA0]+/', ' ', $decoded) ?? $decoded;

        return $decoded;
    }

    /**
     * Get next token from input
     *
     * @return array{type: string, value: string, position: int}|null
     */
    private function nextToken(string $input, int $position, int $length): ?array
    {
        if ($position >= $length) {
            return null;
        }

        $char = $input[$position];
        $remaining = substr($input, $position);

        // Whitespace
        if (preg_match('/^\s+/', $remaining, $matches)) {
            return [
                'type' => self::T_WHITESPACE,
                'value' => $matches[0],
                'position' => $position,
            ];
        }

        // Single-line comment (--)
        if (str_starts_with($remaining, '--')) {
            $end = strpos($remaining, "\n");
            $value = $end === false ? $remaining : substr($remaining, 0, $end);
            return [
                'type' => self::T_COMMENT,
                'value' => $value,
                'position' => $position,
            ];
        }

        // Single-line comment (#)
        if ($char === '#') {
            $end = strpos($remaining, "\n");
            $value = $end === false ? $remaining : substr($remaining, 0, $end);
            return [
                'type' => self::T_COMMENT,
                'value' => $value,
                'position' => $position,
            ];
        }

        // Multi-line comment (/* */)
        if (str_starts_with($remaining, '/*')) {
            $end = strpos($remaining, '*/', 2);
            $value = $end === false ? $remaining : substr($remaining, 0, $end + 2);
            return [
                'type' => self::T_COMMENT,
                'value' => $value,
                'position' => $position,
            ];
        }

        // String literal (single quotes)
        if ($char === "'") {
            return $this->parseStringLiteral($remaining, $position, "'");
        }

        // String literal (double quotes)
        if ($char === '"') {
            return $this->parseStringLiteral($remaining, $position, '"');
        }

        // String literal (backticks - MySQL identifiers)
        if ($char === '`') {
            return $this->parseStringLiteral($remaining, $position, '`');
        }

        // Number (including hex 0x, binary 0b)
        if (preg_match('/^(0x[0-9a-fA-F]+|0b[01]+|\d+\.?\d*(?:[eE][+-]?\d+)?)/i', $remaining, $matches)) {
            return [
                'type' => self::T_NUMBER,
                'value' => $matches[0],
                'position' => $position,
            ];
        }

        // Multi-character operators
        foreach (['<<=', '>>=', '<=>', '<>', '!=', '<=', '>=', '<<', '>>', '||', '&&'] as $op) {
            if (str_starts_with($remaining, $op)) {
                return [
                    'type' => in_array($op, ['<>', '!=', '<=', '>=', '<=>']) ? self::T_COMPARISON : self::T_OPERATOR,
                    'value' => $op,
                    'position' => $position,
                ];
            }
        }

        // Single-character operators and comparison
        if (in_array($char, ['=', '<', '>'], true)) {
            return [
                'type' => self::T_COMPARISON,
                'value' => $char,
                'position' => $position,
            ];
        }

        if (in_array($char, ['+', '-', '*', '/', '%', '&', '|', '^', '~'], true)) {
            return [
                'type' => self::T_OPERATOR,
                'value' => $char,
                'position' => $position,
            ];
        }

        // Punctuation
        if (in_array($char, ['(', ')', ',', ';', '.', '[', ']', '{', '}', ':', '?', '@'], true)) {
            return [
                'type' => self::T_PUNCTUATION,
                'value' => $char,
                'position' => $position,
            ];
        }

        // Keywords, functions, identifiers
        if (preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*/i', $remaining, $matches)) {
            $word = $matches[0];
            $upper = strtoupper($word);

            // Check if it's a logical operator
            if (in_array($upper, ['AND', 'OR', 'NOT', 'XOR'], true)) {
                return [
                    'type' => self::T_LOGICAL,
                    'value' => $word,
                    'position' => $position,
                ];
            }

            // Check if it's a comparison keyword
            if (in_array($upper, ['LIKE', 'RLIKE', 'REGEXP', 'IN', 'BETWEEN', 'IS'], true)) {
                return [
                    'type' => self::T_COMPARISON,
                    'value' => $word,
                    'position' => $position,
                ];
            }

            // Check if it's a SQL keyword
            if (in_array($upper, self::SQL_KEYWORDS, true)) {
                return [
                    'type' => self::T_KEYWORD,
                    'value' => $word,
                    'position' => $position,
                ];
            }

            // Check if it's a SQL function
            if (in_array($upper, self::SQL_FUNCTIONS, true)) {
                return [
                    'type' => self::T_FUNCTION,
                    'value' => $word,
                    'position' => $position,
                ];
            }

            // Otherwise it's an identifier
            return [
                'type' => self::T_IDENTIFIER,
                'value' => $word,
                'position' => $position,
            ];
        }

        // Unknown token
        return [
            'type' => self::T_UNKNOWN,
            'value' => $char,
            'position' => $position,
        ];
    }

    /**
     * Parse string literal with proper escape handling
     *
     * @return array{type: string, value: string, position: int}
     */
    private function parseStringLiteral(string $input, int $position, string $quote): array
    {
        $length = strlen($input);
        $i = 1; // Skip opening quote
        $escaped = false;

        while ($i < $length) {
            $char = $input[$i];

            if ($escaped) {
                $escaped = false;
                $i++;
                continue;
            }

            if ($char === '\\') {
                $escaped = true;
                $i++;
                continue;
            }

            // MySQL doubled quotes escape
            if ($char === $quote) {
                if ($i + 1 < $length && $input[$i + 1] === $quote) {
                    $i += 2;
                    continue;
                }
                // End of string
                $i++;
                break;
            }

            $i++;
        }

        return [
            'type' => self::T_STRING,
            'value' => substr($input, 0, $i),
            'position' => $position,
        ];
    }

    /**
     * Get all SQL keywords (for external use)
     *
     * @return array<string>
     */
    public static function getKeywords(): array
    {
        return self::SQL_KEYWORDS;
    }

    /**
     * Get all SQL functions (for external use)
     *
     * @return array<string>
     */
    public static function getFunctions(): array
    {
        return self::SQL_FUNCTIONS;
    }
}
