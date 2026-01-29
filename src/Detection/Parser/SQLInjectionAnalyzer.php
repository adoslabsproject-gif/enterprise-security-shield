<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection\Parser;

/**
 * SQL Injection Analyzer - Syntactic analysis of tokenized SQL.
 *
 * This analyzer examines token sequences to detect SQL injection patterns.
 * It's NOT regex matching - it understands SQL grammar and detects:
 *
 * - UNION-based injection (data extraction)
 * - Boolean-based blind injection (OR 1=1, AND 1=1)
 * - Time-based blind injection (SLEEP, BENCHMARK, WAITFOR)
 * - Error-based injection (EXTRACTVALUE, UPDATEXML)
 * - Stacked queries (multiple statements)
 * - Second-order injection patterns
 * - Comment-based bypasses
 * - Encoding-based bypasses
 *
 * @version 1.0.0
 */
final class SQLInjectionAnalyzer
{
    private SQLTokenizer $tokenizer;

    /**
     * Detection result structure.
     */
    private const RESULT_SAFE = [
        'detected' => false,
        'confidence' => 0.0,
        'attack_type' => null,
        'evidence' => [],
        'risk_level' => 'NONE',
    ];

    /**
     * Risk levels.
     */
    public const RISK_NONE = 'NONE';

    public const RISK_LOW = 'LOW';

    public const RISK_MEDIUM = 'MEDIUM';

    public const RISK_HIGH = 'HIGH';

    public const RISK_CRITICAL = 'CRITICAL';

    /**
     * Attack types.
     */
    public const ATTACK_UNION = 'UNION_BASED';

    public const ATTACK_BOOLEAN = 'BOOLEAN_BASED';

    public const ATTACK_TIME = 'TIME_BASED';

    public const ATTACK_ERROR = 'ERROR_BASED';

    public const ATTACK_STACKED = 'STACKED_QUERIES';

    public const ATTACK_COMMENT = 'COMMENT_INJECTION';

    public const ATTACK_TAUTOLOGY = 'TAUTOLOGY';

    public const ATTACK_PIGGYBACK = 'PIGGYBACK';

    public const ATTACK_ILLEGAL = 'ILLEGAL_QUERY';

    public function __construct(?SQLTokenizer $tokenizer = null)
    {
        $this->tokenizer = $tokenizer ?? new SQLTokenizer();
    }

    /**
     * Analyze input for SQL injection.
     *
     * @param string $input Raw user input
     *
     * @return array{
     *     detected: bool,
     *     confidence: float,
     *     attack_type: string|null,
     *     evidence: array<string>,
     *     risk_level: string,
     *     tokens_analyzed: int,
     *     dangerous_tokens: array<array{type: string, value: string}>
     * }
     */
    public function analyze(string $input): array
    {
        // Quick reject for obviously safe input
        if ($this->isObviouslySafe($input)) {
            return array_merge(self::RESULT_SAFE, ['tokens_analyzed' => 0, 'dangerous_tokens' => []]);
        }

        // Tokenize input
        $tokens = $this->tokenizer->tokenize($input);

        // Filter out whitespace for analysis
        $significantTokens = array_values(array_filter(
            $tokens,
            fn ($t) => $t['type'] !== SQLTokenizer::T_WHITESPACE,
        ));

        if (empty($significantTokens)) {
            return array_merge(self::RESULT_SAFE, ['tokens_analyzed' => 0, 'dangerous_tokens' => []]);
        }

        $evidence = [];
        $dangerousTokens = [];
        $maxConfidence = 0.0;
        $attackTypes = [];

        // Check for various injection patterns
        $checks = [
            [$this, 'checkUnionInjection'],
            [$this, 'checkBooleanInjection'],
            [$this, 'checkTimeBasedInjection'],
            [$this, 'checkErrorBasedInjection'],
            [$this, 'checkStackedQueries'],
            [$this, 'checkCommentInjection'],
            [$this, 'checkTautology'],
            [$this, 'checkDangerousFunctions'],
            [$this, 'checkSuspiciousPatterns'],
        ];

        foreach ($checks as $check) {
            $result = $check($significantTokens);
            if ($result['detected']) {
                $maxConfidence = max($maxConfidence, $result['confidence']);
                $attackTypes[] = $result['attack_type'];
                $evidence = array_merge($evidence, $result['evidence']);
                $dangerousTokens = array_merge($dangerousTokens, $result['dangerous_tokens'] ?? []);
            }
        }

        // Determine risk level based on confidence
        $riskLevel = match (true) {
            $maxConfidence >= 0.9 => self::RISK_CRITICAL,
            $maxConfidence >= 0.7 => self::RISK_HIGH,
            $maxConfidence >= 0.5 => self::RISK_MEDIUM,
            $maxConfidence >= 0.3 => self::RISK_LOW,
            default => self::RISK_NONE,
        };

        // Deduplicate
        $evidence = array_unique($evidence);
        $attackTypes = array_unique($attackTypes);

        return [
            'detected' => $maxConfidence >= 0.3,
            'confidence' => round($maxConfidence, 4),
            'attack_type' => !empty($attackTypes) ? implode(', ', $attackTypes) : null,
            'evidence' => array_values($evidence),
            'risk_level' => $riskLevel,
            'tokens_analyzed' => count($significantTokens),
            'dangerous_tokens' => $dangerousTokens,
        ];
    }

    /**
     * Quick check for obviously safe input (optimization).
     */
    private function isObviouslySafe(string $input): bool
    {
        // Very short input without SQL characters
        if (strlen($input) < 3) {
            return true;
        }

        // Only alphanumeric, spaces, common punctuation
        if (preg_match('/^[a-zA-Z0-9\s\.\,\-\_\@\!\?\:]+$/', $input)) {
            // Double check no SQL keywords
            $upper = strtoupper($input);
            $dangerousKeywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'EXEC', '--', '/*'];
            foreach ($dangerousKeywords as $kw) {
                if (str_contains($upper, $kw)) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Check for UNION-based injection.
     *
     * Pattern: ... UNION [ALL] SELECT ...
     */
    private function checkUnionInjection(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        for ($i = 0; $i < count($tokens); $i++) {
            if ($this->isTokenKeyword($tokens[$i], 'UNION')) {
                $nextIdx = $i + 1;

                // Skip ALL if present
                if (isset($tokens[$nextIdx]) && $this->isTokenKeyword($tokens[$nextIdx], 'ALL')) {
                    $nextIdx++;
                }

                // Check for SELECT
                if (isset($tokens[$nextIdx]) && $this->isTokenKeyword($tokens[$nextIdx], 'SELECT')) {
                    $result['detected'] = true;
                    $result['confidence'] = 0.95;
                    $result['attack_type'] = self::ATTACK_UNION;
                    $result['evidence'][] = 'UNION SELECT pattern detected';
                    $result['dangerous_tokens'][] = ['type' => 'KEYWORD', 'value' => 'UNION'];
                    $result['dangerous_tokens'][] = ['type' => 'KEYWORD', 'value' => 'SELECT'];

                    return $result;
                }
            }
        }

        return $result;
    }

    /**
     * Check for Boolean-based blind injection.
     *
     * Pattern: OR 1=1, AND 1=1, OR 'a'='a', etc.
     */
    private function checkBooleanInjection(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        for ($i = 0; $i < count($tokens) - 2; $i++) {
            // Look for OR/AND followed by comparison
            if ($this->isTokenLogical($tokens[$i], ['OR', 'AND'])) {
                $logical = strtoupper($tokens[$i]['value']);

                // Check for pattern: LOGICAL VALUE COMPARISON VALUE
                if (isset($tokens[$i + 1], $tokens[$i + 2], $tokens[$i + 3])) {
                    $left = $tokens[$i + 1];
                    $op = $tokens[$i + 2];
                    $right = $tokens[$i + 3];

                    // Check for tautology: 1=1, 'a'='a', 1>0, etc.
                    if ($op['type'] === SQLTokenizer::T_COMPARISON) {
                        // Same value comparison (1=1, 'a'='a')
                        if ($this->isSameValue($left, $right)) {
                            $result['detected'] = true;
                            $result['confidence'] = max($result['confidence'], 0.90);
                            $result['attack_type'] = self::ATTACK_BOOLEAN;
                            $result['evidence'][] = "Boolean injection: {$logical} tautology detected";
                            $result['dangerous_tokens'][] = ['type' => 'LOGICAL', 'value' => $logical];
                        }

                        // Always true comparisons (1>0, 2>1)
                        if ($this->isAlwaysTrue($left, $op, $right)) {
                            $result['detected'] = true;
                            $result['confidence'] = max($result['confidence'], 0.85);
                            $result['attack_type'] = self::ATTACK_BOOLEAN;
                            $result['evidence'][] = 'Boolean injection: always-true comparison';
                        }
                    }
                }

                // Check for: OR TRUE, AND FALSE
                if (isset($tokens[$i + 1])) {
                    $next = strtoupper($tokens[$i + 1]['value']);
                    if (in_array($next, ['TRUE', 'FALSE', '1', '0'], true)) {
                        $result['detected'] = true;
                        $result['confidence'] = max($result['confidence'], 0.75);
                        $result['attack_type'] = self::ATTACK_BOOLEAN;
                        $result['evidence'][] = "Boolean injection: {$logical} {$next}";
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Check for time-based blind injection.
     *
     * Pattern: SLEEP(n), BENCHMARK(n, expr), WAITFOR DELAY, pg_sleep(n)
     */
    private function checkTimeBasedInjection(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        $timeFunctions = ['SLEEP', 'BENCHMARK', 'PG_SLEEP', 'WAITFOR', 'DELAY'];

        for ($i = 0; $i < count($tokens); $i++) {
            $upper = strtoupper($tokens[$i]['value']);

            if (in_array($upper, $timeFunctions, true)) {
                $result['detected'] = true;
                $result['confidence'] = 0.95;
                $result['attack_type'] = self::ATTACK_TIME;
                $result['evidence'][] = "Time-based injection: {$upper} function detected";
                $result['dangerous_tokens'][] = ['type' => 'FUNCTION', 'value' => $upper];
            }

            // WAITFOR DELAY pattern (SQL Server)
            if ($upper === 'WAITFOR' && isset($tokens[$i + 1]) && strtoupper($tokens[$i + 1]['value']) === 'DELAY') {
                $result['detected'] = true;
                $result['confidence'] = 0.98;
                $result['attack_type'] = self::ATTACK_TIME;
                $result['evidence'][] = 'Time-based injection: WAITFOR DELAY pattern detected';
            }
        }

        return $result;
    }

    /**
     * Check for error-based injection.
     *
     * Pattern: EXTRACTVALUE, UPDATEXML, XMLType, etc.
     */
    private function checkErrorBasedInjection(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        $errorFunctions = ['EXTRACTVALUE', 'UPDATEXML', 'XMLTYPE', 'XMLELEMENT', 'EXP', 'GTID_SUBSET'];

        for ($i = 0; $i < count($tokens); $i++) {
            $upper = strtoupper($tokens[$i]['value']);

            if (in_array($upper, $errorFunctions, true)) {
                $result['detected'] = true;
                $result['confidence'] = 0.90;
                $result['attack_type'] = self::ATTACK_ERROR;
                $result['evidence'][] = "Error-based injection: {$upper} function detected";
                $result['dangerous_tokens'][] = ['type' => 'FUNCTION', 'value' => $upper];
            }
        }

        return $result;
    }

    /**
     * Check for stacked queries (multiple statements).
     *
     * Pattern: ; SELECT, ; DROP, ; INSERT, etc.
     */
    private function checkStackedQueries(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        $statementStarters = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'TRUNCATE', 'EXEC', 'EXECUTE'];

        for ($i = 0; $i < count($tokens) - 1; $i++) {
            if ($tokens[$i]['type'] === SQLTokenizer::T_PUNCTUATION && $tokens[$i]['value'] === ';') {
                // Check if next token starts a new statement
                $nextIdx = $i + 1;
                while ($nextIdx < count($tokens) && $tokens[$nextIdx]['type'] === SQLTokenizer::T_WHITESPACE) {
                    $nextIdx++;
                }

                if (isset($tokens[$nextIdx])) {
                    $nextUpper = strtoupper($tokens[$nextIdx]['value']);
                    if (in_array($nextUpper, $statementStarters, true)) {
                        $result['detected'] = true;
                        $result['confidence'] = 0.92;
                        $result['attack_type'] = self::ATTACK_STACKED;
                        $result['evidence'][] = "Stacked queries: semicolon followed by {$nextUpper}";
                        $result['dangerous_tokens'][] = ['type' => 'PUNCTUATION', 'value' => ';'];
                        $result['dangerous_tokens'][] = ['type' => 'KEYWORD', 'value' => $nextUpper];
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Check for comment-based injection/bypass.
     *
     * Pattern: --, /*, #, comment in middle of keyword
     */
    private function checkCommentInjection(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        $hasComment = false;
        $hasKeyword = false;

        foreach ($tokens as $token) {
            if ($token['type'] === SQLTokenizer::T_COMMENT) {
                $hasComment = true;
                $result['evidence'][] = 'SQL comment detected: ' . substr($token['value'], 0, 20);
            }
            if ($token['type'] === SQLTokenizer::T_KEYWORD) {
                $hasKeyword = true;
            }
        }

        // Comment with SQL keywords is suspicious
        if ($hasComment && $hasKeyword) {
            $result['detected'] = true;
            $result['confidence'] = 0.70;
            $result['attack_type'] = self::ATTACK_COMMENT;
        } elseif ($hasComment) {
            // Just comment, might be bypass attempt
            $result['detected'] = true;
            $result['confidence'] = 0.40;
            $result['attack_type'] = self::ATTACK_COMMENT;
        }

        return $result;
    }

    /**
     * Check for tautology attacks.
     *
     * Pattern: WHERE 1=1, WHERE 'x'='x', WHERE 1 LIKE 1
     */
    private function checkTautology(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        for ($i = 0; $i < count($tokens) - 2; $i++) {
            // WHERE followed by tautology
            if ($this->isTokenKeyword($tokens[$i], 'WHERE')) {
                // Look for tautology pattern in next tokens
                for ($j = $i + 1; $j < min($i + 10, count($tokens) - 2); $j++) {
                    if ($tokens[$j + 1]['type'] === SQLTokenizer::T_COMPARISON) {
                        if ($this->isSameValue($tokens[$j], $tokens[$j + 2])) {
                            $result['detected'] = true;
                            $result['confidence'] = 0.85;
                            $result['attack_type'] = self::ATTACK_TAUTOLOGY;
                            $result['evidence'][] = 'Tautology after WHERE clause';

                            return $result;
                        }
                    }
                }
            }
        }

        return $result;
    }

    /**
     * Check for dangerous function usage.
     */
    private function checkDangerousFunctions(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        $criticalFunctions = [
            'LOAD_FILE' => 0.95,
            'INTO_OUTFILE' => 0.98,
            'INTO_DUMPFILE' => 0.98,
            'XP_CMDSHELL' => 0.99,
            'SP_EXECUTESQL' => 0.85,
            'OPENROWSET' => 0.90,
            'OPENDATASOURCE' => 0.90,
            'PG_READ_FILE' => 0.95,
            'UTL_HTTP' => 0.90,
            'DBMS_PIPE' => 0.85,
        ];

        $infoFunctions = [
            'DATABASE' => 0.60,
            'VERSION' => 0.55,
            'USER' => 0.50,
            'CURRENT_USER' => 0.55,
            'SYSTEM_USER' => 0.60,
        ];

        foreach ($tokens as $token) {
            $upper = strtoupper($token['value']);

            if (isset($criticalFunctions[$upper])) {
                $result['detected'] = true;
                $result['confidence'] = max($result['confidence'], $criticalFunctions[$upper]);
                $result['attack_type'] = self::ATTACK_ILLEGAL;
                $result['evidence'][] = "Critical function: {$upper}";
                $result['dangerous_tokens'][] = ['type' => 'FUNCTION', 'value' => $upper];
            }

            if (isset($infoFunctions[$upper])) {
                // Info functions alone are not definitive, but combined with other patterns...
                $result['confidence'] = max($result['confidence'], $infoFunctions[$upper]);
                $result['evidence'][] = "Information function: {$upper}";
                if ($result['confidence'] >= 0.5) {
                    $result['detected'] = true;
                    $result['attack_type'] ??= self::ATTACK_ILLEGAL;
                }
            }
        }

        return $result;
    }

    /**
     * Check for suspicious patterns.
     */
    private function checkSuspiciousPatterns(array $tokens): array
    {
        $result = ['detected' => false, 'confidence' => 0.0, 'attack_type' => null, 'evidence' => [], 'dangerous_tokens' => []];

        $keywordCount = 0;
        $hasComparison = false;
        $hasLogical = false;

        foreach ($tokens as $token) {
            if ($token['type'] === SQLTokenizer::T_KEYWORD) {
                $keywordCount++;
            }
            if ($token['type'] === SQLTokenizer::T_COMPARISON) {
                $hasComparison = true;
            }
            if ($token['type'] === SQLTokenizer::T_LOGICAL) {
                $hasLogical = true;
            }
        }

        // Multiple SQL keywords in user input is very suspicious
        if ($keywordCount >= 3) {
            $result['detected'] = true;
            $result['confidence'] = min(0.70 + ($keywordCount * 0.05), 0.95);
            $result['attack_type'] = self::ATTACK_ILLEGAL;
            $result['evidence'][] = "Multiple SQL keywords detected: {$keywordCount}";
        }

        // Keywords + comparison + logical = likely injection
        if ($keywordCount >= 1 && $hasComparison && $hasLogical) {
            $result['detected'] = true;
            $result['confidence'] = max($result['confidence'], 0.75);
            $result['attack_type'] ??= self::ATTACK_PIGGYBACK;
            $result['evidence'][] = 'SQL clause structure detected in input';
        }

        return $result;
    }

    /**
     * Check if token is a specific keyword.
     */
    private function isTokenKeyword(array $token, string $keyword): bool
    {
        return $token['type'] === SQLTokenizer::T_KEYWORD
            && strtoupper($token['value']) === strtoupper($keyword);
    }

    /**
     * Check if token is a logical operator.
     */
    private function isTokenLogical(array $token, array $operators): bool
    {
        return $token['type'] === SQLTokenizer::T_LOGICAL
            && in_array(strtoupper($token['value']), $operators, true);
    }

    /**
     * Check if two tokens represent the same value (for tautology detection).
     */
    private function isSameValue(array $left, array $right): bool
    {
        // Same type and value
        if ($left['type'] === $right['type'] && $left['value'] === $right['value']) {
            return true;
        }

        // Both numbers with same numeric value
        if ($left['type'] === SQLTokenizer::T_NUMBER && $right['type'] === SQLTokenizer::T_NUMBER) {
            return (float) $left['value'] === (float) $right['value'];
        }

        // Both strings (strip quotes and compare)
        if ($left['type'] === SQLTokenizer::T_STRING && $right['type'] === SQLTokenizer::T_STRING) {
            $leftVal = trim($left['value'], "\"'`");
            $rightVal = trim($right['value'], "\"'`");

            return $leftVal === $rightVal;
        }

        return false;
    }

    /**
     * Check if comparison is always true (like 1>0, 2>1).
     */
    private function isAlwaysTrue(array $left, array $op, array $right): bool
    {
        if ($left['type'] !== SQLTokenizer::T_NUMBER || $right['type'] !== SQLTokenizer::T_NUMBER) {
            return false;
        }

        $leftNum = (float) $left['value'];
        $rightNum = (float) $right['value'];
        $operator = $op['value'];

        return match ($operator) {
            '>' => $leftNum > $rightNum,
            '<' => $leftNum < $rightNum,
            '>=' => $leftNum >= $rightNum,
            '<=' => $leftNum <= $rightNum,
            '=' => $leftNum === $rightNum,
            '!=' , '<>' => $leftNum !== $rightNum,
            default => false,
        };
    }
}
