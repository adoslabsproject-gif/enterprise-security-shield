<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\Detection;

/**
 * GraphQL Security Protector.
 *
 * Protects against GraphQL-specific attacks:
 * - Query depth attacks (deeply nested queries)
 * - Query complexity attacks (expensive operations)
 * - Batching abuse (many operations in one request)
 * - Introspection abuse (schema discovery)
 * - Field duplication attacks
 * - Alias-based attacks
 *
 * @see https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
 */
final class GraphQLProtector
{
    /**
     * Maximum allowed query depth.
     */
    private int $maxDepth = 10;

    /**
     * Maximum allowed query complexity.
     */
    private int $maxComplexity = 1000;

    /**
     * Maximum operations per batch.
     */
    private int $maxBatchSize = 10;

    /**
     * Maximum aliases per query.
     */
    private int $maxAliases = 50;

    /**
     * Maximum field duplications.
     */
    private int $maxFieldDuplications = 20;

    /**
     * Allow introspection queries.
     */
    private bool $allowIntrospection = false;

    /**
     * Complexity cost per field (default).
     */
    private int $fieldCost = 1;

    /**
     * Complexity multiplier for lists.
     */
    private int $listMultiplier = 10;

    /**
     * Blocked field patterns (regex).
     *
     * @var array<string>
     */
    private array $blockedFields = [];

    /**
     * Constructor.
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(array $config = [])
    {
        $this->maxDepth = $config['max_depth'] ?? 10;
        $this->maxComplexity = $config['max_complexity'] ?? 1000;
        $this->maxBatchSize = $config['max_batch_size'] ?? 10;
        $this->maxAliases = $config['max_aliases'] ?? 50;
        $this->maxFieldDuplications = $config['max_field_duplications'] ?? 20;
        $this->allowIntrospection = $config['allow_introspection'] ?? false;
        $this->fieldCost = $config['field_cost'] ?? 1;
        $this->listMultiplier = $config['list_multiplier'] ?? 10;
        $this->blockedFields = $config['blocked_fields'] ?? [];
    }

    /**
     * Analyze GraphQL request for security issues.
     *
     * @param string|array<mixed> $query GraphQL query string or parsed operation
     * @param array<string, mixed>|null $variables Query variables
     *
     * @return array{
     *     allowed: bool,
     *     errors: array<string>,
     *     warnings: array<string>,
     *     metrics: array{depth: int, complexity: int, aliases: int, operations: int},
     *     attacks_detected: array<string>
     * }
     */
    public function analyze(string|array $query, ?array $variables = null): array
    {
        $errors = [];
        $warnings = [];
        $attacksDetected = [];

        // Handle batch queries (array of operations)
        if (is_array($query)) {
            return $this->analyzeBatch($query);
        }

        // Parse the query
        $parsed = $this->parseQuery($query);

        if ($parsed === null) {
            $errors[] = 'Failed to parse GraphQL query';

            return [
                'allowed' => false,
                'errors' => $errors,
                'warnings' => $warnings,
                'metrics' => ['depth' => 0, 'complexity' => 0, 'aliases' => 0, 'operations' => 0],
                'attacks_detected' => ['PARSE_ERROR'],
            ];
        }

        // Check 1: Query depth
        $depth = $this->calculateDepth($parsed);
        if ($depth > $this->maxDepth) {
            $errors[] = "Query depth ({$depth}) exceeds maximum ({$this->maxDepth})";
            $attacksDetected[] = 'DEPTH_ATTACK';
        }

        // Check 2: Query complexity
        $complexity = $this->calculateComplexity($parsed, $variables);
        if ($complexity > $this->maxComplexity) {
            $errors[] = "Query complexity ({$complexity}) exceeds maximum ({$this->maxComplexity})";
            $attacksDetected[] = 'COMPLEXITY_ATTACK';
        }

        // Check 3: Alias count
        $aliasCount = $this->countAliases($parsed);
        if ($aliasCount > $this->maxAliases) {
            $errors[] = "Alias count ({$aliasCount}) exceeds maximum ({$this->maxAliases})";
            $attacksDetected[] = 'ALIAS_ABUSE';
        }

        // Check 4: Field duplication
        $duplications = $this->countFieldDuplications($parsed);
        if ($duplications > $this->maxFieldDuplications) {
            $errors[] = "Field duplications ({$duplications}) exceeds maximum ({$this->maxFieldDuplications})";
            $attacksDetected[] = 'FIELD_DUPLICATION';
        }

        // Check 5: Introspection
        if (!$this->allowIntrospection && $this->hasIntrospection($query)) {
            $errors[] = 'Introspection queries are disabled';
            $attacksDetected[] = 'INTROSPECTION_BLOCKED';
        }

        // Check 6: Blocked fields
        $blockedFieldsFound = $this->findBlockedFields($parsed);
        if (!empty($blockedFieldsFound)) {
            $errors[] = 'Blocked fields detected: ' . implode(', ', $blockedFieldsFound);
            $attacksDetected[] = 'BLOCKED_FIELDS';
        }

        // Check 7: Dangerous patterns
        $dangerousPatterns = $this->detectDangerousPatterns($query);
        if (!empty($dangerousPatterns)) {
            foreach ($dangerousPatterns as $pattern) {
                $warnings[] = "Dangerous pattern: {$pattern}";
            }
            $attacksDetected[] = 'DANGEROUS_PATTERNS';
        }

        // Check 8: Variable injection
        if ($variables !== null) {
            $injectionRisks = $this->checkVariableInjection($variables);
            if (!empty($injectionRisks)) {
                foreach ($injectionRisks as $risk) {
                    $warnings[] = "Variable injection risk: {$risk}";
                }
                $attacksDetected[] = 'VARIABLE_INJECTION';
            }
        }

        $operationCount = $this->countOperations($parsed);

        return [
            'allowed' => empty($errors),
            'errors' => $errors,
            'warnings' => $warnings,
            'metrics' => [
                'depth' => $depth,
                'complexity' => $complexity,
                'aliases' => $aliasCount,
                'operations' => $operationCount,
            ],
            'attacks_detected' => $attacksDetected,
        ];
    }

    /**
     * Analyze batch of GraphQL operations.
     *
     * @param array<mixed> $operations
     *
     * @return array{
     *     allowed: bool,
     *     errors: array<string>,
     *     warnings: array<string>,
     *     metrics: array{depth: int, complexity: int, aliases: int, operations: int},
     *     attacks_detected: array<string>
     * }
     */
    private function analyzeBatch(array $operations): array
    {
        $errors = [];
        $warnings = [];
        $attacksDetected = [];
        $totalDepth = 0;
        $totalComplexity = 0;
        $totalAliases = 0;

        // Check batch size
        $batchSize = count($operations);
        if ($batchSize > $this->maxBatchSize) {
            $errors[] = "Batch size ({$batchSize}) exceeds maximum ({$this->maxBatchSize})";
            $attacksDetected[] = 'BATCH_ABUSE';
        }

        // Analyze each operation
        foreach ($operations as $index => $operation) {
            $query = $operation['query'] ?? '';
            $variables = $operation['variables'] ?? null;

            $result = $this->analyze($query, $variables);

            if (!$result['allowed']) {
                foreach ($result['errors'] as $error) {
                    $errors[] = "Operation {$index}: {$error}";
                }
            }

            $warnings = array_merge($warnings, $result['warnings']);
            $attacksDetected = array_merge($attacksDetected, $result['attacks_detected']);

            $totalDepth = max($totalDepth, $result['metrics']['depth']);
            $totalComplexity += $result['metrics']['complexity'];
            $totalAliases += $result['metrics']['aliases'];
        }

        // Check combined complexity
        if ($totalComplexity > $this->maxComplexity) {
            $errors[] = "Combined batch complexity ({$totalComplexity}) exceeds maximum ({$this->maxComplexity})";
            $attacksDetected[] = 'BATCH_COMPLEXITY';
        }

        return [
            'allowed' => empty($errors),
            'errors' => $errors,
            'warnings' => array_unique($warnings),
            'metrics' => [
                'depth' => $totalDepth,
                'complexity' => $totalComplexity,
                'aliases' => $totalAliases,
                'operations' => $batchSize,
            ],
            'attacks_detected' => array_unique($attacksDetected),
        ];
    }

    /**
     * Parse GraphQL query into a simplified AST.
     *
     * Note: This is a simplified parser. For production, use graphql-php library.
     *
     * @return array<mixed>|null
     */
    private function parseQuery(string $query): ?array
    {
        // Remove comments
        $query = preg_replace('/#[^\n]*/', '', $query);

        // Basic structure extraction
        $structure = [
            'operations' => [],
            'fragments' => [],
            'fields' => [],
        ];

        // Find operations (query, mutation, subscription)
        if (preg_match_all('/\b(query|mutation|subscription)\s*(\w*)\s*(\([^)]*\))?\s*\{/i', $query, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $structure['operations'][] = [
                    'type' => strtolower($match[1]),
                    'name' => $match[2] ?? '',
                ];
            }
        }

        // If no explicit operation, it's an anonymous query
        if (empty($structure['operations']) && str_contains($query, '{')) {
            $structure['operations'][] = [
                'type' => 'query',
                'name' => '',
            ];
        }

        // Find fragments
        if (preg_match_all('/fragment\s+(\w+)\s+on\s+(\w+)/i', $query, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $structure['fragments'][] = [
                    'name' => $match[1],
                    'type' => $match[2],
                ];
            }
        }

        // Extract fields with aliases
        if (preg_match_all('/(\w+)\s*:\s*(\w+)|(\w+)\s*(?:\([^)]*\))?\s*\{/i', $query, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                if (!empty($match[1])) {
                    // Aliased field
                    $structure['fields'][] = [
                        'alias' => $match[1],
                        'name' => $match[2],
                    ];
                } elseif (!empty($match[3])) {
                    // Regular field
                    $structure['fields'][] = [
                        'alias' => null,
                        'name' => $match[3],
                    ];
                }
            }
        }

        // Store raw query for depth calculation
        $structure['raw'] = $query;

        return $structure;
    }

    /**
     * Calculate query depth by counting nested braces.
     */
    private function calculateDepth(array $parsed): int
    {
        $query = $parsed['raw'] ?? '';

        // Remove strings to avoid counting braces in them
        $query = preg_replace('/"[^"]*"/', '', $query);

        $maxDepth = 0;
        $currentDepth = 0;

        for ($i = 0; $i < strlen($query); $i++) {
            if ($query[$i] === '{') {
                $currentDepth++;
                $maxDepth = max($maxDepth, $currentDepth);
            } elseif ($query[$i] === '}') {
                $currentDepth--;
            }
        }

        return $maxDepth;
    }

    /**
     * Calculate query complexity.
     *
     * @param array<string, mixed>|null $variables
     */
    private function calculateComplexity(array $parsed, ?array $variables): int
    {
        $query = $parsed['raw'] ?? '';
        $complexity = 0;

        // Count fields
        $fieldCount = count($parsed['fields'] ?? []);
        $complexity += $fieldCount * $this->fieldCost;

        // Check for list arguments (first, last, limit)
        if (preg_match_all('/\b(first|last|limit)\s*:\s*(\$\w+|\d+)/i', $query, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $value = $match[2];

                // Resolve variable
                if (str_starts_with($value, '$') && $variables !== null) {
                    $varName = substr($value, 1);
                    $value = $variables[$varName] ?? 10;
                }

                $listSize = min((int) $value, 100); // Cap at 100
                $complexity += $listSize * $this->listMultiplier;
            }
        }

        // Fragment spreads add complexity
        $fragmentCount = substr_count($query, '...');
        $complexity += $fragmentCount * 10;

        // Depth multiplier
        $depth = $this->calculateDepth($parsed);
        $complexity = (int) ($complexity * (1 + ($depth * 0.1)));

        return $complexity;
    }

    /**
     * Count aliases in query.
     */
    private function countAliases(array $parsed): int
    {
        $count = 0;

        foreach ($parsed['fields'] ?? [] as $field) {
            if (!empty($field['alias'])) {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Count field duplications (same field requested multiple times).
     */
    private function countFieldDuplications(array $parsed): int
    {
        $fieldNames = [];

        foreach ($parsed['fields'] ?? [] as $field) {
            $name = $field['name'];
            $fieldNames[$name] = ($fieldNames[$name] ?? 0) + 1;
        }

        $duplications = 0;
        foreach ($fieldNames as $count) {
            if ($count > 1) {
                $duplications += $count - 1;
            }
        }

        return $duplications;
    }

    /**
     * Check if query contains introspection.
     */
    private function hasIntrospection(string $query): bool
    {
        $introspectionFields = [
            '__schema',
            '__type',
            '__typename',
            '__directive',
            '__directiveLocation',
            '__enumValue',
            '__field',
            '__inputValue',
        ];

        foreach ($introspectionFields as $field) {
            if (str_contains($query, $field)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Find blocked fields in query.
     *
     * @return array<string>
     */
    private function findBlockedFields(array $parsed): array
    {
        $found = [];

        foreach ($parsed['fields'] ?? [] as $field) {
            $name = $field['name'];

            foreach ($this->blockedFields as $pattern) {
                if (preg_match($pattern, $name)) {
                    $found[] = $name;
                    break;
                }
            }
        }

        return array_unique($found);
    }

    /**
     * Detect dangerous patterns in query.
     *
     * @return array<string>
     */
    private function detectDangerousPatterns(string $query): array
    {
        $patterns = [];

        // Recursive fragment (potential DoS)
        if (preg_match('/fragment\s+(\w+).*\.\.\.\1/s', $query)) {
            $patterns[] = 'Recursive fragment detected';
        }

        // Multiple mutations in single request
        if (substr_count(strtolower($query), 'mutation') > 3) {
            $patterns[] = 'Multiple mutations in single request';
        }

        // Deeply nested inline fragments
        if (preg_match('/(\.\.\.\s*on\s*\w+\s*\{){4,}/', $query)) {
            $patterns[] = 'Deeply nested inline fragments';
        }

        // Extremely long field names (potential buffer overflow attempt)
        if (preg_match('/\b\w{100,}\b/', $query)) {
            $patterns[] = 'Extremely long identifier';
        }

        return $patterns;
    }

    /**
     * Check variables for injection risks.
     *
     * @param array<string, mixed> $variables
     *
     * @return array<string>
     */
    private function checkVariableInjection(array $variables): array
    {
        $risks = [];

        foreach ($variables as $name => $value) {
            if (is_string($value)) {
                // Check for GraphQL injection in strings
                if (preg_match('/[{}()\[\]]/', $value)) {
                    $risks[] = "Variable '{$name}' contains GraphQL syntax characters";
                }

                // Check for extremely long strings
                if (strlen($value) > 10000) {
                    $risks[] = "Variable '{$name}' is extremely long";
                }

                // Check for null bytes
                if (str_contains($value, "\0")) {
                    $risks[] = "Variable '{$name}' contains null bytes";
                }
            } elseif (is_array($value) && count($value) > 1000) {
                $risks[] = "Variable '{$name}' is an extremely large array";
            }
        }

        return $risks;
    }

    /**
     * Count operations in query.
     */
    private function countOperations(array $parsed): int
    {
        return count($parsed['operations'] ?? []);
    }

    /**
     * Set maximum query depth.
     */
    public function setMaxDepth(int $depth): self
    {
        $this->maxDepth = $depth;

        return $this;
    }

    /**
     * Set maximum query complexity.
     */
    public function setMaxComplexity(int $complexity): self
    {
        $this->maxComplexity = $complexity;

        return $this;
    }

    /**
     * Enable or disable introspection.
     */
    public function setAllowIntrospection(bool $allow): self
    {
        $this->allowIntrospection = $allow;

        return $this;
    }

    /**
     * Add a blocked field pattern.
     */
    public function addBlockedField(string $pattern): self
    {
        $this->blockedFields[] = $pattern;

        return $this;
    }

    /**
     * Set maximum batch size.
     */
    public function setMaxBatchSize(int $size): self
    {
        $this->maxBatchSize = $size;

        return $this;
    }
}
