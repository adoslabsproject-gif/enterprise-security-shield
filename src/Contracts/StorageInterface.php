<?php

namespace Senza1dio\SecurityShield\Contracts;

/**
 * Storage Interface - Framework-Agnostic Data Persistence
 *
 * Allows SecurityShield to work with any backend:
 * - Redis (recommended for production)
 * - Database (PostgreSQL, MySQL, SQLite)
 * - Memory (for testing)
 * - Custom implementations
 */
interface StorageInterface
{
    /**
     * Store IP threat score
     *
     * @param string $ip Client IP address
     * @param int $score Current threat score
     * @param int $ttl Time to live in seconds
     * @return bool Success
     */
    public function setScore(string $ip, int $score, int $ttl): bool;

    /**
     * Get IP threat score
     *
     * @param string $ip Client IP address
     * @return int|null Score or null if not found
     */
    public function getScore(string $ip): ?int;

    /**
     * Increment IP threat score
     *
     * @param string $ip Client IP address
     * @param int $points Points to add
     * @param int $ttl Time to live in seconds
     * @return int New score
     */
    public function incrementScore(string $ip, int $points, int $ttl): int;

    /**
     * Check if IP is banned
     *
     * @param string $ip Client IP address
     * @return bool True if banned
     */
    public function isBanned(string $ip): bool;

    /**
     * Ban an IP address
     *
     * @param string $ip Client IP address
     * @param int $duration Ban duration in seconds
     * @param string $reason Ban reason
     * @return bool Success
     */
    public function banIP(string $ip, int $duration, string $reason): bool;

    /**
     * Unban an IP address
     *
     * @param string $ip Client IP address
     * @return bool Success
     */
    public function unbanIP(string $ip): bool;

    /**
     * Store bot verification result in cache
     *
     * @param string $ip Bot IP address
     * @param bool $isLegitimate Verification result
     * @param array<string, mixed> $metadata Bot metadata (user_agent, hostname, etc.)
     * @param int $ttl Cache TTL in seconds
     * @return bool Success
     */
    public function cacheBotVerification(string $ip, bool $isLegitimate, array $metadata, int $ttl): bool;

    /**
     * Get cached bot verification result
     *
     * @param string $ip Bot IP address
     * @return array<string, mixed>|null ['verified' => bool, 'metadata' => array] or null
     */
    public function getCachedBotVerification(string $ip): ?array;

    /**
     * Log security event (attack, honeypot access, etc.)
     *
     * @param string $type Event type (scan, honeypot, ban, etc.)
     * @param string $ip Client IP
     * @param array<string, mixed> $data Event data
     * @return bool Success
     */
    public function logSecurityEvent(string $type, string $ip, array $data): bool;

    /**
     * Get recent security events
     *
     * @param int $limit Number of events to retrieve
     * @param string|null $type Filter by event type
     * @return array<int, array<string, mixed>> Array of events
     */
    public function getRecentEvents(int $limit = 100, ?string $type = null): array;

    /**
     * Increment request count for IP (rate limiting)
     *
     * Increments the request counter for a specific IP within a time window.
     * Used for rate limiting to prevent abuse and DDoS attacks.
     *
     * @param string $ip Client IP address
     * @param int $window Time window in seconds
     * @return int Current request count after increment
     */
    public function incrementRequestCount(string $ip, int $window): int;

    /**
     * Get request count for IP (rate limiting)
     *
     * Retrieves the current request count for a specific IP within a time window.
     * Returns 0 if no requests recorded or window expired.
     *
     * @param string $ip Client IP address
     * @param int $window Time window in seconds (not used in get, but kept for interface consistency)
     * @return int Current request count (0 if not found or expired)
     */
    public function getRequestCount(string $ip, int $window): int;

    /**
     * Clear all data (for testing)
     *
     * @return bool Success
     */
    public function clear(): bool;
}
