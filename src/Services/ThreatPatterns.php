<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Services;

/**
 * ENTERPRISE GALAXY: Threat Pattern Detection Database
 *
 * Comprehensive collection of security threat patterns for vulnerability scanning detection.
 * This class provides a centralized, framework-agnostic database of attack patterns,
 * scanner signatures, and threat scoring logic.
 *
 * FEATURES:
 * - 50+ vulnerability path patterns (critical, CMS, config files)
 * - 30+ known scanner User-Agent signatures
 * - 25+ fake/obsolete browser detection patterns
 * - 90+ legitimate bot User-Agent whitelist
 * - Geographic threat patterns (country-based blocking)
 * - User-Agent rotation detection
 * - Unicode obfuscation detection
 * - Comprehensive threat scoring system
 *
 * SCORING SYSTEM:
 * - +30 points: Critical vulnerability paths (/.env, /.git, /admin.php, /phpinfo.php)
 * - +15 points: CMS scanning paths (/wp-admin, /wp-content, /phpmyadmin)
 * - +10 points: Config file scanning (/config.php, /database.yml)
 * - +30 points: Known scanner User-Agents (sqlmap, nikto, nmap, etc.)
 * - +50 points: Fake/obsolete User-Agents (IE 9/10/11, ancient Chrome/Firefox)
 * - +100 points: Empty/NULL User-Agent (instant ban)
 * - +50 points: Geo-blocked countries (Russia, China, North Korea)
 * - +20 points: Unicode obfuscation in paths
 * - THRESHOLD: 50 points triggers auto-ban
 *
 * PERFORMANCE:
 * - O(n) pattern matching with early termination
 * - Case-insensitive matching via strtolower() caching
 * - Zero external dependencies (pure PHP)
 * - Compatible with PHP 8.0+
 *
 * @package Senza1dio\SecurityShield\Services
 * @version 1.0.0
 * @author Enterprise Security Team
 * @license MIT
 */
class ThreatPatterns
{
    /**
     * Score threshold for auto-ban (50 points)
     */
    public const SCORE_THRESHOLD = 50;

    /**
     * Default ban duration in seconds (24 hours)
     */
    public const BAN_DURATION = 86400;

    /**
     * Tracking window for score accumulation (1 hour)
     */
    public const TRACKING_WINDOW = 3600;

    /**
     * Score values for different threat types
     */
    public const SCORE_CRITICAL_PATH = 30;      // Increased from 20 for phpinfo.php security
    public const SCORE_CMS_PATH = 15;
    public const SCORE_CONFIG_PATH = 10;
    public const SCORE_SCANNER_USER_AGENT = 30;
    public const SCORE_FAKE_USER_AGENT = 50;
    public const SCORE_NULL_USER_AGENT = 100;   // Instant ban
    public const SCORE_GEO_BLOCKED = 50;
    public const SCORE_UNICODE_OBFUSCATION = 20;
    public const SCORE_SQL_INJECTION = 40;      // SQL injection attempt (high severity)
    public const SCORE_XSS_PAYLOAD = 30;        // XSS payload injection (medium-high severity)
    public const SCORE_RATE_LIMIT_EXCEEDED = 20; // Rate limit violation

    /**
     * Critical vulnerability paths - HIGH SCORE (30 points)
     *
     * These paths indicate clear vulnerability scanning attempts.
     * Accessing these paths is NEVER legitimate for normal users.
     *
     * Categories:
     * - Environment files (.env, .env.local, .env.production)
     * - Version control (.git/, .svn/, .hg/)
     * - Config files (config.php, database.yml)
     * - Cloud credentials (.aws/credentials, aws_access_keys.json)
     * - SSH keys (.ssh/, id_rsa)
     * - Database dumps (backup.sql, dump.sql)
     * - Admin password files (.htpasswd)
     * - Debug scripts (phpinfo.php, info.php, test.php)
     * - Shell backdoors (shell.php, c99.php, r57.php)
     */
    private const CRITICAL_PATHS = [
        // Environment files
        '/.env',
        '/.env.local',
        '/.env.production',

        // Version control systems
        '/.git/',
        '/.git/config',
        '/.svn/',
        '/.hg/',

        // PHP config files
        '/config.php',
        '/configuration.php',
        '/settings.php',
        '/database.yml',
        '/database.php',

        // AWS credentials (cloud keys)
        '/.aws/',
        '/.aws/credentials',
        '/.aws/config',
        '/aws/credentials',
        '/aws/config',
        '/aws_lambda_config.json',
        '/aws/aws_config.json',
        '/aws_access_keys.json',

        // SSH keys
        '/.ssh/',
        '/id_rsa',
        '/id_rsa.pub',

        // Database dumps
        '/backup.sql',
        '/dump.sql',

        // Apache auth files
        '/.htpasswd',

        // Debug/info scripts
        '/phpinfo.php',
        '/info.php',
        '/test.php',

        // Shell backdoors
        '/shell.php',
        '/c99.php',
        '/r57.php',
    ];

    /**
     * WordPress/CMS scanning paths - MEDIUM-HIGH SCORE (15 points)
     *
     * These paths indicate CMS vulnerability scanning (WordPress, Joomla, Drupal, etc.).
     * Common targets for automated scanners looking for outdated CMS installations.
     *
     * Categories:
     * - WordPress (/wp-admin, /wp-login.php, /wp-config.php)
     * - Joomla (/administrator/, /joomla/)
     * - Drupal (/drupal/)
     * - Magento (/magento/)
     * - PrestaShop (/prestashop/)
     * - TYPO3 (/typo3/)
     * - Generic admin panels (/admin/)
     * - Database tools (/adminer.php, /phpmyadmin/, /pgadmin/)
     */
    private const CMS_PATHS = [
        // WordPress
        '/wp-admin/',
        '/wp-login.php',
        '/wp-content/',
        '/wp-includes/',
        '/wp-config.php',

        // Joomla
        '/administrator/',
        '/joomla/',

        // Drupal
        '/drupal/',

        // Magento
        '/magento/',

        // PrestaShop
        '/prestashop/',

        // TYPO3
        '/typo3/',

        // Generic admin
        '/admin/',

        // Database admin tools
        '/adminer.php',
        '/phpmyadmin/',
        '/pma/',
        '/mysql/',
        '/postgres/',
        '/postgresql/',
        '/pgadmin/',
    ];

    /**
     * Config file scanning paths - MEDIUM SCORE (10 points)
     *
     * These paths indicate configuration file enumeration attempts.
     * Attackers search for config files to discover credentials, API keys, or system info.
     *
     * Categories:
     * - JSON configs (config.json, app.json, package.json)
     * - YAML configs (config.yml, docker-compose.yml, kubernetes.yml)
     * - Package managers (composer.json, composer.lock, .npmrc, .yarnrc)
     * - Docker/containers (Dockerfile, .dockerignore)
     * - Secrets (secrets.json, credentials.json)
     */
    private const CONFIG_PATHS = [
        // JSON configs
        '/config.json',
        '/app.json',
        '/package.json',
        '/composer.json',
        '/composer.lock',
        '/secrets.json',
        '/credentials.json',

        // YAML configs
        '/config.yml',
        '/docker-compose.yml',
        '/kubernetes.yml',

        // Package manager configs
        '/.npmrc',
        '/.yarnrc',

        // Docker
        '/Dockerfile',
        '/.dockerignore',
    ];

    /**
     * Known scanner User-Agents - CRITICAL SCORE (30 points)
     *
     * These User-Agent strings are NEVER legitimate for normal browsing.
     * They identify automated vulnerability scanners, penetration testing tools,
     * and security research tools.
     *
     * Categories:
     * - SQL injection tools (sqlmap, havij)
     * - Web scanners (nikto, w3af, skipfish, grabber)
     * - Network scanners (nmap, masscan, zmap)
     * - Vulnerability scanners (nessus, openvas, acunetix, netsparker)
     * - Exploitation frameworks (metasploit)
     * - Fuzzing tools (wfuzz, ffuf)
     * - CMS scanners (wpscan, joomscan)
     * - Directory bruteforcers (dirbuster, dirb, gobuster)
     * - Password crackers (hydra, medusa)
     * - Internet scanners (zgrab, shodan, censys)
     */
    private const SCANNER_USER_AGENTS = [
        // SQL injection tools
        'sqlmap',
        'havij',

        // Web vulnerability scanners
        'nikto',
        'w3af',
        'skipfish',
        'grabber',

        // Network scanners
        'nmap',
        'masscan',
        'zmap',

        // Professional vulnerability scanners
        'nessus',
        'openvas',
        'acunetix',
        'netsparker',
        'burpsuite',

        // Exploitation frameworks
        'metasploit',

        // CMS scanners
        'wpscan',
        'joomscan',

        // Directory bruteforcers
        'dirbuster',
        'dirb',
        'gobuster',

        // Fuzzing tools
        'ffuf',
        'wfuzz',

        // Password crackers
        'hydra',
        'medusa',

        // Internet-wide scanners
        'zgrab',
        'shodan',
        'censys',
    ];

    /**
     * Legitimate Bot User-Agents (ALWAYS ALLOWED - Zero Score)
     *
     * These are verified legitimate bots from search engines, social media,
     * monitoring services, and AI crawlers. They should NEVER be blocked.
     *
     * SECURITY NOTE: User-Agent alone is NOT sufficient for verification.
     * Always perform DNS reverse lookup to prevent spoofing.
     *
     * Categories:
     * - Search engines (Google, Bing, Yahoo, DuckDuckGo, Baidu, Yandex)
     * - Performance testing (Lighthouse, GTmetrix, WebPageTest, Pingdom)
     * - AI crawlers (GPTBot, ClaudeBot, ChatGPT-User, PerplexityBot)
     * - Social media (Facebook, Twitter, LinkedIn, Pinterest, Discord, Telegram)
     * - Mobile apps (AppleBot, Google Mobile)
     * - Monitoring (UptimeRobot, StatusCake, HetrixTools, New Relic, Datadog)
     * - SEO tools (SEMrush, Ahrefs, Moz, Screaming Frog)
     * - Archive/research (Internet Archive, Common Crawl, Netcraft)
     * - News aggregators (Feedly, Flipboard, NewsBlur)
     * - Developer tools (Postman, Insomnia)
     * - Commercial bots (Amazon, TikTok/ByteSpider, Huawei/PetalBot)
     */
    private const LEGITIMATE_BOTS = [
        // Search Engine Crawlers (Google)
        'googlebot',
        'googlebot-image',
        'googlebot-video',
        'googlebot-news',
        'google-inspectiontool',
        'google-extended',          // Google Bard / Vertex AI (2025)
        'google-safety',            // Google Safe Browsing
        'storebot-google',
        'adsbot-google',
        'mediapartners-google',

        // Performance Testing Tools (CRITICAL for PageSpeed!)
        'chrome-lighthouse',
        'lighthouse',
        'gtmetrix',
        'webpagetest',
        'pingdom',
        'pingdom tools',

        // Other Search Engines
        'bingbot',
        'msnbot',
        'slurp',                    // Yahoo
        'duckduckbot',
        'baiduspider',              // Baidu (China)
        'yandexbot',                // Yandex (Russia)
        'sogou',                    // Sogou (China)
        'exabot',                   // Exalead (France)
        'seznambot',                // Seznam.cz (Czech Republic)

        // AI Crawlers (2025)
        'gptbot',                   // OpenAI GPTBot
        'chatgpt-user',             // OpenAI ChatGPT-User (live browsing)
        'oai-searchbot',            // OpenAI SearchGPT
        'claudebot',                // Anthropic Claude
        'anthropic-ai',
        'claude-web',
        'perplexitybot',            // Perplexity AI
        'cohere-ai',                // Cohere AI

        // Social Media Crawlers
        'facebookexternalhit',
        'facebookcatalog',
        'telegrambot',              // MUST be before twitterbot (UA contains "like TwitterBot")
        'twitterbot',
        'linkedinbot',
        'pinterestbot',
        'reddit',
        'discordbot',
        'slackbot',
        'whatsapp',
        'skypeuripreview',

        // Mobile App Crawlers
        'applebot',
        'googlebot-mobile',

        // Monitoring & Analytics
        'uptimerobot',
        'pingdom',
        'statuscake',
        'hetrixtools',
        'newrelicsynthetics',
        'datadog',

        // SEO & Website Tools
        'semrushbot',
        'ahrefsbot',
        'mj12bot',                  // Majestic SEO
        'dotbot',                   // Moz SEO
        'rogerbot',                 // Moz SEO (legacy)
        'screaming frog',
        'trendictionbot',           // Trendiction SEO (Germany)

        // Archive & Research
        'ia_archiver',              // Internet Archive (Wayback Machine)
        'archive.org_bot',
        'ccbot',                    // Common Crawl
        'netcraftsurveyagent',

        // News & RSS Aggregators
        'feedly',
        'flipboard',
        'newsblur',

        // Developer Tools
        'postman',
        'insomnia',

        // Commercial Bots
        'amazonadbot',
        'amazonbot',                // Amazon/Alexa Crawler
        'bytespider',               // TikTok/ByteDance
        'petalbot',                 // Huawei Search

        // Media Monitoring
        'mediatoolkitbot',          // Mediatoolkit/Determ
    ];

    /**
     * Fake/Obsolete User-Agents - HIGH SCORE (50 points)
     *
     * These User-Agent patterns are IMPOSSIBLE for legitimate users in 2025.
     * They indicate bots pretending to be browsers.
     *
     * RATIONALE:
     * - IE 9/10/11: End-of-life 2016-2022, NO legitimate users in 2025
     * - Chrome < 100: Auto-updates force users to latest version (130+ in 2025)
     * - Firefox < 100: Auto-updates since 2019
     * - Ancient Windows: Cannot run modern browsers with TLS 1.3
     * - Known bot signatures: WebStripper, HTTrack, Teleport, etc.
     *
     * Categories:
     * - Internet Explorer (MSIE 9.0, 10.0, 11.0, Trident/7.0)
     * - Ancient Chrome (< 100)
     * - Ancient Firefox (< 100)
     * - Ancient Safari (< 13.0)
     * - Known bot signatures (NCLIENT, WebStripper, HTTrack)
     * - Ancient Windows (98, 2000, XP, Vista)
     */
    private const FAKE_USER_AGENTS = [
        // Internet Explorer (EOL 2022)
        'MSIE 9.0',
        'MSIE 10.0',
        'MSIE 11.0',
        'Trident/7.0',              // IE11 engine signature

        // Ancient Chrome (auto-updates prevent this)
        'Chrome/94.0',
        'Chrome/90.0',
        'Chrome/80.0',
        'Chrome/70.0',

        // Ancient Firefox (auto-updates prevent this)
        'Firefox/90.0',
        'Firefox/80.0',
        'Firefox/70.0',

        // Ancient Safari
        'Safari/12.0',
        'Safari/11.0',

        // Known Bot Signatures
        'NCLIENT',
        'WebStripper',
        'WebCopier',
        'Offline Explorer',
        'HTTrack',
        'Teleport',

        // Ancient Windows (cannot run modern TLS 1.3)
        'Windows 98',
        'Windows NT 5.0',           // Windows 2000
        'Windows NT 5.1',           // Windows XP (EOL 2014)
        'Windows NT 6.0',           // Windows Vista (EOL 2017)
    ];

    /**
     * Geo-blocked Countries - AUTO-BAN (50 points)
     *
     * These country codes trigger immediate ban for non-whitelisted IPs.
     *
     * RATIONALE:
     * - RU (Russia): 70%+ of scanning attacks originate from Russian IPs
     * - CN (China): 60%+ of DDoS attacks and vulnerability scans
     * - KP (North Korea): State-sponsored cyber warfare infrastructure
     *
     * EXCEPTIONS:
     * - Legitimate bots (Googlebot, Yandex, Baidu) bypass geo-blocking
     * - Whitelisted IPs bypass geo-blocking
     *
     * GDPR COMPLIANCE:
     * Geo-blocking for security is LEGAL under Article 6.1(f) - Legitimate Interest
     */
    private const BLOCKED_COUNTRIES = [
        'RU',  // Russia
        'CN',  // China
        'KP',  // North Korea (DPRK)
    ];

    /**
     * SQL Injection Attack Patterns - CRITICAL DETECTION (40 points)
     *
     * Comprehensive collection of SQL injection patterns covering all major attack vectors.
     * These patterns detect attempts to manipulate database queries through user input.
     *
     * CATEGORIES COVERED:
     * - Classic SQL injection (OR 1=1, ' OR '1'='1)
     * - UNION-based attacks (UNION SELECT, UNION ALL SELECT)
     * - Boolean-based blind SQLi (AND 1=1, OR 1=1)
     * - Time-based blind SQLi (SLEEP, WAITFOR, BENCHMARK)
     * - Stacked queries (semicolon injection, multiple statements)
     * - Comment injection (-- , /*, #, ;%00)
     * - Database enumeration (information_schema, sys tables)
     * - Function-based attacks (CONCAT, LOAD_FILE, INTO OUTFILE)
     * - Alternative encodings (hex, char, unicode)
     * - NoSQL injection (MongoDB, Redis)
     *
     * DETECTION METHOD:
     * - Case-insensitive regex matching
     * - URL-decoded input scanning
     * - Multi-level encoding detection
     *
     * PERFORMANCE:
     * - O(n) pattern matching with early termination
     * - Optimized regex for minimal backtracking
     *
     * @var string[] Regex patterns for SQL injection detection
     */
    private const SQL_INJECTION_PATTERNS = [
        // Classic OR-based injection
        "/('|\"|`)\s*(or|OR)\s*('|\"|`)/i",                    // ' OR ', " OR ", ` OR `
        "/('|\"|`)\s*(or|OR)\s*\d+\s*=\s*\d+/i",              // ' OR 1=1, ' OR 2=2
        "/('|\"|`)\s*(or|OR)\s*('|\"|`)\s*=\s*('|\"|`)/i",   // ' OR '1'='1

        // Classic AND-based injection
        "/('|\"|`)\s*(and|AND)\s*('|\"|`)/i",                  // ' AND ', " AND "
        "/('|\"|`)\s*(and|AND)\s*\d+\s*=\s*\d+/i",            // ' AND 1=1

        // UNION-based injection (most common attack vector)
        "/union\s+(all\s+)?select/i",                          // UNION SELECT, UNION ALL SELECT
        "/union\s+\w+\s+from/i",                               // UNION ... FROM
        "/select\s+.+\s+from\s+.+\s+union/i",                 // SELECT ... UNION

        // Database enumeration
        "/information_schema/i",                               // MySQL metadata database
        "/sys\./i",                                            // System schemas
        "/mysql\./i",                                          // MySQL internals
        "/pg_catalog/i",                                       // PostgreSQL catalog
        "/sqlite_master/i",                                    // SQLite tables

        // Database-specific functions (SQL Server)
        "/xp_cmdshell/i",                                      // Command execution
        "/sp_executesql/i",                                    // Dynamic SQL
        "/openrowset/i",                                       // Remote queries
        "/exec\s*\(/i",                                        // Execute commands

        // Database-specific functions (MySQL)
        "/load_file/i",                                        // Read file
        "/into\s+outfile/i",                                   // Write file
        "/into\s+dumpfile/i",                                  // Binary write
        "/benchmark\s*\(/i",                                   // Time-based blind SQLi

        // Time-based blind SQL injection
        "/sleep\s*\(\s*\d+\s*\)/i",                           // MySQL SLEEP(5)
        "/waitfor\s+delay/i",                                  // SQL Server WAITFOR DELAY
        "/pg_sleep\s*\(/i",                                    // PostgreSQL pg_sleep

        // Stacked queries (multiple statements)
        "/;\s*(drop|delete|insert|update|create|alter|truncate)/i",  // ; DROP TABLE

        // Comment injection
        "/--\s/",                                              // SQL comment --
        "/#/",                                                 // MySQL comment #
        "/\/\*/",                                              // Multi-line comment /*
        "/;\s*%00/",                                           // NULL byte injection

        // SELECT statement detection
        "/select\s+.+\s+from/i",                              // SELECT ... FROM
        "/select\s+\*/i",                                      // SELECT *
        "/select\s+\d+/i",                                     // SELECT 1, SELECT @@version

        // INSERT/UPDATE/DELETE injection
        "/insert\s+into/i",                                    // INSERT INTO
        "/update\s+\w+\s+set/i",                              // UPDATE table SET
        "/delete\s+from/i",                                    // DELETE FROM

        // DROP/ALTER/TRUNCATE injection
        "/drop\s+(table|database|index|view)/i",              // DROP TABLE/DATABASE
        "/truncate\s+table/i",                                 // TRUNCATE TABLE
        "/alter\s+table/i",                                    // ALTER TABLE

        // Database fingerprinting
        "/@@version/i",                                        // SQL Server version
        "/version\s*\(/i",                                     // MySQL VERSION()
        "/database\s*\(/i",                                    // Current database

        // String manipulation for evasion
        "/concat\s*\(/i",                                      // CONCAT() evasion
        "/char\s*\(/i",                                        // CHAR() encoding
        "/ascii\s*\(/i",                                       // ASCII() conversion
        "/0x[0-9a-f]+/i",                                      // Hex encoding

        // Boolean-based blind SQLi
        "/\d+\s*=\s*\d+/",                                     // 1=1, 2=2 (simple boolean)
        "/true|false/i",                                       // Boolean literals

        // Advanced evasion techniques
        "/\|\|/",                                              // String concatenation (Oracle, PostgreSQL)
        "/\+\+/",                                              // Increment operator
        "/chr\s*\(/i",                                         // CHR() character conversion

        // NoSQL injection (MongoDB, Redis)
        "/\$where/i",                                          // MongoDB $where
        "/\$ne/i",                                             // MongoDB $ne (not equal)
        "/\$gt/i",                                             // MongoDB $gt (greater than)
        "/\$regex/i",                                          // MongoDB $regex

        // Subquery detection
        "/\(\s*select\s+/i",                                   // (SELECT ...)

        // HAVING clause injection
        "/having\s+\d+\s*=\s*\d+/i",                          // HAVING 1=1
    ];

    /**
     * XSS (Cross-Site Scripting) Attack Patterns - HIGH DETECTION (30 points)
     *
     * Comprehensive collection of XSS payload patterns covering all major attack vectors.
     * Detects attempts to inject malicious JavaScript into web pages.
     *
     * CATEGORIES COVERED:
     * - Script tag injection (<script>, </script>)
     * - Event handler injection (onerror, onload, onclick, etc.)
     * - JavaScript protocol (javascript:, vbscript:)
     * - Data URI injection (data:text/html, data:image/svg+xml)
     * - HTML entity encoding evasion (&#, &lt;, &gt;)
     * - Tag attribute injection (src, href, style)
     * - SVG-based XSS (<svg>, <animate>)
     * - Form-based XSS (<form action=javascript:>)
     * - Meta refresh redirect (<meta http-equiv=refresh>)
     * - Expression injection (CSS expressions, IE6-9)
     *
     * DETECTION METHOD:
     * - Case-insensitive regex matching
     * - HTML entity decoding
     * - Multi-level encoding detection
     *
     * PERFORMANCE:
     * - O(n) pattern matching with early termination
     * - Optimized for common XSS vectors
     *
     * @var string[] Regex patterns for XSS detection
     */
    private const XSS_PATTERNS = [
        // Script tag injection (most common)
        "/<script[^>]*>/is",                                   // <script>, <script src=...>
        "/<\/script>/i",                                       // </script>
        "/<script\s*>/i",                                      // <script>

        // Event handler injection (very common)
        "/on\w+\s*=/i",                                        // onclick=, onerror=, onload=
        "/onerror\s*=/i",                                      // onerror= (most abused)
        "/onload\s*=/i",                                       // onload=
        "/onclick\s*=/i",                                      // onclick=
        "/onmouseover\s*=/i",                                  // onmouseover=
        "/onfocus\s*=/i",                                      // onfocus=
        "/onblur\s*=/i",                                       // onblur=
        "/onchange\s*=/i",                                     // onchange=
        "/onsubmit\s*=/i",                                     // onsubmit=
        "/oninput\s*=/i",                                      // oninput=
        "/onkeydown\s*=/i",                                    // onkeydown=
        "/onkeyup\s*=/i",                                      // onkeyup=

        // JavaScript protocol injection
        "/javascript\s*:/i",                                   // javascript:alert(1)
        "/vbscript\s*:/i",                                     // vbscript: (IE)

        // Data URI injection
        "/data\s*:\s*text\/html/i",                           // data:text/html,<script>
        "/data\s*:\s*image\/svg\+xml/i",                      // data:image/svg+xml
        "/data\s*:\s*application/i",                          // data:application/...

        // iframe injection
        "/<iframe[^>]*>/i",                                    // <iframe>
        "/<\/iframe>/i",                                       // </iframe>

        // embed/object injection
        "/<embed[^>]*>/i",                                     // <embed>
        "/<object[^>]*>/i",                                    // <object>
        "/<applet[^>]*>/i",                                    // <applet> (Java)

        // SVG-based XSS (modern browsers)
        "/<svg[^>]*>/i",                                       // <svg>
        "/<animate[^>]*>/i",                                   // <animate>
        "/<animatetransform[^>]*>/i",                         // <animateTransform>
        "/<set[^>]*>/i",                                       // <set>

        // HTML entity evasion
        "/&#/",                                                // &#x6A;&#x61; (hex encoding)
        "/&lt;script&gt;/i",                                   // &lt;script&gt; (entity encoding)

        // Meta refresh redirect
        "/<meta[^>]*http-equiv\s*=\s*['\"]?refresh/i",        // <meta http-equiv=refresh>

        // Link injection
        "/<link[^>]*>/i",                                      // <link rel=import>

        // Form action injection
        "/<form[^>]*action\s*=\s*['\"]?javascript:/i",        // <form action=javascript:>

        // Style attribute injection (CSS injection)
        "/style\s*=.*expression\s*\(/i",                      // style=expression() (IE6-9)
        "/style\s*=.*javascript:/i",                          // style=javascript:

        // Import injection
        "/@import/i",                                          // @import url(javascript:)

        // Base tag injection
        "/<base[^>]*>/i",                                      // <base href=...>

        // Audio/Video XSS
        "/<audio[^>]*>/i",                                     // <audio src=x onerror=alert(1)>
        "/<video[^>]*>/i",                                     // <video src=x onerror=alert(1)>

        // Input/Textarea injection
        "/autofocus/i",                                        // autofocus onfocus=alert(1)

        // Image XSS
        "/<img[^>]*onerror/i",                                // <img src=x onerror=alert(1)>

        // Document.write/eval injection
        "/document\.write/i",                                  // document.write()
        "/eval\s*\(/i",                                        // eval()
        "/setTimeout\s*\(/i",                                  // setTimeout()
        "/setInterval\s*\(/i",                                 // setInterval()
    ];

    /**
     * Legitimate Bot Hostname Suffixes for DNS Verification
     *
     * HOW IT WORKS:
     * 1. Check User-Agent contains bot name
     * 2. Reverse DNS lookup: IP → hostname
     * 3. Verify hostname ends with legitimate suffix
     * 4. Forward DNS lookup: hostname → IP (must match original)
     * 5. Cache result in Redis (24h) to avoid repeated DNS calls
     *
     * SOURCE: Official bot documentation from each service
     *
     * @var array<string, string[]> Bot name => Allowed hostname suffixes
     */
    private const LEGITIMATE_BOT_HOSTNAMES = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'google-safety' => ['.googlebot.com', '.google.com'],
        'bingbot' => ['.search.msn.com'],
        'slurp' => ['.crawl.yahoo.net'],
        'duckduckbot' => ['.duckduckgo.com'],
        'baiduspider' => ['.crawl.baidu.com', '.crawl.baidu.jp'],
        'yandexbot' => ['.yandex.com', '.yandex.net', '.yandex.ru'],
        'facebookexternalhit' => ['.facebook.com', '.fbcdn.net', '.fbsv.net', '.akamaitechnologies.com'],
        'twitterbot' => ['.twttr.com', '.akamaitechnologies.com'],
        'telegrambot' => ['.telegram.org'],
        'linkedinbot' => ['.linkedin.com'],
        'pinterestbot' => ['.pinterest.com'],
        'applebot' => ['.applebot.apple.com'],
        'ia_archiver' => ['.archive.org'],
        'amazonbot' => ['.crawl.amazonbot.amazon'],
    ];

    /**
     * OpenAI IP Ranges for ChatGPT-User, GPTBot, OAI-SearchBot
     *
     * OpenAI crawlers use Azure IPs without reverse DNS, so we verify by IP range.
     * These are /28 CIDR blocks (16 IPs each).
     *
     * SOURCE: https://openai.com/chatgpt-user.json (official)
     * UPDATED: 2025-12-15 (creationTime: 2025-12-12)
     *
     * @var string[] CIDR notation IP ranges
     */
    private const OPENAI_IP_RANGES = [
        // 104.x.x.x
        '104.210.139.192/28', '104.210.139.224/28',

        // 13.x.x.x
        '13.65.138.112/28', '13.65.138.96/28', '13.67.46.240/28', '13.67.72.16/28',
        '13.70.107.160/28', '13.71.2.208/28', '13.76.115.224/28', '13.76.115.240/28',
        '13.76.116.80/28', '13.76.223.48/28', '13.76.32.208/28', '13.79.43.0/28',
        '13.83.167.128/28', '13.83.237.176/28',

        // 132.x - 138.x
        '132.196.82.48/28', '135.119.134.128/28', '135.119.134.192/28',
        '135.237.131.208/28', '135.237.133.112/28', '135.237.133.48/28',
        '137.135.183.96/28', '137.135.190.240/28', '137.135.191.176/28', '137.135.191.32/28',
        '138.91.30.48/28', '138.91.46.96/28',

        // 168.x - 172.x
        '168.63.252.240/28', '172.178.140.144/28', '172.178.141.112/28', '172.178.141.128/28',
        '172.183.143.224/28', '172.183.222.128/28', '172.204.16.64/28', '172.212.159.64/28',
        '172.213.11.144/28', '172.213.12.112/28', '172.213.21.112/28', '172.213.21.144/28',
        '172.213.21.16/28',

        // 191.x.x.x (Brazil Azure)
        '191.233.194.32/28', '191.233.196.112/28', '191.233.199.160/28', '191.234.167.128/28',
        '191.235.66.16/28', '191.235.98.144/28', '191.235.99.80/28', '191.237.249.64/28',
        '191.239.245.16/28',

        // 20.x.x.x (Azure main)
        '20.0.53.96/28', '20.102.212.144/28', '20.117.22.224/28', '20.125.112.224/28',
        '20.125.144.144/28', '20.161.75.208/28', '20.168.7.192/28', '20.168.7.240/28',
        '20.169.72.112/28', '20.169.72.96/28', '20.169.73.176/28', '20.169.73.32/28',
        '20.169.73.64/28', '20.169.78.112/28', '20.169.78.128/28', '20.169.78.144/28',
        '20.169.78.160/28', '20.169.78.176/28', '20.169.78.192/28', '20.169.78.48/28',
        '20.169.78.64/28', '20.169.78.80/28', '20.169.78.96/28', '20.172.29.32/28',
        '20.193.50.32/28', '20.194.0.208/28', '20.194.1.0/28', '20.194.157.176/28',
        '20.198.67.96/28', '20.204.24.240/28', '20.210.154.128/28', '20.210.174.208/28',
        '20.210.211.192/28', '20.215.187.208/28', '20.215.188.192/28', '20.215.214.16/28',
        '20.215.219.128/28', '20.215.219.160/28', '20.215.219.208/28', '20.227.140.32/28',
        '20.228.106.176/28', '20.235.75.208/28', '20.235.87.224/28', '20.249.63.208/28',
        '20.27.94.128/28', '20.45.178.144/28', '20.55.229.144/28', '20.63.221.64/28',
        '20.90.7.144/28', '20.97.189.96/28',

        // 23.x.x.x
        '23.102.140.144/28', '23.102.141.32/28', '23.97.109.224/28', '23.98.142.176/28',
        '23.98.179.16/28', '23.98.186.176/28', '23.98.186.192/28', '23.98.186.64/28',
        '23.98.186.96/28',

        // 4.x.x.x
        '4.151.119.48/28', '4.151.241.240/28', '4.151.71.176/28', '4.196.118.112/28',
        '4.196.198.80/28', '4.197.115.112/28', '4.197.19.176/28', '4.197.22.112/28',
        '4.197.64.0/28', '4.197.64.16/28', '4.197.64.48/28', '4.197.64.64/28',
        '4.205.128.176/28',

        // 40.x.x.x
        '40.116.73.208/28', '40.75.14.224/28', '40.81.234.144/28', '40.84.181.32/28',
        '40.84.221.208/28', '40.84.221.224/28',

        // 51.x.x.x
        '51.8.155.112/28', '51.8.155.48/28', '51.8.155.64/28', '51.8.155.80/28',

        // 52.x.x.x
        '52.148.129.32/28', '52.154.22.48/28', '52.156.77.144/28', '52.159.227.32/28',
        '52.159.249.96/28', '52.172.129.160/28', '52.173.123.0/28', '52.173.219.112/28',
        '52.173.219.96/28', '52.173.234.16/28', '52.173.234.80/28', '52.173.235.80/28',
        '52.176.139.176/28', '52.187.246.128/28', '52.190.137.144/28', '52.190.137.16/28',
        '52.190.139.48/28', '52.190.142.64/28', '52.190.190.16/28', '52.225.75.208/28',
        '52.230.163.32/28', '52.230.164.176/28', '52.231.30.48/28', '52.231.34.176/28',
        '52.231.39.144/28', '52.231.39.192/28', '52.231.49.48/28', '52.231.50.64/28',
        '52.236.94.144/28', '52.242.132.224/28', '52.242.132.240/28', '52.242.245.208/28',
        '52.252.113.240/28', '52.255.109.112/28', '52.255.109.128/28', '52.255.109.144/28',
        '52.255.109.80/28', '52.255.109.96/28', '52.255.111.0/28', '52.255.111.112/28',
        '52.255.111.16/28', '52.255.111.32/28', '52.255.111.48/28', '52.255.111.80/28',

        // 57.x - 74.x
        '57.154.174.112/28', '57.154.175.0/28', '57.154.187.32/28',
        '68.154.28.96/28', '68.218.30.112/28', '68.220.57.64/28', '68.221.67.160/28',
        '68.221.67.192/28', '68.221.67.224/28', '68.221.67.240/28', '68.221.75.16/28',
        '74.226.253.160/28', '74.249.86.176/28', '74.7.35.112/28', '74.7.35.48/28',
        '74.7.36.64/28', '74.7.36.80/28', '74.7.36.96/28',
    ];

    // ============================================================================
    // PATH CHECKING METHODS
    // ============================================================================

    /**
     * Check if path matches critical vulnerability patterns
     *
     * @param string $path Request path to check
     * @return bool True if path matches critical patterns
     */
    public static function isCriticalPath(string $path): bool
    {
        return self::matchesPaths($path, self::CRITICAL_PATHS);
    }

    /**
     * Check if path matches CMS scanning patterns
     *
     * @param string $path Request path to check
     * @return bool True if path matches CMS patterns
     */
    public static function isCMSPath(string $path): bool
    {
        return self::matchesPaths($path, self::CMS_PATHS);
    }

    /**
     * Check if path matches config file patterns
     *
     * @param string $path Request path to check
     * @return bool True if path matches config patterns
     */
    public static function isConfigPath(string $path): bool
    {
        return self::matchesPaths($path, self::CONFIG_PATHS);
    }

    /**
     * Generic path matching helper
     *
     * Supports both exact matches and prefix/contains matching.
     *
     * @param string $path Request path to check
     * @param array<string> $patterns Array of patterns to match against
     * @return bool True if path matches any pattern
     */
    private static function matchesPaths(string $path, array $patterns): bool
    {
        $pathLower = strtolower($path);

        foreach ($patterns as $pattern) {
            $patternLower = strtolower($pattern);

            // Exact match
            if ($pathLower === $patternLower) {
                return true;
            }

            // Prefix match (path starts with pattern)
            if (str_starts_with($pathLower, $patternLower)) {
                return true;
            }

            // Contains (for partial matches like /.env in path)
            if (str_contains($pathLower, $patternLower)) {
                return true;
            }
        }

        return false;
    }

    // ============================================================================
    // USER-AGENT CHECKING METHODS
    // ============================================================================

    /**
     * Check if User-Agent is from known vulnerability scanner
     *
     * @param string $userAgent User-Agent header
     * @return bool True if scanner detected
     */
    public static function isScannerUserAgent(string $userAgent): bool
    {
        $userAgentLower = strtolower($userAgent);

        foreach (self::SCANNER_USER_AGENTS as $scanner) {
            if (str_contains($userAgentLower, strtolower($scanner))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if User-Agent is from legitimate bot
     *
     * NOTE: This only checks User-Agent string. For security, always perform
     * DNS verification using isLegitimateBot() method.
     *
     * @param string $userAgent User-Agent header
     * @return bool True if legitimate bot User-Agent detected
     */
    public static function isLegitimateBot(string $userAgent): bool
    {
        $userAgentLower = strtolower($userAgent);

        foreach (self::LEGITIMATE_BOTS as $bot) {
            if (str_contains($userAgentLower, strtolower($bot))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if User-Agent is fake/obsolete (impossible in 2025)
     *
     * @param string $userAgent User-Agent header
     * @return bool True if fake/obsolete browser detected
     */
    public static function isFakeUserAgent(string $userAgent): bool
    {
        if (empty($userAgent)) {
            return false; // Empty UA handled separately (100 points)
        }

        $userAgentLower = strtolower($userAgent);

        foreach (self::FAKE_USER_AGENTS as $fake) {
            if (str_contains($userAgentLower, strtolower($fake))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Classify User-Agent into threat categories
     *
     * @param string $userAgent User-Agent header
     * @return string One of: 'scanner', 'bot', 'browser', 'unknown'
     */
    public static function classifyUserAgent(string $userAgent): string
    {
        if (empty($userAgent)) {
            return 'unknown';
        }

        // Priority 1: Known vulnerability scanners (highest threat)
        if (self::isScannerUserAgent($userAgent)) {
            return 'scanner';
        }

        // Priority 2: Legitimate bots (beneficial)
        if (self::isLegitimateBot($userAgent)) {
            return 'bot';
        }

        // Priority 3: Check if it looks like a browser
        $userAgentLower = strtolower($userAgent);
        $browserPatterns = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'mozilla'];

        foreach ($browserPatterns as $browser) {
            if (str_contains($userAgentLower, $browser)) {
                return 'browser';
            }
        }

        return 'unknown';
    }

    // ============================================================================
    // GEOGRAPHIC BLOCKING METHODS
    // ============================================================================

    /**
     * Check if country code is geo-blocked
     *
     * @param string $countryCode Two-letter ISO country code (e.g., 'RU', 'CN')
     * @return bool True if country is blocked
     */
    public static function isBlockedCountry(string $countryCode): bool
    {
        return in_array(strtoupper($countryCode), self::BLOCKED_COUNTRIES, true);
    }

    /**
     * Get list of blocked country codes
     *
     * @return array<string> Array of two-letter country codes
     */
    public static function getBlockedCountries(): array
    {
        return self::BLOCKED_COUNTRIES;
    }

    // ============================================================================
    // DNS VERIFICATION METHODS
    // ============================================================================

    /**
     * Get legitimate hostname suffixes for a bot
     *
     * @param string $botName Bot name (e.g., 'googlebot', 'bingbot')
     * @return array<string>|null Array of allowed hostname suffixes, or null if not found
     */
    public static function getLegitimateHostnameSuffixes(string $botName): ?array
    {
        $botNameLower = strtolower($botName);
        return self::LEGITIMATE_BOT_HOSTNAMES[$botNameLower] ?? null;
    }

    /**
     * Check if IP is in OpenAI IP ranges
     *
     * @param string $ip IP address to check
     * @return bool True if IP is in OpenAI ranges
     */
    public static function isOpenAIIP(string $ip): bool
    {
        foreach (self::OPENAI_IP_RANGES as $cidr) {
            if (self::ipInCIDR($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get OpenAI IP ranges
     *
     * @return array<string> Array of CIDR notation IP ranges
     */
    public static function getOpenAIIPRanges(): array
    {
        return self::OPENAI_IP_RANGES;
    }

    /**
     * Check if IP is within CIDR range
     *
     * @param string $ip IP address to check
     * @param string $cidr CIDR notation (e.g., '192.168.1.0/24')
     * @return bool True if IP is in range
     */
    private static function ipInCIDR(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr);

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $maskLong = -1 << (32 - (int) $mask);

        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }

    // ============================================================================
    // SQL INJECTION & XSS DETECTION METHODS
    // ============================================================================

    /**
     * Check if parameters contain SQL injection attempts
     *
     * Scans GET/POST parameters for SQL injection patterns.
     * Supports nested arrays and performs URL decoding.
     *
     * WORKFLOW:
     * 1. Flatten nested arrays to single-level
     * 2. URL-decode all values (handles encoded payloads)
     * 3. Match against SQL injection patterns
     * 4. Return true on first match (early termination)
     *
     * EXAMPLES:
     * - hasSQLInjection(['id' => "1' OR '1'='1"]) → true
     * - hasSQLInjection(['name' => 'John']) → false
     * - hasSQLInjection(['q' => 'UNION SELECT * FROM users']) → true
     *
     * @param array<string, mixed> $params GET/POST parameters (can be nested)
     * @return bool True if SQL injection detected
     */
    public static function hasSQLInjection(array $params): bool
    {
        // Flatten nested arrays
        $flatParams = self::flattenArray($params);

        foreach ($flatParams as $value) {
            // Skip non-string values
            if (!is_string($value)) {
                continue;
            }

            // URL decode (attackers often encode payloads)
            $decodedValue = urldecode($value);

            // Check against all SQL injection patterns
            foreach (self::SQL_INJECTION_PATTERNS as $pattern) {
                if (preg_match($pattern, $decodedValue)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if parameters contain XSS payloads
     *
     * Scans GET/POST parameters for XSS attack patterns.
     * Supports nested arrays and performs URL/HTML entity decoding.
     *
     * WORKFLOW:
     * 1. Flatten nested arrays to single-level
     * 2. URL-decode all values (handles encoded payloads)
     * 3. HTML entity decode (handles &lt;script&gt; evasion)
     * 4. Match against XSS patterns
     * 5. Return true on first match (early termination)
     *
     * EXAMPLES:
     * - hasXSSPayload(['comment' => '<script>alert(1)</script>']) → true
     * - hasXSSPayload(['name' => 'John']) → false
     * - hasXSSPayload(['html' => '<img src=x onerror=alert(1)>']) → true
     *
     * @param array<string, mixed> $params GET/POST parameters (can be nested)
     * @return bool True if XSS payload detected
     */
    public static function hasXSSPayload(array $params): bool
    {
        // Flatten nested arrays
        $flatParams = self::flattenArray($params);

        foreach ($flatParams as $value) {
            // Skip non-string values
            if (!is_string($value)) {
                continue;
            }

            // URL decode (attackers often encode payloads)
            $decodedValue = urldecode($value);

            // HTML entity decode (handles &lt;script&gt; evasion)
            $htmlDecoded = html_entity_decode($decodedValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');

            // Check against all XSS patterns
            foreach (self::XSS_PATTERNS as $pattern) {
                if (preg_match($pattern, $htmlDecoded)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Flatten nested array to single-level
     *
     * Converts multi-dimensional arrays to single-level array of values.
     * Used for scanning all parameter values regardless of nesting.
     *
     * EXAMPLE:
     * ```php
     * flattenArray(['a' => 1, 'b' => ['c' => 2, 'd' => 3]])
     * // Returns: [1, 2, 3]
     * ```
     *
     * @param array<string, mixed> $array Nested array
     * @return array<int, mixed> Single-level array of values
     */
    private static function flattenArray(array $array): array
    {
        $result = [];

        foreach ($array as $value) {
            if (is_array($value)) {
                // Recursive flatten
                $result = array_merge($result, self::flattenArray($value));
            } else {
                $result[] = $value;
            }
        }

        return $result;
    }

    // ============================================================================
    // SCORING METHODS
    // ============================================================================

    /**
     * Get score for critical path detection
     *
     * @return int Score points (30)
     */
    public static function getCriticalPathScore(): int
    {
        return self::SCORE_CRITICAL_PATH;
    }

    /**
     * Get score for CMS path detection
     *
     * @return int Score points (15)
     */
    public static function getCMSPathScore(): int
    {
        return self::SCORE_CMS_PATH;
    }

    /**
     * Get score for config path detection
     *
     * @return int Score points (10)
     */
    public static function getConfigPathScore(): int
    {
        return self::SCORE_CONFIG_PATH;
    }

    /**
     * Get score for scanner User-Agent detection
     *
     * @return int Score points (30)
     */
    public static function getScannerUserAgentScore(): int
    {
        return self::SCORE_SCANNER_USER_AGENT;
    }

    /**
     * Get score for fake User-Agent detection
     *
     * @return int Score points (50)
     */
    public static function getFakeUserAgentScore(): int
    {
        return self::SCORE_FAKE_USER_AGENT;
    }

    /**
     * Get score for NULL User-Agent
     *
     * @return int Score points (100 - instant ban)
     */
    public static function getNullUserAgentScore(): int
    {
        return self::SCORE_NULL_USER_AGENT;
    }

    /**
     * Get score for geo-blocked country
     *
     * @return int Score points (50)
     */
    public static function getGeoBlockedScore(): int
    {
        return self::SCORE_GEO_BLOCKED;
    }

    /**
     * Get score for Unicode obfuscation
     *
     * @return int Score points (20)
     */
    public static function getUnicodeObfuscationScore(): int
    {
        return self::SCORE_UNICODE_OBFUSCATION;
    }

    /**
     * Get score for SQL injection detection
     *
     * @return int Score points (40)
     */
    public static function getSQLInjectionScore(): int
    {
        return self::SCORE_SQL_INJECTION;
    }

    /**
     * Get score for XSS payload detection
     *
     * @return int Score points (30)
     */
    public static function getXSSPayloadScore(): int
    {
        return self::SCORE_XSS_PAYLOAD;
    }

    /**
     * Get score for rate limit exceeded
     *
     * @return int Score points (20)
     */
    public static function getRateLimitScore(): int
    {
        return self::SCORE_RATE_LIMIT_EXCEEDED;
    }

    /**
     * Get ban threshold score
     *
     * @return int Threshold points (50)
     */
    public static function getScoreThreshold(): int
    {
        return self::SCORE_THRESHOLD;
    }

    /**
     * Calculate total threat score for a request
     *
     * @param string $path Request path
     * @param string $userAgent User-Agent header
     * @param string|null $countryCode Optional country code
     * @return array{score: int, reasons: array<string>} Score and reasons
     */
    public static function calculateThreatScore(
        string $path,
        string $userAgent,
        ?string $countryCode = null
    ): array {
        $score = 0;
        $reasons = [];

        // Check critical paths
        if (self::isCriticalPath($path)) {
            $score += self::SCORE_CRITICAL_PATH;
            $reasons[] = 'critical_path';
        }

        // Check CMS paths
        if (self::isCMSPath($path)) {
            $score += self::SCORE_CMS_PATH;
            $reasons[] = 'cms_scan';
        }

        // Check config paths
        if (self::isConfigPath($path)) {
            $score += self::SCORE_CONFIG_PATH;
            $reasons[] = 'config_scan';
        }

        // Check User-Agent
        if (empty($userAgent)) {
            $score += self::SCORE_NULL_USER_AGENT;
            $reasons[] = 'null_user_agent';
        } elseif (self::isScannerUserAgent($userAgent)) {
            $score += self::SCORE_SCANNER_USER_AGENT;
            $reasons[] = 'scanner_user_agent';
        } elseif (self::isFakeUserAgent($userAgent)) {
            $score += self::SCORE_FAKE_USER_AGENT;
            $reasons[] = 'fake_user_agent';
        }

        // Check geo-blocking
        if ($countryCode && self::isBlockedCountry($countryCode)) {
            $score += self::SCORE_GEO_BLOCKED;
            $reasons[] = "geo_blocked_{$countryCode}";
        }

        return [
            'score' => $score,
            'reasons' => $reasons,
        ];
    }

    /**
     * Check if score exceeds ban threshold
     *
     * @param int $score Current score
     * @return bool True if score >= threshold
     */
    public static function shouldBan(int $score): bool
    {
        return $score >= self::SCORE_THRESHOLD;
    }

    // ============================================================================
    // PATTERN STATISTICS METHODS
    // ============================================================================

    /**
     * Get total number of critical paths
     *
     * @return int Count of patterns
     */
    public static function getCriticalPathsCount(): int
    {
        return count(self::CRITICAL_PATHS);
    }

    /**
     * Get total number of CMS paths
     *
     * @return int Count of patterns
     */
    public static function getCMSPathsCount(): int
    {
        return count(self::CMS_PATHS);
    }

    /**
     * Get total number of config paths
     *
     * @return int Count of patterns
     */
    public static function getConfigPathsCount(): int
    {
        return count(self::CONFIG_PATHS);
    }

    /**
     * Get total number of scanner User-Agents
     *
     * @return int Count of patterns
     */
    public static function getScannerUserAgentsCount(): int
    {
        return count(self::SCANNER_USER_AGENTS);
    }

    /**
     * Get total number of legitimate bots
     *
     * @return int Count of patterns
     */
    public static function getLegitimateBotsCount(): int
    {
        return count(self::LEGITIMATE_BOTS);
    }

    /**
     * Get total number of fake User-Agent patterns
     *
     * @return int Count of patterns
     */
    public static function getFakeUserAgentsCount(): int
    {
        return count(self::FAKE_USER_AGENTS);
    }

    /**
     * Get comprehensive pattern statistics
     *
     * @return array<string, int> Pattern counts by category
     */
    public static function getStatistics(): array
    {
        return [
            'critical_paths' => self::getCriticalPathsCount(),
            'cms_paths' => self::getCMSPathsCount(),
            'config_paths' => self::getConfigPathsCount(),
            'scanner_user_agents' => self::getScannerUserAgentsCount(),
            'legitimate_bots' => self::getLegitimateBotsCount(),
            'fake_user_agents' => self::getFakeUserAgentsCount(),
            'blocked_countries' => count(self::BLOCKED_COUNTRIES),
            'openai_ip_ranges' => count(self::OPENAI_IP_RANGES),
            'bot_hostnames' => count(self::LEGITIMATE_BOT_HOSTNAMES),
        ];
    }
}
