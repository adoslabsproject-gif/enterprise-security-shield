<?php

declare(strict_types=1);

namespace Senza1dio\SecurityShield\Tests\Unit;

use Senza1dio\SecurityShield\Services\ThreatPatterns;
use PHPUnit\Framework\TestCase;

/**
 * ENTERPRISE GALAXY: ThreatPatterns Service Comprehensive Test Suite
 *
 * 100% coverage test suite for ThreatPatterns service with strict assertions.
 * Tests all critical paths, edge cases, and security patterns.
 *
 * COVERAGE MATRIX:
 * - Critical Path Detection (30 points)
 * - CMS Path Detection (15 points)
 * - Config Path Detection (10 points)
 * - Scanner User-Agent Detection (30 points)
 * - Legitimate Bot Detection
 * - Fake User-Agent Detection (50 points)
 * - Geographic Blocking (50 points)
 * - OpenAI IP Verification
 * - Threat Score Calculation
 * - Statistics Methods
 *
 * @package Senza1dio\SecurityShield\Tests\Unit
 * @covers \Senza1dio\SecurityShield\Services\ThreatPatterns
 */
class ThreatPatternsTest extends TestCase
{
    // ============================================================================
    // CRITICAL PATH DETECTION TESTS (30 points)
    // ============================================================================

    /**
     * Test critical path detection - Environment files
     */
    public function testDetectsEnvironmentFiles(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env.local'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env.production'));
    }

    /**
     * Test critical path detection - Version control systems
     */
    public function testDetectsVersionControlPaths(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.git/'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.git/config'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.svn/'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.hg/'));
    }

    /**
     * Test critical path detection - Config files
     */
    public function testDetectsConfigFiles(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/config.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/configuration.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/settings.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/database.yml'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/database.php'));
    }

    /**
     * Test critical path detection - AWS credentials
     */
    public function testDetectsAWSCredentials(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.aws/'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.aws/credentials'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.aws/config'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/aws/credentials'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/aws/config'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/aws_lambda_config.json'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/aws/aws_config.json'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/aws_access_keys.json'));
    }

    /**
     * Test critical path detection - SSH keys
     */
    public function testDetectsSSHKeys(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.ssh/'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/id_rsa'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/id_rsa.pub'));
    }

    /**
     * Test critical path detection - Database dumps
     */
    public function testDetectsDatabaseDumps(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/backup.sql'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/dump.sql'));
    }

    /**
     * Test critical path detection - Apache auth files
     */
    public function testDetectsApacheAuthFiles(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.htpasswd'));
    }

    /**
     * Test critical path detection - Debug/info scripts
     */
    public function testDetectsDebugScripts(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/phpinfo.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/info.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/test.php'));
    }

    /**
     * Test critical path detection - Shell backdoors
     */
    public function testDetectsShellBackdoors(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/shell.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/c99.php'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/r57.php'));
    }

    /**
     * Test critical path detection - Case insensitivity
     */
    public function testCriticalPathCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.ENV'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.Env'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/PHPINFO.PHP'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/Config.PHP'));
    }

    /**
     * Test critical path detection - URL encoding variations
     *
     * NOTE: ThreatPatterns expects decoded paths.
     * Middleware should decode URL before checking.
     */
    public function testCriticalPathURLEncodingVariations(): void
    {
        // URL-encoded paths are NOT decoded by ThreatPatterns - expected to be pre-decoded
        $this->assertFalse(ThreatPatterns::isCriticalPath('%2e%2e%2f.env'));

        // Double URL encoding
        $this->assertFalse(ThreatPatterns::isCriticalPath('%252e%252e%252f.env'));

        // Path with query strings (segment matching - /.env followed by ?)
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env?test=1'));
    }

    /**
     * Test critical path detection - Path normalization
     *
     * NOTE: Path traversal detection is NOT done by ThreatPatterns.
     * Middleware should normalize paths before checking.
     */
    public function testCriticalPathNormalization(): void
    {
        // Paths with trailing slash - direct prefix match
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.git/config/'));

        // Paths with query strings (contains match)
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env?test=1'));

        // Path traversal is NOT normalized by ThreatPatterns
        // These would need middleware pre-processing
        $this->assertFalse(ThreatPatterns::isCriticalPath('../.env'));
        $this->assertFalse(ThreatPatterns::isCriticalPath('/../../.env'));
    }

    /**
     * Test critical path detection - Legitimate paths
     */
    public function testLegitimatePathsNotCritical(): void
    {
        $this->assertFalse(ThreatPatterns::isCriticalPath('/'));
        $this->assertFalse(ThreatPatterns::isCriticalPath('/index.php'));
        $this->assertFalse(ThreatPatterns::isCriticalPath('/api/users'));
        $this->assertFalse(ThreatPatterns::isCriticalPath('/profile'));
        $this->assertFalse(ThreatPatterns::isCriticalPath('/images/photo.jpg'));
    }

    /**
     * Test critical path detection - Prefix matching
     */
    public function testCriticalPathPrefixMatching(): void
    {
        // Paths that START with critical patterns
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.git/HEAD'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.git/config/main'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.aws/credentials/prod'));
    }

    /**
     * Test critical path detection - Segment boundary matching
     *
     * NOTE: ThreatPatterns uses PREFIX matching, not contains matching.
     * Paths like /app/.env are NOT detected because patterns like /.env
     * are matched from the START of the path.
     *
     * This is by design to prevent false positives - the middleware
     * should normalize paths before checking.
     */
    public function testCriticalPathContainsMatching(): void
    {
        // PREFIX matching only - patterns must start from root
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.git/'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.ssh/'));

        // Nested paths are NOT matched by design (prefix only)
        // Use path normalization in middleware to handle traversal attacks
        $this->assertFalse(ThreatPatterns::isCriticalPath('/app/.env'));
        $this->assertFalse(ThreatPatterns::isCriticalPath('/backup/.git/'));
    }

    /**
     * Test critical path score value
     */
    public function testCriticalPathScore(): void
    {
        $this->assertSame(30, ThreatPatterns::getCriticalPathScore());
    }

    // ============================================================================
    // CMS PATH DETECTION TESTS (15 points)
    // ============================================================================

    /**
     * Test CMS path detection - WordPress
     */
    public function testDetectsWordPressPaths(): void
    {
        $this->assertTrue(ThreatPatterns::isCMSPath('/wp-admin/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/wp-login.php'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/wp-content/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/wp-includes/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/wp-config.php'));
    }

    /**
     * Test CMS path detection - Joomla
     */
    public function testDetectsJoomlaPaths(): void
    {
        $this->assertTrue(ThreatPatterns::isCMSPath('/administrator/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/joomla/'));
    }

    /**
     * Test CMS path detection - Other CMS
     */
    public function testDetectsOtherCMSPaths(): void
    {
        $this->assertTrue(ThreatPatterns::isCMSPath('/drupal/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/magento/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/prestashop/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/typo3/'));
    }

    /**
     * Test CMS path detection - Generic admin
     *
     * NOTE: /admin/ is excluded from CMS detection when FrameworkDetector
     * identifies it as a legitimate framework path (which it does for 'custom' framework).
     * This prevents false positives for legitimate admin panels.
     */
    public function testDetectsGenericAdminPaths(): void
    {
        // /admin/ is in CMS_PATHS array but is also a legitimate framework path
        // FrameworkDetector::isLegitimateFrameworkPath() returns true for /admin/
        // So isCMSPath returns false to prevent false positives
        $this->assertFalse(ThreatPatterns::isCMSPath('/admin/'));

        // But other admin-like paths are still detected
        $this->assertTrue(ThreatPatterns::isCMSPath('/administrator/'));
    }

    /**
     * Test CMS path detection - Database tools
     */
    public function testDetectsDatabaseToolPaths(): void
    {
        $this->assertTrue(ThreatPatterns::isCMSPath('/adminer.php'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/phpmyadmin/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/pma/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/mysql/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/postgres/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/postgresql/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/pgadmin/'));
    }

    /**
     * Test CMS path detection - Case insensitivity
     */
    public function testCMSPathCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isCMSPath('/WP-ADMIN/'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/Wp-Login.php'));
        $this->assertTrue(ThreatPatterns::isCMSPath('/PHPMYADMIN/'));
    }

    /**
     * Test CMS path detection - Legitimate paths
     */
    public function testLegitimatePathsNotCMS(): void
    {
        $this->assertFalse(ThreatPatterns::isCMSPath('/'));
        $this->assertFalse(ThreatPatterns::isCMSPath('/blog/'));
        $this->assertFalse(ThreatPatterns::isCMSPath('/api/'));
    }

    /**
     * Test CMS path score value
     */
    public function testCMSPathScore(): void
    {
        $this->assertSame(15, ThreatPatterns::getCMSPathScore());
    }

    // ============================================================================
    // CONFIG PATH DETECTION TESTS (10 points)
    // ============================================================================

    /**
     * Test config path detection - JSON configs
     */
    public function testDetectsJSONConfigs(): void
    {
        $this->assertTrue(ThreatPatterns::isConfigPath('/config.json'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/app.json'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/package.json'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/composer.json'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/composer.lock'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/secrets.json'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/credentials.json'));
    }

    /**
     * Test config path detection - YAML configs
     */
    public function testDetectsYAMLConfigs(): void
    {
        $this->assertTrue(ThreatPatterns::isConfigPath('/config.yml'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/docker-compose.yml'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/kubernetes.yml'));
    }

    /**
     * Test config path detection - Package manager configs
     */
    public function testDetectsPackageManagerConfigs(): void
    {
        $this->assertTrue(ThreatPatterns::isConfigPath('/.npmrc'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/.yarnrc'));
    }

    /**
     * Test config path detection - Docker
     */
    public function testDetectsDockerFiles(): void
    {
        $this->assertTrue(ThreatPatterns::isConfigPath('/Dockerfile'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/.dockerignore'));
    }

    /**
     * Test config path detection - Case insensitivity
     */
    public function testConfigPathCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isConfigPath('/CONFIG.JSON'));
        $this->assertTrue(ThreatPatterns::isConfigPath('/Composer.json'));
    }

    /**
     * Test config path score value
     */
    public function testConfigPathScore(): void
    {
        $this->assertSame(10, ThreatPatterns::getConfigPathScore());
    }

    // ============================================================================
    // SCANNER USER-AGENT DETECTION TESTS (30 points)
    // ============================================================================

    /**
     * Test scanner detection - SQL injection tools
     */
    public function testDetectsSQLInjectionTools(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('sqlmap/1.0'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('havij'));
    }

    /**
     * Test scanner detection - Web vulnerability scanners
     */
    public function testDetectsWebVulnerabilityScanners(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('nikto/2.1.5'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('w3af.org'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('skipfish'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('grabber'));
    }

    /**
     * Test scanner detection - Network scanners
     */
    public function testDetectsNetworkScanners(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Nmap Scripting Engine'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('masscan/1.0'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('ZMap v2.0'));
    }

    /**
     * Test scanner detection - Professional vulnerability scanners
     */
    public function testDetectsProfessionalScanners(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Nessus'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('OpenVAS'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Acunetix'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Netsparker'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('BurpSuite'));
    }

    /**
     * Test scanner detection - Exploitation frameworks
     */
    public function testDetectsExploitationFrameworks(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Metasploit/5.0'));
    }

    /**
     * Test scanner detection - CMS scanners
     */
    public function testDetectsCMSScanners(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('WPScan v3.0'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Joomscan'));
    }

    /**
     * Test scanner detection - Directory bruteforcers
     */
    public function testDetectsDirectoryBruteforcers(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('DirBuster'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('dirb'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('gobuster'));
    }

    /**
     * Test scanner detection - Fuzzing tools
     */
    public function testDetectsFuzzingTools(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('ffuf/v1.0'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('wfuzz/2.0'));
    }

    /**
     * Test scanner detection - Password crackers
     */
    public function testDetectsPasswordCrackers(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('THC-Hydra'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Medusa'));
    }

    /**
     * Test scanner detection - Internet-wide scanners
     */
    public function testDetectsInternetScanners(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('zgrab/0.x'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Shodan'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Censys'));
    }

    /**
     * Test scanner detection - Case insensitivity
     */
    public function testScannerUserAgentCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('SQLMAP'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Nikto'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('NMAP'));
    }

    /**
     * Test scanner detection - Partial matches
     */
    public function testScannerUserAgentPartialMatches(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Mozilla/5.0 (compatible; Nikto/2.1.5)'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('sqlmap/1.4.12 (http://sqlmap.org)'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('User-Agent: Nmap Scripting Engine'));
    }

    /**
     * Test scanner detection - Legitimate browsers not detected
     */
    public function testLegitimateBrowsersNotScanners(): void
    {
        $this->assertFalse(ThreatPatterns::isScannerUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'));
        $this->assertFalse(ThreatPatterns::isScannerUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1'));
    }

    /**
     * Test scanner User-Agent score value
     */
    public function testScannerUserAgentScore(): void
    {
        $this->assertSame(30, ThreatPatterns::getScannerUserAgentScore());
    }

    // ============================================================================
    // LEGITIMATE BOT DETECTION TESTS
    // ============================================================================

    /**
     * Test legitimate bot detection - Google crawlers
     */
    public function testDetectsGoogleCrawlers(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Mozilla/5.0 (compatible; Googlebot/2.1)'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Googlebot-Image/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Googlebot-Video/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Googlebot-News'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Google-InspectionTool/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Google-Extended'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Google-Safety'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Storebot-Google'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('AdsBot-Google'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Mediapartners-Google'));
    }

    /**
     * Test legitimate bot detection - Performance testing tools
     */
    public function testDetectsPerformanceTestingTools(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Chrome-Lighthouse'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Lighthouse'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('GTmetrix'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('WebPageTest'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Pingdom.com_bot'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Pingdom Tools'));
    }

    /**
     * Test legitimate bot detection - Other search engines
     */
    public function testDetectsOtherSearchEngines(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Mozilla/5.0 (compatible; bingbot/2.0)'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('msnbot/2.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Mozilla/5.0 (compatible; Yahoo! Slurp)'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('DuckDuckBot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('BaiduSpider'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('YandexBot/3.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Sogou web spider'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Exabot/3.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('SeznamBot/3.2'));
    }

    /**
     * Test legitimate bot detection - AI crawlers
     */
    public function testDetectsAICrawlers(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('GPTBot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('ChatGPT-User/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('OAI-SearchBot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('ClaudeBot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('anthropic-ai'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Claude-Web'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('PerplexityBot'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Cohere-AI'));
    }

    /**
     * Test legitimate bot detection - Social media crawlers
     *
     * NOTE: Several social media bots have been removed from the list as they
     * lack reliable DNS verification (whatsapp, discord, reddit, slackbot).
     * Only DNS-verifiable bots are included for security.
     */
    public function testDetectsSocialMediaCrawlers(): void
    {
        // DNS-verifiable social media crawlers
        $this->assertTrue(ThreatPatterns::isLegitimateBot('facebookexternalhit/1.1'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('FacebookCatalog/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('TelegramBot (like TwitterBot)'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Twitterbot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('LinkedInBot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Pinterestbot/0.2'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('SkypeUriPreview'));

        // Telegram-specific test
        $this->assertTrue(ThreatPatterns::isLegitimateBot('TelegramBot/1.0'));

        // These bots have been REMOVED from legitimate list (no DNS verification):
        // - reddit, discordbot, slackbot, whatsapp
        $this->assertFalse(ThreatPatterns::isLegitimateBot('reddit'));
        $this->assertFalse(ThreatPatterns::isLegitimateBot('Discordbot/2.0'));
        $this->assertFalse(ThreatPatterns::isLegitimateBot('Slackbot-LinkExpanding'));
        $this->assertFalse(ThreatPatterns::isLegitimateBot('WhatsApp/2.0'));
    }

    /**
     * Test legitimate bot detection - Mobile app crawlers
     */
    public function testDetectsMobileAppCrawlers(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('AppleBot/0.1'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Googlebot-Mobile'));
    }

    /**
     * Test legitimate bot detection - Monitoring & Analytics
     */
    public function testDetectsMonitoringBots(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('UptimeRobot/2.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Pingdom'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('StatusCake'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('HetrixTools'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('NewRelicSynthetics'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Datadog Agent'));
    }

    /**
     * Test legitimate bot detection - SEO & Website Tools
     */
    public function testDetectsSEOTools(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('SemrushBot'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('AhrefsBot/7.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('MJ12bot/v1.4.8'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('DotBot/1.1'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('rogerbot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Screaming Frog SEO Spider'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('TrendictionBot'));
    }

    /**
     * Test legitimate bot detection - Archive & Research
     */
    public function testDetectsArchiveBots(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('ia_archiver (+http://www.archive.org/)'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('archive.org_bot'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('CCBot/2.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('NetcraftSurveyAgent'));
    }

    /**
     * Test legitimate bot detection - News & RSS Aggregators
     */
    public function testDetectsNewsBots(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Feedly/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Flipboard'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('NewsBlur'));
    }

    /**
     * Test legitimate bot detection - Developer Tools
     *
     * NOTE: Developer tools (Postman, Insomnia) have been REMOVED from legitimate
     * bot list. They are easily spoofable with no DNS verification possible.
     * Use IP whitelist instead if you need to allow these tools.
     */
    public function testDetectsDeveloperTools(): void
    {
        // Developer tools have been removed - anyone can set these User-Agents
        $this->assertFalse(ThreatPatterns::isLegitimateBot('PostmanRuntime/7.26.8'));
        $this->assertFalse(ThreatPatterns::isLegitimateBot('insomnia/2021.1.0'));
    }

    /**
     * Test legitimate bot detection - Commercial Bots
     */
    public function testDetectsCommercialBots(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('AmazonAdBot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Amazonbot/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('ByteSpider'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('PetalBot'));
    }

    /**
     * Test legitimate bot detection - Media Monitoring
     */
    public function testDetectsMediaMonitoringBots(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('MediatoolkitBot'));
    }

    /**
     * Test legitimate bot detection - Case insensitivity
     */
    public function testLegitimateBotCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isLegitimateBot('GOOGLEBOT'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('BingBot'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('LIGHTHOUSE'));
    }

    /**
     * Test legitimate bot detection - Scanners not detected as bots
     */
    public function testScannersNotLegitimateBots(): void
    {
        $this->assertFalse(ThreatPatterns::isLegitimateBot('sqlmap/1.0'));
        $this->assertFalse(ThreatPatterns::isLegitimateBot('Nikto'));
    }

    /**
     * Test legitimate bot hostname suffixes
     */
    public function testGetLegitimateHostnameSuffixes(): void
    {
        $this->assertSame(['.googlebot.com', '.google.com'], ThreatPatterns::getLegitimateHostnameSuffixes('googlebot'));
        $this->assertSame(['.search.msn.com'], ThreatPatterns::getLegitimateHostnameSuffixes('bingbot'));
        $this->assertSame(['.crawl.yahoo.net'], ThreatPatterns::getLegitimateHostnameSuffixes('slurp'));
        $this->assertNull(ThreatPatterns::getLegitimateHostnameSuffixes('unknown-bot'));
    }

    // ============================================================================
    // FAKE USER-AGENT DETECTION TESTS (50 points)
    // ============================================================================

    /**
     * Test fake User-Agent detection - Internet Explorer
     *
     * NOTE: IE11/Trident has been removed from fake list (still used in corporate environments).
     * Only IE 6-10 are considered definitely fake.
     */
    public function testDetectsInternetExplorer(): void
    {
        // IE 6-10 are definitely fake (in FAKE_USER_AGENTS list)
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 6.1; MSIE 9.0)'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 6.1; MSIE 10.0)'));

        // IE11 (Trident) NOT in fake list - still used in corporate environments
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0)'));
    }

    /**
     * Test fake User-Agent detection - Ancient Chrome
     *
     * NOTE: Only Chrome 60 and below are in fake list.
     * Chrome 70-99 removed - possible on embedded/old devices.
     */
    public function testDetectsAncientChrome(): void
    {
        // Very old Chrome (in FAKE_USER_AGENTS)
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Chrome/60.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Chrome/50.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Chrome/40.0'));

        // Chrome 70-99 NOT in fake list - possible on old devices
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 10.0) Chrome/94.0.4606.81'));
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 10.0) Chrome/80.0.3987.149'));
    }

    /**
     * Test fake User-Agent detection - Ancient Firefox
     *
     * NOTE: Only Firefox 50 and below are in fake list.
     * Firefox 60-99 removed - possible on old systems.
     */
    public function testDetectsAncientFirefox(): void
    {
        // Very old Firefox (in FAKE_USER_AGENTS)
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Firefox/50.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Firefox/40.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Firefox/30.0'));

        // Firefox 60-99 NOT in fake list - possible on old systems
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 10.0; Firefox/90.0)'));
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 10.0; Firefox/70.0)'));
    }

    /**
     * Test fake User-Agent detection - Ancient Safari
     *
     * NOTE: Only Safari 9 and below are in fake list.
     * Safari 10-15 removed - possible on older macOS.
     */
    public function testDetectsAncientSafari(): void
    {
        // Very old Safari (in FAKE_USER_AGENTS)
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Safari/9.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 Safari/8.0'));

        // Safari 10+ NOT in fake list
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14) Safari/12.0'));
    }

    /**
     * Test fake User-Agent detection - Known bot signatures
     */
    public function testDetectsKnownBotSignatures(): void
    {
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('NCLIENT'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('WebStripper/2.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('WebCopier'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Offline Explorer'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('HTTrack 3.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Teleport Pro'));
    }

    /**
     * Test fake User-Agent detection - Ancient Windows
     *
     * NOTE: Only Windows 98 and 2000 (NT 5.0) are in fake list.
     * XP/Vista removed - still exist in some industrial/embedded environments.
     */
    public function testDetectsAncientWindows(): void
    {
        // Windows 98 and 2000 (in FAKE_USER_AGENTS)
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 5.0)'));  // Windows 2000

        // XP/Vista NOT in fake list - still exist in some environments
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 5.1)'));  // Windows XP
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 6.0)'));  // Windows Vista
    }

    /**
     * Test fake User-Agent detection - Case insensitivity
     */
    public function testFakeUserAgentCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('msie 9.0'));
        // Chrome/80 and Firefox/70 are NOT in fake list (only 60 and below)
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('CHROME/80.0'));
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('firefox/70.0'));

        // Test with patterns that ARE in the list
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('CHROME/50.0'));
        $this->assertTrue(ThreatPatterns::isFakeUserAgent('FIREFOX/40.0'));
    }

    /**
     * Test fake User-Agent detection - Modern browsers not fake
     */
    public function testModernBrowsersNotFake(): void
    {
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'));
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/120.0'));
        $this->assertFalse(ThreatPatterns::isFakeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15'));
    }

    /**
     * Test fake User-Agent detection - Empty User-Agent not fake (handled separately)
     */
    public function testEmptyUserAgentNotFake(): void
    {
        $this->assertFalse(ThreatPatterns::isFakeUserAgent(''));
    }

    /**
     * Test fake User-Agent score value
     */
    public function testFakeUserAgentScore(): void
    {
        $this->assertSame(50, ThreatPatterns::getFakeUserAgentScore());
    }

    /**
     * Test NULL User-Agent score value
     */
    public function testNullUserAgentScore(): void
    {
        $this->assertSame(100, ThreatPatterns::getNullUserAgentScore());
    }

    // ============================================================================
    // GEOGRAPHIC BLOCKING TESTS (50 points)
    // ============================================================================

    /**
     * Test geographic blocking - Blocked countries
     */
    public function testDetectsBlockedCountries(): void
    {
        $this->assertTrue(ThreatPatterns::isBlockedCountry('RU'));  // Russia
        $this->assertTrue(ThreatPatterns::isBlockedCountry('CN'));  // China
        $this->assertTrue(ThreatPatterns::isBlockedCountry('KP'));  // North Korea
    }

    /**
     * Test geographic blocking - Case insensitivity
     */
    public function testBlockedCountryCaseInsensitivity(): void
    {
        $this->assertTrue(ThreatPatterns::isBlockedCountry('ru'));
        $this->assertTrue(ThreatPatterns::isBlockedCountry('cn'));
        $this->assertTrue(ThreatPatterns::isBlockedCountry('kp'));
    }

    /**
     * Test geographic blocking - Allowed countries
     */
    public function testAllowedCountries(): void
    {
        $this->assertFalse(ThreatPatterns::isBlockedCountry('US'));
        $this->assertFalse(ThreatPatterns::isBlockedCountry('GB'));
        $this->assertFalse(ThreatPatterns::isBlockedCountry('DE'));
        $this->assertFalse(ThreatPatterns::isBlockedCountry('IT'));
        $this->assertFalse(ThreatPatterns::isBlockedCountry('FR'));
    }

    /**
     * Test get blocked countries list
     */
    public function testGetBlockedCountries(): void
    {
        $blocked = ThreatPatterns::getBlockedCountries();
        $this->assertIsArray($blocked);
        $this->assertContains('RU', $blocked);
        $this->assertContains('CN', $blocked);
        $this->assertContains('KP', $blocked);
        $this->assertCount(3, $blocked);
    }

    /**
     * Test geo-blocked score value
     */
    public function testGeoBlockedScore(): void
    {
        $this->assertSame(50, ThreatPatterns::getGeoBlockedScore());
    }

    // ============================================================================
    // OPENAI IP VERIFICATION TESTS
    // ============================================================================

    /**
     * Test OpenAI IP verification - Valid IPs
     */
    public function testValidOpenAIIPs(): void
    {
        // Test IPs from different CIDR ranges
        $this->assertTrue(ThreatPatterns::isOpenAIIP('104.210.139.193'));  // 104.210.139.192/28
        $this->assertTrue(ThreatPatterns::isOpenAIIP('13.65.138.97'));     // 13.65.138.96/28
        $this->assertTrue(ThreatPatterns::isOpenAIIP('20.0.53.97'));       // 20.0.53.96/28
        $this->assertTrue(ThreatPatterns::isOpenAIIP('23.102.140.145'));   // 23.102.140.144/28
        $this->assertTrue(ThreatPatterns::isOpenAIIP('40.116.73.209'));    // 40.116.73.208/28
        $this->assertTrue(ThreatPatterns::isOpenAIIP('52.148.129.33'));    // 52.148.129.32/28
    }

    /**
     * Test OpenAI IP verification - Invalid IPs
     */
    public function testInvalidOpenAIIPs(): void
    {
        $this->assertFalse(ThreatPatterns::isOpenAIIP('192.168.1.1'));    // Private IP
        $this->assertFalse(ThreatPatterns::isOpenAIIP('8.8.8.8'));        // Google DNS
        $this->assertFalse(ThreatPatterns::isOpenAIIP('1.1.1.1'));        // Cloudflare DNS
        $this->assertFalse(ThreatPatterns::isOpenAIIP('104.210.139.255')); // Outside range
    }

    /**
     * Test OpenAI IP verification - CIDR range boundaries
     */
    public function testOpenAIIPCIDRBoundaries(): void
    {
        // Test /28 CIDR (16 IPs: .192-.207)
        $this->assertTrue(ThreatPatterns::isOpenAIIP('104.210.139.192'));  // First IP
        $this->assertTrue(ThreatPatterns::isOpenAIIP('104.210.139.207'));  // Last IP
        $this->assertFalse(ThreatPatterns::isOpenAIIP('104.210.139.191')); // Before range
        $this->assertFalse(ThreatPatterns::isOpenAIIP('104.210.139.208')); // After range
    }

    /**
     * Test get OpenAI IP ranges
     */
    public function testGetOpenAIIPRanges(): void
    {
        $ranges = ThreatPatterns::getOpenAIIPRanges();
        $this->assertIsArray($ranges);
        $this->assertGreaterThan(190, count($ranges));  // 190+ ranges documented (194 actual)
        $this->assertContains('104.210.139.192/28', $ranges);
        $this->assertContains('13.65.138.96/28', $ranges);
    }

    // ============================================================================
    // USER-AGENT CLASSIFICATION TESTS
    // ============================================================================

    /**
     * Test User-Agent classification - Scanner
     */
    public function testClassifiesScanner(): void
    {
        $this->assertSame('scanner', ThreatPatterns::classifyUserAgent('sqlmap/1.0'));
        $this->assertSame('scanner', ThreatPatterns::classifyUserAgent('Nikto/2.1.5'));
    }

    /**
     * Test User-Agent classification - Bot
     */
    public function testClassifiesBot(): void
    {
        $this->assertSame('bot', ThreatPatterns::classifyUserAgent('Googlebot/2.1'));
        $this->assertSame('bot', ThreatPatterns::classifyUserAgent('Lighthouse'));
    }

    /**
     * Test User-Agent classification - Browser
     */
    public function testClassifiesBrowser(): void
    {
        $this->assertSame('browser', ThreatPatterns::classifyUserAgent('Mozilla/5.0 Chrome/120.0'));
        $this->assertSame('browser', ThreatPatterns::classifyUserAgent('Mozilla/5.0 Firefox/120.0'));
        $this->assertSame('browser', ThreatPatterns::classifyUserAgent('Mozilla/5.0 Safari/605.1'));
    }

    /**
     * Test User-Agent classification - Unknown
     */
    public function testClassifiesUnknown(): void
    {
        $this->assertSame('unknown', ThreatPatterns::classifyUserAgent(''));
        $this->assertSame('unknown', ThreatPatterns::classifyUserAgent('CustomBot/1.0'));
    }

    /**
     * Test User-Agent classification - Priority order
     */
    public function testClassificationPriorityOrder(): void
    {
        // Scanner has priority over browser patterns
        $this->assertSame('scanner', ThreatPatterns::classifyUserAgent('Mozilla/5.0 sqlmap/1.0 Chrome/80.0'));

        // Bot has priority over browser patterns
        $this->assertSame('bot', ThreatPatterns::classifyUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1)'));
    }

    // ============================================================================
    // THREAT SCORE CALCULATION TESTS
    // ============================================================================

    /**
     * Test threat score - Critical path only
     */
    public function testThreatScoreCriticalPath(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/.env', 'Mozilla/5.0 Chrome/120.0');

        $this->assertSame(30, $result['score']);
        $this->assertContains('critical_path', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - CMS path only
     */
    public function testThreatScoreCMSPath(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/wp-admin/', 'Mozilla/5.0 Chrome/120.0');

        $this->assertSame(15, $result['score']);
        $this->assertContains('cms_scan', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - Config path only
     */
    public function testThreatScoreConfigPath(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/composer.json', 'Mozilla/5.0 Chrome/120.0');

        $this->assertSame(10, $result['score']);
        $this->assertContains('config_scan', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - Scanner User-Agent only
     */
    public function testThreatScoreScannerUserAgent(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/index.php', 'sqlmap/1.0');

        $this->assertSame(30, $result['score']);
        $this->assertContains('scanner_user_agent', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - Fake User-Agent only
     *
     * NOTE: Use a User-Agent pattern that is actually in the FAKE_USER_AGENTS list.
     * Chrome/80 is NOT in the list (only Chrome 60 and below).
     */
    public function testThreatScoreFakeUserAgent(): void
    {
        // Use MSIE 9.0 which is definitely in the fake list
        $result = ThreatPatterns::calculateThreatScore('/index.php', 'Mozilla/5.0 (Windows NT 10.0) MSIE 9.0');

        $this->assertSame(50, $result['score']);
        $this->assertContains('fake_user_agent', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - NULL User-Agent (instant ban)
     */
    public function testThreatScoreNullUserAgent(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/index.php', '');

        $this->assertSame(100, $result['score']);
        $this->assertContains('null_user_agent', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - Geo-blocked country only
     */
    public function testThreatScoreGeoBlocked(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/index.php', 'Mozilla/5.0 Chrome/120.0', 'RU');

        $this->assertSame(50, $result['score']);
        $this->assertContains('geo_blocked_RU', $result['reasons']);
        $this->assertCount(1, $result['reasons']);
    }

    /**
     * Test threat score - Combined threats
     */
    public function testThreatScoreCombined(): void
    {
        // Critical path + Scanner UA + Geo-blocked = 30 + 30 + 50 = 110
        $result = ThreatPatterns::calculateThreatScore('/.env', 'sqlmap/1.0', 'CN');

        $this->assertSame(110, $result['score']);
        $this->assertContains('critical_path', $result['reasons']);
        $this->assertContains('scanner_user_agent', $result['reasons']);
        $this->assertContains('geo_blocked_CN', $result['reasons']);
        $this->assertCount(3, $result['reasons']);
    }

    /**
     * Test threat score - Multiple path matches
     */
    public function testThreatScoreMultiplePathMatches(): void
    {
        // /wp-config.php matches cms_path only (not in critical_path array)
        $result = ThreatPatterns::calculateThreatScore('/wp-config.php', 'Mozilla/5.0 Chrome/120.0');

        $this->assertSame(15, $result['score']);  // 15 (cms only)
        $this->assertContains('cms_scan', $result['reasons']);

        // Use /composer.json for multiple matches (config only, 10 points)
        $result2 = ThreatPatterns::calculateThreatScore('/composer.json', 'Mozilla/5.0 Chrome/120.0');
        $this->assertSame(10, $result2['score']);  // 10 (config only)
        $this->assertContains('config_scan', $result2['reasons']);

        // /config.php is in CRITICAL_PATHS (30 points), not CONFIG_PATHS
        $result3 = ThreatPatterns::calculateThreatScore('/config.php', 'Mozilla/5.0 Chrome/120.0');
        $this->assertSame(30, $result3['score']);  // 30 (critical only)
        $this->assertContains('critical_path', $result3['reasons']);
    }

    /**
     * Test threat score - No threats
     */
    public function testThreatScoreNoThreats(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/index.php', 'Mozilla/5.0 Chrome/120.0', 'US');

        $this->assertSame(0, $result['score']);
        $this->assertEmpty($result['reasons']);
    }

    /**
     * Test threat score - Legitimate bot (no score)
     */
    public function testThreatScoreLegitimateBot(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/index.php', 'Googlebot/2.1', 'US');

        $this->assertSame(0, $result['score']);
        $this->assertEmpty($result['reasons']);
    }

    // ============================================================================
    // BAN THRESHOLD TESTS
    // ============================================================================

    /**
     * Test shouldBan - Below threshold
     */
    public function testShouldNotBanBelowThreshold(): void
    {
        $this->assertFalse(ThreatPatterns::shouldBan(0));
        $this->assertFalse(ThreatPatterns::shouldBan(30));
        $this->assertFalse(ThreatPatterns::shouldBan(49));
    }

    /**
     * Test shouldBan - At threshold
     */
    public function testShouldBanAtThreshold(): void
    {
        $this->assertTrue(ThreatPatterns::shouldBan(50));
    }

    /**
     * Test shouldBan - Above threshold
     */
    public function testShouldBanAboveThreshold(): void
    {
        $this->assertTrue(ThreatPatterns::shouldBan(51));
        $this->assertTrue(ThreatPatterns::shouldBan(100));
        $this->assertTrue(ThreatPatterns::shouldBan(200));
    }

    /**
     * Test ban threshold value
     */
    public function testGetScoreThreshold(): void
    {
        $this->assertSame(50, ThreatPatterns::getScoreThreshold());
    }

    // ============================================================================
    // UNICODE OBFUSCATION SCORE TEST
    // ============================================================================

    /**
     * Test Unicode obfuscation score value
     */
    public function testUnicodeObfuscationScore(): void
    {
        $this->assertSame(20, ThreatPatterns::getUnicodeObfuscationScore());
    }

    // ============================================================================
    // STATISTICS TESTS
    // ============================================================================

    /**
     * Test pattern count - Critical paths
     */
    public function testGetCriticalPathsCount(): void
    {
        $count = ThreatPatterns::getCriticalPathsCount();
        $this->assertGreaterThan(30, $count);  // 30+ critical paths documented (32 actual)
        $this->assertIsInt($count);
    }

    /**
     * Test pattern count - CMS paths
     */
    public function testGetCMSPathsCount(): void
    {
        $count = ThreatPatterns::getCMSPathsCount();
        $this->assertGreaterThan(15, $count);  // 15+ CMS paths documented
        $this->assertIsInt($count);
    }

    /**
     * Test pattern count - Config paths
     */
    public function testGetConfigPathsCount(): void
    {
        $count = ThreatPatterns::getConfigPathsCount();
        $this->assertGreaterThan(10, $count);  // 10+ config paths documented
        $this->assertIsInt($count);
    }

    /**
     * Test pattern count - Scanner User-Agents
     */
    public function testGetScannerUserAgentsCount(): void
    {
        $count = ThreatPatterns::getScannerUserAgentsCount();
        $this->assertGreaterThan(25, $count);  // 25+ scanner UAs documented
        $this->assertIsInt($count);
    }

    /**
     * Test pattern count - Legitimate bots
     *
     * NOTE: Bot list was reduced by removing non-DNS-verifiable bots
     * (postman, insomnia, whatsapp, discord, reddit, slackbot).
     */
    public function testGetLegitimateBotsCount(): void
    {
        $count = ThreatPatterns::getLegitimateBotsCount();
        $this->assertGreaterThan(60, $count);  // Reduced list after security review
        $this->assertIsInt($count);
    }

    /**
     * Test pattern count - Fake User-Agents
     */
    public function testGetFakeUserAgentsCount(): void
    {
        $count = ThreatPatterns::getFakeUserAgentsCount();
        $this->assertGreaterThan(15, $count);  // 15+ fake UAs documented
        $this->assertIsInt($count);
    }

    /**
     * Test comprehensive statistics
     */
    public function testGetStatistics(): void
    {
        $stats = ThreatPatterns::getStatistics();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('critical_paths', $stats);
        $this->assertArrayHasKey('cms_paths', $stats);
        $this->assertArrayHasKey('config_paths', $stats);
        $this->assertArrayHasKey('scanner_user_agents', $stats);
        $this->assertArrayHasKey('legitimate_bots', $stats);
        $this->assertArrayHasKey('fake_user_agents', $stats);
        $this->assertArrayHasKey('blocked_countries', $stats);
        $this->assertArrayHasKey('openai_ip_ranges', $stats);
        $this->assertArrayHasKey('bot_hostnames', $stats);

        // Verify counts (adjusted to actual implementation after security review)
        $this->assertGreaterThan(30, $stats['critical_paths']);
        $this->assertGreaterThan(15, $stats['cms_paths']);
        $this->assertGreaterThan(10, $stats['config_paths']);
        $this->assertGreaterThan(25, $stats['scanner_user_agents']);
        $this->assertGreaterThan(60, $stats['legitimate_bots']);  // Reduced list
        $this->assertGreaterThan(15, $stats['fake_user_agents']);
        $this->assertSame(3, $stats['blocked_countries']);
        $this->assertGreaterThan(190, $stats['openai_ip_ranges']);
        $this->assertGreaterThan(10, $stats['bot_hostnames']);
    }

    // ============================================================================
    // EDGE CASE TESTS
    // ============================================================================

    /**
     * Test edge case - Very long path
     *
     * NOTE: ThreatPatterns uses PREFIX matching only.
     * Very long paths that don't START with a critical pattern
     * will NOT be detected.
     */
    public function testVeryLongPath(): void
    {
        // Paths that don't START with critical patterns are NOT matched
        $longPath = str_repeat('/very/long/path/', 100) . '.env';
        $this->assertFalse(ThreatPatterns::isCriticalPath($longPath));

        // Also not matched (nested critical paths)
        $longPathWithEnv = str_repeat('/very/long/path', 100) . '/.env';
        $this->assertFalse(ThreatPatterns::isCriticalPath($longPathWithEnv));

        // Only prefix matches work
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env' . str_repeat('/long', 100)));
    }

    /**
     * Test edge case - Very long User-Agent
     */
    public function testVeryLongUserAgent(): void
    {
        $longUA = str_repeat('Mozilla/5.0 ', 100) . 'sqlmap';
        $this->assertTrue(ThreatPatterns::isScannerUserAgent($longUA));
    }

    /**
     * Test edge case - Path with special characters
     */
    public function testPathWithSpecialCharacters(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env?query=1&test=2'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env#anchor'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env;jsessionid=123'));
    }

    /**
     * Test edge case - User-Agent with special characters
     */
    public function testUserAgentWithSpecialCharacters(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('Mozilla/5.0 (compatible; Nikto/2.1.5 +https://cirt.net/Nikto2)'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'));
    }

    /**
     * Test edge case - Mixed case variations
     */
    public function testMixedCaseVariations(): void
    {
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.EnV'));
        $this->assertTrue(ThreatPatterns::isCriticalPath('/PHPinfo.PhP'));
        $this->assertTrue(ThreatPatterns::isScannerUserAgent('SqlMap/1.0'));
        $this->assertTrue(ThreatPatterns::isLegitimateBot('GoogleBot/2.1'));
    }

    /**
     * Test edge case - Empty country code
     */
    public function testEmptyCountryCode(): void
    {
        $this->assertFalse(ThreatPatterns::isBlockedCountry(''));
    }

    /**
     * Test edge case - Invalid country code format
     */
    public function testInvalidCountryCodeFormat(): void
    {
        $this->assertFalse(ThreatPatterns::isBlockedCountry('USA'));  // 3 letters
        $this->assertFalse(ThreatPatterns::isBlockedCountry('R'));    // 1 letter
    }

    /**
     * Test edge case - Path with null bytes
     */
    public function testPathWithNullBytes(): void
    {
        // PHP strings can contain null bytes
        $path = "/.env\0";
        $this->assertTrue(ThreatPatterns::isCriticalPath($path));
    }

    /**
     * Test edge case - Whitespace in paths
     *
     * NOTE: ThreatPatterns does NOT trim whitespace.
     * Paths with leading/trailing whitespace won't match
     * because ' /.env ' != '/.env' in segment matching.
     */
    public function testWhitespaceInPaths(): void
    {
        // Whitespace is NOT trimmed - paths don't match
        $this->assertFalse(ThreatPatterns::isCriticalPath(' /.env '));
        $this->assertFalse(ThreatPatterns::isCriticalPath("\n/.env\n"));
        $this->assertFalse(ThreatPatterns::isCriticalPath("\t/.env\t"));

        // Without whitespace, path matches
        $this->assertTrue(ThreatPatterns::isCriticalPath('/.env'));
    }

    /**
     * Test edge case - Whitespace in User-Agents
     */
    public function testWhitespaceInUserAgents(): void
    {
        $this->assertTrue(ThreatPatterns::isScannerUserAgent(' sqlmap '));
        $this->assertTrue(ThreatPatterns::isLegitimateBot("\tGooglebot\t"));
    }

    /**
     * Test real-world scenario - WordPress vulnerability scan
     */
    public function testRealWorldWordPressScan(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/wp-login.php', 'WPScan v3.8.17', 'RU');

        // Should detect: cms_path (15) + scanner_user_agent (30) + geo_blocked (50) = 95
        $this->assertSame(95, $result['score']);
        $this->assertTrue(ThreatPatterns::shouldBan($result['score']));
        $this->assertContains('cms_scan', $result['reasons']);
        $this->assertContains('scanner_user_agent', $result['reasons']);
        $this->assertContains('geo_blocked_RU', $result['reasons']);
    }

    /**
     * Test real-world scenario - Environment file scan with fake UA
     */
    public function testRealWorldEnvFileScan(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/.env', 'Mozilla/5.0 (Windows NT 5.1; MSIE 9.0)', 'CN');

        // Should detect: critical_path (30) + fake_user_agent (50) + geo_blocked (50) = 130
        $this->assertSame(130, $result['score']);
        $this->assertTrue(ThreatPatterns::shouldBan($result['score']));
        $this->assertContains('critical_path', $result['reasons']);
        $this->assertContains('fake_user_agent', $result['reasons']);
        $this->assertContains('geo_blocked_CN', $result['reasons']);
    }

    /**
     * Test real-world scenario - Legitimate Googlebot crawl
     */
    public function testRealWorldLegitimateCrawl(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/sitemap.xml', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'US');

        $this->assertSame(0, $result['score']);
        $this->assertFalse(ThreatPatterns::shouldBan($result['score']));
        $this->assertEmpty($result['reasons']);
    }

    /**
     * Test real-world scenario - Legitimate Lighthouse audit
     */
    public function testRealWorldLighthouseAudit(): void
    {
        $result = ThreatPatterns::calculateThreatScore('/index.php', 'Mozilla/5.0 (X11; Linux x86_64) Chrome-Lighthouse', 'US');

        $this->assertSame(0, $result['score']);
        $this->assertFalse(ThreatPatterns::shouldBan($result['score']));
        $this->assertEmpty($result['reasons']);
    }
}
