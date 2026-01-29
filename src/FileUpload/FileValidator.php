<?php

declare(strict_types=1);

namespace AdosLabs\EnterpriseSecurityShield\FileUpload;

/**
 * Enterprise File Upload Validator
 *
 * Multi-layer file validation to prevent malicious uploads:
 * - MIME type detection (magic bytes, not extension)
 * - Extension validation (whitelist/blacklist)
 * - Content analysis (embedded scripts, polyglots)
 * - Size limits (per type)
 * - Image validation (dimensions, corruption)
 * - Archive inspection (zip bombs, nested archives)
 * - Antivirus integration (ClamAV)
 *
 * PROTECTS AGAINST:
 * - Webshell uploads (.php disguised as .jpg)
 * - MIME type spoofing
 * - Polyglot files (valid image + valid PHP)
 * - ZIP bombs (decompression attacks)
 * - SVG XSS attacks
 * - PDF JavaScript injection
 * - Double extensions (.php.jpg)
 * - Null byte injection (file.php%00.jpg)
 *
 * @version 1.0.0
 */
final class FileValidator
{
    /**
     * Magic bytes signatures for file type detection
     */
    private const MAGIC_BYTES = [
        // Images
        'image/jpeg' => [[0 => "\xFF\xD8\xFF"]],
        'image/png' => [[0 => "\x89PNG\r\n\x1a\n"]],
        'image/gif' => [[0 => "GIF87a"], [0 => "GIF89a"]],
        'image/webp' => [[0 => "RIFF", 8 => "WEBP"]],
        'image/bmp' => [[0 => "BM"]],
        'image/tiff' => [[0 => "II\x2a\x00"], [0 => "MM\x00\x2a"]],
        'image/x-icon' => [[0 => "\x00\x00\x01\x00"]],
        'image/svg+xml' => [[0 => "<?xml"], [0 => "<svg"]],

        // Documents
        'application/pdf' => [[0 => "%PDF"]],
        'application/msword' => [[0 => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"]],
        'application/vnd.openxmlformats-officedocument' => [[0 => "PK\x03\x04"]],

        // Archives
        'application/zip' => [[0 => "PK\x03\x04"], [0 => "PK\x05\x06"], [0 => "PK\x07\x08"]],
        'application/x-rar' => [[0 => "Rar!\x1a\x07"]],
        'application/gzip' => [[0 => "\x1f\x8b"]],
        'application/x-7z-compressed' => [[0 => "7z\xBC\xAF\x27\x1C"]],
        'application/x-tar' => [[257 => "ustar"]],

        // Audio/Video
        'audio/mpeg' => [[0 => "\xFF\xFB"], [0 => "\xFF\xFA"], [0 => "ID3"]],
        'audio/wav' => [[0 => "RIFF", 8 => "WAVE"]],
        'video/mp4' => [[4 => "ftyp"]],
        'video/webm' => [[0 => "\x1a\x45\xdf\xa3"]],

        // Text/Code (dangerous)
        'text/html' => [[0 => "<!DOCTYPE"], [0 => "<html"], [0 => "<HTML"]],
        'application/javascript' => [],
        'text/x-php' => [[0 => "<?php"], [0 => "<?="], [0 => "<?\n"], [0 => "<?\r"]],
    ];

    /**
     * Dangerous file extensions (always blocked)
     */
    private const DANGEROUS_EXTENSIONS = [
        // Server-side scripts
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar',
        'asp', 'aspx', 'asa', 'asax', 'ascx', 'ashx', 'asmx', 'axd',
        'jsp', 'jspx', 'jsf', 'jspa',
        'cgi', 'pl', 'py', 'rb', 'sh', 'bash', 'zsh',
        'exe', 'dll', 'so', 'dylib', 'bin', 'com', 'bat', 'cmd', 'ps1',

        // Config files
        'htaccess', 'htpasswd', 'ini', 'config', 'conf', 'cfg',
        'env', 'yaml', 'yml', 'toml', 'json',

        // Potentially dangerous
        'svg', 'xml', 'xsl', 'xslt',
        'swf', 'jar', 'war', 'ear',
        'hta', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'msc',
    ];

    /**
     * PHP code signatures to detect in files
     */
    private const PHP_SIGNATURES = [
        '<?php',
        '<?=',
        '<? ',
        "<?\n",
        "<?\r",
        '<%',
        '<script language="php">',
        '<script language=php>',
    ];

    /**
     * JavaScript signatures (for SVG/HTML)
     */
    private const JS_SIGNATURES = [
        'javascript:',
        'vbscript:',
        'onclick',
        'onerror',
        'onload',
        'onmouseover',
        'onfocus',
        'onblur',
        '<script',
        'eval(',
        'document.cookie',
        'document.write',
        'window.location',
    ];

    private array $config;
    private ?ClamAVClient $clamav = null;

    /**
     * @param array{
     *     allowed_extensions?: array<string>,
     *     blocked_extensions?: array<string>,
     *     max_file_size?: int,
     *     max_image_width?: int,
     *     max_image_height?: int,
     *     check_magic_bytes?: bool,
     *     check_content?: bool,
     *     check_image?: bool,
     *     check_archive?: bool,
     *     max_archive_files?: int,
     *     max_archive_size?: int,
     *     max_archive_depth?: int,
     *     allow_svg?: bool,
     *     sanitize_svg?: bool,
     *     clamav_enabled?: bool,
     *     clamav_socket?: string
     * } $config
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt', 'csv'],
            'blocked_extensions' => self::DANGEROUS_EXTENSIONS,
            'max_file_size' => 10 * 1024 * 1024, // 10 MB
            'max_image_width' => 10000,
            'max_image_height' => 10000,
            'check_magic_bytes' => true,
            'check_content' => true,
            'check_image' => true,
            'check_archive' => true,
            'max_archive_files' => 100,
            'max_archive_size' => 100 * 1024 * 1024, // 100 MB uncompressed
            'max_archive_depth' => 3,
            'allow_svg' => false,
            'sanitize_svg' => true,
            'clamav_enabled' => false,
            'clamav_socket' => '/var/run/clamav/clamd.sock',
        ], $config);
    }

    /**
     * Validate uploaded file
     *
     * @param string $filePath Path to uploaded file
     * @param string $originalName Original filename
     * @return ValidationResult
     */
    public function validate(string $filePath, string $originalName): ValidationResult
    {
        $errors = [];
        $warnings = [];
        $metadata = [];

        // Check if file exists
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return new ValidationResult(false, ['File not found or not readable'], [], []);
        }

        // Get file info
        $fileSizeRaw = filesize($filePath);
        $fileSize = $fileSizeRaw !== false ? $fileSizeRaw : 0;
        $extension = $this->getExtension($originalName);
        $detectedMime = $this->detectMimeType($filePath);

        $metadata['original_name'] = $originalName;
        $metadata['extension'] = $extension;
        $metadata['size'] = $fileSize;
        $metadata['detected_mime'] = $detectedMime;

        // 1. Size check
        if ($fileSize > $this->config['max_file_size']) {
            $errors[] = sprintf(
                'File size (%s) exceeds maximum allowed (%s)',
                $this->formatBytes($fileSize),
                $this->formatBytes((int) $this->config['max_file_size'])
            );
        }

        // 2. Extension check
        $extensionResult = $this->validateExtension($extension, $originalName);
        if (!$extensionResult['valid']) {
            $errors = array_merge($errors, $extensionResult['errors']);
        }
        if (!empty($extensionResult['warnings'])) {
            $warnings = array_merge($warnings, $extensionResult['warnings']);
        }

        // 3. Magic bytes check
        if ($this->config['check_magic_bytes']) {
            $magicResult = $this->validateMagicBytes($filePath, $extension);
            if (!$magicResult['valid']) {
                $errors = array_merge($errors, $magicResult['errors']);
            }
            $metadata['magic_mime'] = $magicResult['detected_mime'] ?? null;
        }

        // 4. Content analysis (PHP/JS injection)
        if ($this->config['check_content']) {
            $contentResult = $this->validateContent($filePath, $extension);
            if (!$contentResult['valid']) {
                $errors = array_merge($errors, $contentResult['errors']);
            }
        }

        // 5. Image validation
        if ($this->config['check_image'] && $this->isImageExtension($extension)) {
            $imageResult = $this->validateImage($filePath);
            if (!$imageResult['valid']) {
                $errors = array_merge($errors, $imageResult['errors']);
            }
            $metadata['image'] = $imageResult['metadata'] ?? [];
        }

        // 6. Archive validation
        if ($this->config['check_archive'] && $this->isArchiveExtension($extension)) {
            $archiveResult = $this->validateArchive($filePath);
            if (!$archiveResult['valid']) {
                $errors = array_merge($errors, $archiveResult['errors']);
            }
            if (!empty($archiveResult['warnings'])) {
                $warnings = array_merge($warnings, $archiveResult['warnings']);
            }
            $metadata['archive'] = $archiveResult['metadata'] ?? [];
        }

        // 7. SVG sanitization
        if ($extension === 'svg' && $this->config['allow_svg']) {
            $svgResult = $this->validateSvg($filePath);
            if (!$svgResult['valid']) {
                $errors = array_merge($errors, $svgResult['errors']);
            }
        }

        // 8. ClamAV scan
        if ($this->config['clamav_enabled']) {
            $clamResult = $this->scanWithClamAV($filePath);
            if (!$clamResult['valid']) {
                $errors = array_merge($errors, $clamResult['errors']);
            }
            $metadata['antivirus'] = $clamResult['metadata'] ?? [];
        }

        return new ValidationResult(
            empty($errors),
            $errors,
            $warnings,
            $metadata
        );
    }

    /**
     * Get safe extension from filename
     */
    private function getExtension(string $filename): string
    {
        // Remove null bytes (injection attack)
        $filename = str_replace("\x00", '', $filename);

        // Get extension
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        // Check for double extensions
        $parts = explode('.', strtolower($filename));
        if (count($parts) > 2) {
            // Check if any middle part is a dangerous extension
            for ($i = 1; $i < count($parts) - 1; $i++) {
                if (in_array($parts[$i], self::DANGEROUS_EXTENSIONS, true)) {
                    return $parts[$i]; // Return the dangerous one
                }
            }
        }

        return $ext;
    }

    /**
     * Validate extension
     */
    private function validateExtension(string $extension, string $originalName): array
    {
        $errors = [];
        $warnings = [];

        // Check blocked extensions
        if (in_array($extension, $this->config['blocked_extensions'], true)) {
            $errors[] = "File extension '{$extension}' is not allowed";
        }

        // Check allowed extensions
        if (!empty($this->config['allowed_extensions'])) {
            if (!in_array($extension, $this->config['allowed_extensions'], true)) {
                $errors[] = "File extension '{$extension}' is not in the allowed list";
            }
        }

        // Check for double extensions
        $parts = explode('.', strtolower($originalName));
        if (count($parts) > 2) {
            foreach ($parts as $i => $part) {
                if ($i > 0 && $i < count($parts) - 1) {
                    if (in_array($part, self::DANGEROUS_EXTENSIONS, true)) {
                        $errors[] = "Double extension attack detected: '.{$part}' in filename";
                    }
                }
            }
        }

        // Check for null bytes in filename
        if (str_contains($originalName, "\x00")) {
            $errors[] = "Null byte detected in filename (injection attack)";
        }

        // Check for suspicious characters
        if (preg_match('/[<>:"|?*\x00-\x1f]/', $originalName)) {
            $warnings[] = "Filename contains suspicious characters";
        }

        return ['valid' => empty($errors), 'errors' => $errors, 'warnings' => $warnings];
    }

    /**
     * Validate magic bytes match declared extension
     */
    private function validateMagicBytes(string $filePath, string $extension): array
    {
        $errors = [];
        $detectedMime = $this->detectMimeType($filePath);

        // Map extension to expected MIME
        $expectedMimes = $this->getExpectedMimes($extension);

        if (!empty($expectedMimes) && $detectedMime !== null) {
            $mimeMatch = false;
            foreach ($expectedMimes as $expected) {
                if (str_starts_with($detectedMime, $expected)) {
                    $mimeMatch = true;
                    break;
                }
            }

            if (!$mimeMatch) {
                $errors[] = sprintf(
                    "MIME type mismatch: extension '%s' but detected '%s' (possible spoofing)",
                    $extension,
                    $detectedMime
                );
            }
        }

        // Check for PHP/script MIME types
        $dangerousMimes = ['text/x-php', 'application/x-php', 'application/x-httpd-php'];
        if (in_array($detectedMime, $dangerousMimes, true)) {
            $errors[] = "File detected as PHP script regardless of extension";
        }

        return ['valid' => empty($errors), 'errors' => $errors, 'detected_mime' => $detectedMime];
    }

    /**
     * Detect MIME type using magic bytes
     */
    private function detectMimeType(string $filePath): ?string
    {
        $handle = @fopen($filePath, 'rb');
        if ($handle === false) {
            return null;
        }

        $header = fread($handle, 512);
        fclose($handle);

        if ($header === false || strlen($header) < 4) {
            return null;
        }

        foreach (self::MAGIC_BYTES as $mime => $signatures) {
            foreach ($signatures as $signature) {
                $match = true;
                foreach ($signature as $offset => $bytes) {
                    if ($offset + strlen($bytes) > strlen($header)) {
                        $match = false;
                        break;
                    }
                    if (substr($header, $offset, strlen($bytes)) !== $bytes) {
                        $match = false;
                        break;
                    }
                }
                if ($match) {
                    return $mime;
                }
            }
        }

        // Fallback to finfo
        if (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo !== false) {
                $mime = finfo_file($finfo, $filePath);
                finfo_close($finfo);
                return $mime ?: null;
            }
        }

        return null;
    }

    /**
     * Validate file content for embedded scripts
     */
    private function validateContent(string $filePath, string $extension): array
    {
        $errors = [];

        $content = @file_get_contents($filePath, false, null, 0, 65536); // First 64KB
        if ($content === false) {
            return ['valid' => true, 'errors' => []];
        }

        $contentLower = strtolower($content);

        // Check for PHP code in non-PHP files
        if (!in_array($extension, ['php', 'phtml', 'phar'], true)) {
            foreach (self::PHP_SIGNATURES as $sig) {
                if (str_contains($contentLower, strtolower($sig))) {
                    $errors[] = "PHP code detected in file (possible webshell)";
                    break;
                }
            }
        }

        // Check for JavaScript in images/documents
        if ($this->isImageExtension($extension) || in_array($extension, ['pdf', 'svg'], true)) {
            foreach (self::JS_SIGNATURES as $sig) {
                if (str_contains($contentLower, strtolower($sig))) {
                    $errors[] = "JavaScript/Event handler detected in file (XSS risk)";
                    break;
                }
            }
        }

        // Check for HTML in non-HTML files
        if (!in_array($extension, ['html', 'htm', 'svg', 'xml'], true)) {
            if (preg_match('/<\s*(html|script|iframe|object|embed|form|body)/i', $content)) {
                $errors[] = "HTML content detected in non-HTML file";
            }
        }

        // Polyglot detection: Valid image header + PHP code
        if ($this->isImageExtension($extension)) {
            $magicMime = $this->detectMimeType($filePath);
            $hasImageHeader = $magicMime !== null && str_starts_with($magicMime, 'image/');
            $hasPhp = false;
            foreach (self::PHP_SIGNATURES as $sig) {
                if (str_contains($content, $sig)) {
                    $hasPhp = true;
                    break;
                }
            }
            if ($hasImageHeader && $hasPhp) {
                $errors[] = "Polyglot file detected: Valid image with embedded PHP code";
            }
        }

        return ['valid' => empty($errors), 'errors' => $errors];
    }

    /**
     * Validate image file
     */
    private function validateImage(string $filePath): array
    {
        $errors = [];
        $metadata = [];

        if (!function_exists('getimagesize')) {
            return ['valid' => true, 'errors' => [], 'metadata' => []];
        }

        $imageInfo = @getimagesize($filePath);
        if ($imageInfo === false) {
            $errors[] = "Invalid or corrupted image file";
            return ['valid' => false, 'errors' => $errors, 'metadata' => []];
        }

        $metadata['width'] = $imageInfo[0];
        $metadata['height'] = $imageInfo[1];
        $metadata['type'] = $imageInfo[2];
        $metadata['mime'] = $imageInfo['mime'] ?? null;

        // Check dimensions
        if ($imageInfo[0] > $this->config['max_image_width']) {
            $errors[] = sprintf(
                "Image width (%d) exceeds maximum (%d)",
                $imageInfo[0],
                $this->config['max_image_width']
            );
        }

        if ($imageInfo[1] > $this->config['max_image_height']) {
            $errors[] = sprintf(
                "Image height (%d) exceeds maximum (%d)",
                $imageInfo[1],
                $this->config['max_image_height']
            );
        }

        // Decompression bomb detection (pixel count)
        $pixels = $imageInfo[0] * $imageInfo[1];
        if ($pixels > 100000000) { // 100 megapixels
            $errors[] = "Image has excessive pixel count (decompression bomb risk)";
        }

        // Check compression ratio for decompression bombs
        $fileSize = filesize($filePath);
        if ($fileSize > 0) {
            $bitsPerPixel = ($fileSize * 8) / $pixels;
            if ($bitsPerPixel < 0.01) { // Suspiciously high compression
                $errors[] = "Image has suspicious compression ratio (possible bomb)";
            }
        }

        return ['valid' => empty($errors), 'errors' => $errors, 'metadata' => $metadata];
    }

    /**
     * Validate archive file
     */
    private function validateArchive(string $filePath): array
    {
        $errors = [];
        $warnings = [];
        $metadata = [];

        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        if ($extension === 'zip' && class_exists(\ZipArchive::class)) {
            $zip = new \ZipArchive();
            $result = $zip->open($filePath, \ZipArchive::RDONLY);

            if ($result !== true) {
                $errors[] = "Invalid or corrupted ZIP archive";
                return ['valid' => false, 'errors' => $errors, 'warnings' => [], 'metadata' => []];
            }

            $fileCount = $zip->numFiles;
            $totalSize = 0;
            $dangerousFiles = [];
            $nestedArchives = 0;

            $metadata['file_count'] = $fileCount;

            // Check file count
            if ($fileCount > $this->config['max_archive_files']) {
                $errors[] = sprintf(
                    "Archive contains too many files (%d > %d)",
                    $fileCount,
                    $this->config['max_archive_files']
                );
            }

            for ($i = 0; $i < $fileCount; $i++) {
                $stat = $zip->statIndex($i);
                if ($stat === false) {
                    continue;
                }

                $entryName = $stat['name'];
                $entrySize = $stat['size'];
                $totalSize += $entrySize;

                // Check for path traversal
                if (str_contains($entryName, '..') || str_starts_with($entryName, '/')) {
                    $errors[] = "Archive contains path traversal: " . substr($entryName, 0, 50);
                }

                // Check for dangerous files
                $entryExt = strtolower(pathinfo($entryName, PATHINFO_EXTENSION));
                if (in_array($entryExt, self::DANGEROUS_EXTENSIONS, true)) {
                    $dangerousFiles[] = $entryName;
                }

                // Check for nested archives
                if (in_array($entryExt, ['zip', 'rar', '7z', 'tar', 'gz'], true)) {
                    $nestedArchives++;
                }
            }

            $metadata['total_uncompressed_size'] = $totalSize;
            $metadata['nested_archives'] = $nestedArchives;

            // Check total uncompressed size (ZIP bomb)
            if ($totalSize > $this->config['max_archive_size']) {
                $errors[] = sprintf(
                    "Archive uncompressed size too large (%s > %s) - possible ZIP bomb",
                    $this->formatBytes($totalSize),
                    $this->formatBytes($this->config['max_archive_size'])
                );
            }

            // Check compression ratio
            $compressedSize = filesize($filePath);
            if ($compressedSize > 0 && $totalSize > 0) {
                $ratio = $totalSize / $compressedSize;
                $metadata['compression_ratio'] = round($ratio, 2);
                if ($ratio > 1000) { // 1000:1 ratio is suspicious
                    $errors[] = sprintf("Suspicious compression ratio (%.0f:1) - possible ZIP bomb", $ratio);
                }
            }

            // Warn about dangerous files
            if (!empty($dangerousFiles)) {
                $warnings[] = "Archive contains potentially dangerous files: " .
                    implode(', ', array_slice($dangerousFiles, 0, 5)) .
                    (count($dangerousFiles) > 5 ? '...' : '');
            }

            // Warn about nested archives
            if ($nestedArchives > $this->config['max_archive_depth']) {
                $warnings[] = sprintf("Archive contains %d nested archives", $nestedArchives);
            }

            $zip->close();
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'warnings' => $warnings,
            'metadata' => $metadata,
        ];
    }

    /**
     * Validate and optionally sanitize SVG
     */
    private function validateSvg(string $filePath): array
    {
        $errors = [];

        $content = @file_get_contents($filePath);
        if ($content === false) {
            return ['valid' => false, 'errors' => ['Cannot read SVG file']];
        }

        // Check for script elements
        if (preg_match('/<\s*script/i', $content)) {
            $errors[] = "SVG contains script element";
        }

        // Check for event handlers
        if (preg_match('/\s+on\w+\s*=/i', $content)) {
            $errors[] = "SVG contains event handlers";
        }

        // Check for javascript: URLs
        if (preg_match('/javascript\s*:/i', $content)) {
            $errors[] = "SVG contains javascript: URL";
        }

        // Check for data: URLs with scripts
        if (preg_match('/data\s*:\s*text\/html/i', $content)) {
            $errors[] = "SVG contains data:text/html URL";
        }

        // Check for external references (SSRF risk)
        if (preg_match('/xlink:href\s*=\s*["\']https?:/i', $content)) {
            $errors[] = "SVG contains external HTTP references";
        }

        // Check for foreignObject (can contain HTML)
        if (preg_match('/<\s*foreignObject/i', $content)) {
            $errors[] = "SVG contains foreignObject element";
        }

        // Check for use element with external reference
        if (preg_match('/<\s*use[^>]+xlink:href\s*=\s*["\'][^#]/i', $content)) {
            $errors[] = "SVG use element references external resource";
        }

        return ['valid' => empty($errors), 'errors' => $errors];
    }

    /**
     * Scan file with ClamAV
     */
    private function scanWithClamAV(string $filePath): array
    {
        if ($this->clamav === null) {
            $this->clamav = new ClamAVClient($this->config['clamav_socket']);
        }

        try {
            $result = $this->clamav->scanFile($filePath);
            return [
                'valid' => $result['clean'],
                'errors' => $result['clean'] ? [] : ["Malware detected: " . ($result['virus'] ?? 'Unknown')],
                'metadata' => [
                    'scanned' => true,
                    'clean' => $result['clean'],
                    'virus' => $result['virus'] ?? null,
                ],
            ];
        } catch (\Exception $e) {
            // ClamAV not available - log warning but don't block
            return [
                'valid' => true,
                'errors' => [],
                'metadata' => [
                    'scanned' => false,
                    'error' => $e->getMessage(),
                ],
            ];
        }
    }

    /**
     * Get expected MIME types for extension
     */
    private function getExpectedMimes(string $extension): array
    {
        $map = [
            'jpg' => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png' => ['image/png'],
            'gif' => ['image/gif'],
            'webp' => ['image/webp'],
            'bmp' => ['image/bmp', 'image/x-ms-bmp'],
            'tiff' => ['image/tiff'],
            'tif' => ['image/tiff'],
            'ico' => ['image/x-icon', 'image/vnd.microsoft.icon'],
            'svg' => ['image/svg+xml', 'text/xml', 'application/xml'],
            'pdf' => ['application/pdf'],
            'doc' => ['application/msword'],
            'docx' => ['application/vnd.openxmlformats-officedocument', 'application/zip'],
            'xls' => ['application/vnd.ms-excel'],
            'xlsx' => ['application/vnd.openxmlformats-officedocument', 'application/zip'],
            'zip' => ['application/zip', 'application/x-zip-compressed'],
            'rar' => ['application/x-rar', 'application/x-rar-compressed'],
            'gz' => ['application/gzip', 'application/x-gzip'],
            '7z' => ['application/x-7z-compressed'],
            'tar' => ['application/x-tar'],
            'mp3' => ['audio/mpeg'],
            'wav' => ['audio/wav', 'audio/x-wav'],
            'mp4' => ['video/mp4'],
            'webm' => ['video/webm'],
            'txt' => ['text/plain'],
            'csv' => ['text/csv', 'text/plain'],
            'html' => ['text/html'],
            'htm' => ['text/html'],
            'xml' => ['text/xml', 'application/xml'],
            'json' => ['application/json', 'text/json'],
        ];

        return $map[$extension] ?? [];
    }

    /**
     * Check if extension is for image
     */
    private function isImageExtension(string $extension): bool
    {
        return in_array($extension, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'tif', 'ico', 'svg'], true);
    }

    /**
     * Check if extension is for archive
     */
    private function isArchiveExtension(string $extension): bool
    {
        return in_array($extension, ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'], true);
    }

    /**
     * Format bytes for display
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Sanitize SVG file (remove dangerous elements)
     */
    public function sanitizeSvg(string $content): string
    {
        // Remove script tags
        $content = preg_replace('/<\s*script[^>]*>.*?<\s*\/\s*script\s*>/is', '', $content) ?? $content;

        // Remove event handlers
        $content = preg_replace('/\s+on\w+\s*=\s*["\'][^"\']*["\']?/i', '', $content) ?? $content;
        $content = preg_replace('/\s+on\w+\s*=\s*[^\s>]*/i', '', $content) ?? $content;

        // Remove javascript: URLs
        $content = preg_replace('/javascript\s*:[^"\'>\s]*/i', '', $content) ?? $content;

        // Remove data: URLs with HTML
        $content = preg_replace('/data\s*:\s*text\/html[^"\'>\s]*/i', '', $content) ?? $content;

        // Remove foreignObject
        $content = preg_replace('/<\s*foreignObject[^>]*>.*?<\s*\/\s*foreignObject\s*>/is', '', $content) ?? $content;

        return $content;
    }

    /**
     * Configure ClamAV client
     */
    public function setClamAVClient(ClamAVClient $client): self
    {
        $this->clamav = $client;
        return $this;
    }
}
