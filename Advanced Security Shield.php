<?php
/*
Plugin Name: Advanced Security Shield (ALFA Shell Protection)
Plugin URI: https://example.com/advanced-security-shield
Description: Comprehensive security plugin to prevent backdoor exploits, ALFA shell attacks, and unauthorized admin password changes
Version: 1.0
Author: MeckyMouse
*/

class AdvancedSecurityShield {
    public function __construct() {
        // File upload protection
        add_filter('wp_handle_upload_prefilter', array($this, 'block_malicious_uploads'));
        
        // Admin password change protection
        add_filter('wp_authenticate', array($this, 'prevent_unauthorized_password_changes'), 10, 2);
        
        // File modification protection
        add_action('init', array($this, 'block_file_modifications'));
        
        // Suspicious file detection
        add_action('admin_init', array($this, 'scan_suspicious_files'));
    }

    // Block potentially malicious file uploads
    public function block_malicious_uploads($file) {
        $dangerous_extensions = array(
            'php', 'php3', 'php4', 'php5', 'php7', 
            'phtml', 'phps', 'pl', 'py', 'jsp', 
            'asp', 'aspx', 'exe', 'shell'
        );

        $filename = strtolower($file['name']);
        $ext = pathinfo($filename, PATHINFO_EXTENSION);

        // Block known dangerous file types
        if (in_array($ext, $dangerous_extensions)) {
            $file['error'] = 'Blocked: Potentially dangerous file type';
        }

        // Check for known ALFA shell signatures
        $dangerous_signatures = array(
            'alfa', 'shell', 'backdoor', 
            'bypass', 'exploit', 'webshell'
        );

        foreach ($dangerous_signatures as $signature) {
            if (strpos($filename, $signature) !== false) {
                $file['error'] = 'Blocked: Potential malicious file detected';
            }
        }

        return $file;
    }

    // Prevent unauthorized admin password changes
    public function prevent_unauthorized_password_changes($username, $password) {
        // Implement IP-based and location-based restrictions
        $current_ip = $_SERVER['REMOTE_ADDR'];
        $allowed_ips = $this->get_allowed_admin_ips();

        if (!in_array($current_ip, $allowed_ips)) {
            // Additional verification required
            $this->trigger_security_alert($username, $current_ip);
            return new WP_Error('unauthorized_access', 'Unauthorized password change attempt');
        }

        return null;
    }

    // Get list of allowed admin IPs
    private function get_allowed_admin_ips() {
        // Option to configure allowed IPs in WordPress admin
        return apply_filters('security_allowed_admin_ips', array(
            // Add your trusted IP addresses here
            '127.0.0.1'
        ));
    }

    // Block suspicious file modifications
    public function block_file_modifications() {
        // Prevent modifications to critical WordPress files
        $protected_files = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . 'wp-includes',
            ABSPATH . 'wp-admin'
        );

        $current_file = isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '';

        foreach ($protected_files as $protected_file) {
            if (strpos($current_file, $protected_file) !== false) {
                // Log and block suspicious modification attempts
                $this->trigger_security_alert('File Modification Attempt', $current_file);
                wp_die('Unauthorized file modification blocked');
            }
        }
    }

    // Scan for suspicious files
    public function scan_suspicious_files() {
        $upload_dir = wp_upload_dir();
        $files = $this->recursive_file_search($upload_dir['basedir']);

        foreach ($files as $file) {
            if ($this->is_suspicious_file($file)) {
                // Quarantine or delete suspicious files
                $this->quarantine_file($file);
            }
        }
    }

    // Recursive file search
    private function recursive_file_search($dir) {
        $files = array();
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $path) {
            if ($path->isFile()) {
                $files[] = $path->getPathname();
            }
        }

        return $files;
    }

    // Check if file is suspicious
    private function is_suspicious_file($filepath) {
        $filename = basename($filepath);
        $content = file_get_contents($filepath);

        $suspicious_indicators = array(
            'eval(',
            'base64_decode',
            'system(',
            'exec(',
            'shell_exec',
            'passthru(',
            'alfa',
            'backdoor'
        );

        foreach ($suspicious_indicators as $indicator) {
            if (stripos($filename, $indicator) !== false || 
                stripos($content, $indicator) !== false) {
                return true;
            }
        }

        return false;
    }

    // Quarantine suspicious files
    private function quarantine_file($filepath) {
        $quarantine_dir = wp_upload_dir()['basedir'] . '/quarantine/';
        
        // Create quarantine directory if not exists
        if (!file_exists($quarantine_dir)) {
            mkdir($quarantine_dir, 0755, true);
        }

        $new_path = $quarantine_dir . basename($filepath);
        rename($filepath, $new_path);

        // Log the quarantine action
        $this->trigger_security_alert('File Quarantined', $filepath);
    }

    // Trigger security alerts
    private function trigger_security_alert($event, $details) {
        // Implement email notifications, logging, etc.
        error_log("Security Alert: $event - Details: $details");
        
        // Optional: Send email to site admin
        $admin_email = get_option('admin_email');
        wp_mail($admin_email, 'Security Alert', 
            "Security event detected:\n\nEvent: $event\nDetails: $details"
        );
    }
}

// Initialize the plugin
new AdvancedSecurityShield();