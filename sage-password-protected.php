<?php
/**
 * Sage Password Protected
 *
 * @copyright    Copyright (C) 2023, Adeliom - io@adeliom.com
 * @link         https://adeliom.io
 *
 * @wordpress-plugin
 * Plugin Name:       Sage Password Protected
 * Version:           1.0.0
 * Plugin URI:        https://adeliom.io/
 * Description:       An simple password protection package for Roots Sage customizable with filters.
 * Author:            Adeliom
 * Author URI:        https://adeliom.com/?utm_source=Plugin&utm_medium=Readme%20Author%20URI&utm_campaign=WP
 * License:           MIT
 * License URI:       https://choosealicense.com/licenses/mit/
 * Text Domain:       sage-password-protected
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define('SAGE_PASSWORD_PROTECTED_VERSION', '1.0.0');
define('SAGE_PASSWORD_PROTECTED_ABSPATH', dirname( plugin_basename( __FILE__ ) ));

/**
 * Password Protected
 */
class PasswordProtected
{
    /**
     * Cookie Name
     *
     * @var string
     */
    protected $cookie = '_password_protected';

    /**
     * Cipher Method
     *
     * @var string
     */
    protected $cipher = 'AES-256-CBC';

    /**
     * Initialization Vector
     *
     * @var string
     */
    protected $vector = '1234567812345678';

    /**
     * Secret Token
     *
     * @var string
     */
    protected $secret = '_this_is_very_secure';

    private static $_instance = null;

    public static function getInstance() {

        if(is_null(self::$_instance)) {
            self::$_instance = new self();
        }

        return self::$_instance;
    }

    /**
     * Constructor
     */
    public function __construct()
    {
        load_plugin_textdomain('sage-password-protected', false, SAGE_PASSWORD_PROTECTED_ABSPATH . '/languages');
        /** Hooks */
        add_action('init', [$this, 'disableCaching'], 1);
        add_action('init', [$this, 'processLogin'], 1);
        add_action('wp', [$this, 'disableFeeds']);
        add_action('template_redirect', [$this, 'showLogin'], -1);

        if(!function_exists('get_field')){
            function get_field($selector, $post_id = false)
            {
                return null;
            }
        }

        /** Configuration */
        $this->defaults = [
            'active'             => get_field('password_protected', 'option') ?? false,
            'password'           => get_field('password', 'option') ??  false,
            'secret'             => $this->secret,
            'allowFeeds'         => false,
            'allowAdmins'        => get_field('password_allow_administrators', 'option') ??  false,
            'allowUsers'         => get_field('password_allow_users', 'option') ??  false,
            'allowIpAddresses'   => get_field('password_allowed_ip_addresses', 'option') ??  false,
            'allowedIpAddresses' => [],
            'title'              => $this->name()
        ];

        $this->config = (object) wp_parse_args(apply_filters('password_protected', []), $this->defaults);

        /** Initialize WP_Error */
        $this->errors = new \WP_Error();
    }

    /**
     * Show login if password protect is active and user is not already authorized.
     *
     * @return void
     */
    public function showLogin()
    {
        if (!$this->isActive() || $this->isAllowed()) {
            return;
        }

        if (isset($_REQUEST['password_protected']) && $_REQUEST['password_protected'] == 'login') {
            echo \Roots\view( __DIR__ . '/views/password-protected.blade.php', [
                'password' => $this
            ]);

            exit();
        }

        if (wp_safe_redirect($this->requestUrl())) {
            exit();
        }
    }

    /**
     * Attempt to authorize and process the user's login with the specified password.
     *
     * @return void
     */
    public function processLogin()
    {
        if ($this->isActive() && !empty($_REQUEST['password'])) {
            if ($this->verifyPassword($_REQUEST['password'])) {
                $this->setCookie();

                if (wp_safe_redirect($this->redirectUrl())) {
                    exit;
                }

                return;
            }

            $this->unsetCookie();
            $this->errors->add('invalid_password', __('<strong>Error:</strong> The passwords do not match.'));
        }
    }

    /**
     * Returns true if password protect is enabled.
     *
     * @return boolean
     */
    public function isActive()
    {
        if ($this->config->active) {
            return is_robots() ? false : true;
        }

        return false;
    }

    /**
     * Disables page caching while password protect is active.
     *
     * @return void
     */
    public function disableCaching()
    {
        if ($this->isActive() && !defined('DONOTCACHEPAGE')) {
            define('DONOTCACHEPAGE', true);
        }
    }

    /**
     * Disables feeds if they are not explicitly enabled while password protection is active.
     *
     * @return void
     */
    public function disableFeeds()
    {
        if ($this->isActive() && !$this->allowFeeds()) {
            return collect([
                'do_feed',
                'do_feed_rdf',
                'do_feed_rss',
                'do_feed_rss2',
                'do_feed_atom'
            ])->map(function ($feed) {
                return add_action($feed, function () {
                    wp_die(sprintf(__('Feeds are not available for this site. Please visit the <a href="%s">website</a>.', 'app'), get_bloginfo('url')));
                }, 1);
            });
        }
    }

    /**
     * Returns true if feeds are allowed during password protection.
     *
     * @return boolean
     */
    protected function allowFeeds()
    {
        if ($this->config->allowFeeds && is_feed()) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if administrators are allowed to bypass password protection
     * and current user is deemed an administrator.
     *
     * @return boolean
     */
    protected function allowAdmins()
    {
        if (!is_admin() && $this->config->allowAdmins && current_user_can('manage_options')) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if users are allowed to bypass password protection
     * and current user is logged in.
     *
     * @return boolean
     */
    protected function allowUsers()
    {
        if (!is_admin() && $this->config->allowUsers && is_user_logged_in()) {
            return true;
        }

        return false;
    }

    /**
     * Returns true if the current users IP address is permitted to bypass password protection.
     *
     * @return boolean
     */
    protected function allowedIpAddress()
    {
        if ($this->config->allowIpAddresses && is_array($this->getAllowedIpAddresses())) {
            if (in_array($_SERVER['REMOTE_ADDR'], $this->getAllowedIpAddresses())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the allowed IP Addresses.
     *
     * @return array
     */
    protected function getAllowedIpAddresses()
    {
        return collect($this->config->allowedIpAddresses)
            ->map(function ($address) {
                return collect($address)
                    ->filter()
                    ->pop();
            })->filter()->toArray();
    }

    /**
     * Returns true if the user is allowed access.
     *
     * @return boolean
     */
    protected function isAllowed()
    {
        if ($this->verifyCookie() || $this->allowAdmins() || $this->allowUsers() || $this->allowedIpAddress()) {
            return true;
        }

        return false;
    }

    /**
     * Returns the current hashed password.
     *
     * @return string
     */
    protected function getPassword()
    {
        return $this->config->password;
    }

    /**
     * Returns true if the specified password is correct.
     *
     * @param  string $password
     * @return boolean
     */
    protected function verifyPassword($password)
    {
        return $password === $this->getPassword();
    }

    /**
     * Returns the hash value.
     *
     * @return string
     */
    protected function getHash()
    {
        return md5($this->getPassword());
    }

    /**
     * Returns the login page URL.
     *
     * @return string
     */
    protected function loginUrl()
    {
        return add_query_arg('password_protected', 'login', $this->url());
    }

    /**
     * Returns the redirect URL.
     *
     * @return string
     */
    public function redirectUrl()
    {
        return !empty($_REQUEST['redirect_to']) && $_REQUEST['redirect_to'] !== '/' ? $_REQUEST['redirect_to'] : $this->url();
    }

    /**
     * Returns the inital requested URL.
     *
     * @return string
     */
    protected function requestUrl()
    {
        if (!empty($_SERVER['REQUEST_URI']) && $_SERVER['REQUEST_URI'] !== '/') {
            $request = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        }

        return add_query_arg('redirect_to', urlencode($request ?? $this->url()), $this->loginUrl());
    }

    /**
     * Returns the blog title.
     *
     * @return string
     */
    public function name()
    {
        $login_header_title = get_bloginfo('name');
        $login_header_title = apply_filters_deprecated(
            'login_headertitle',
            array( $login_header_title ),
            '5.2.0',
            'login_headertext',
            __( 'Usage of the title attribute on the login logo is not recommended for accessibility reasons. Use the link text instead.' )
        );

        return empty( $login_header_title ) ? __( 'Powered by WordPress' ) : $login_header_title;
    }

    /**
     * Returns the blog title.
     *
     * @return string
     */
    public function text()
    {
        return apply_filters( 'login_headertext', $this->title() );
    }

    /**
     * Returns the blog URL.
     *
     * @return string
     */
    public function url()
    {
        return get_home_url('/');
    }

    /**
     * Returns the page title used on the password protected page.
     *
     * @return string
     */
    public function title()
    {
        return $this->config->title;
    }

    /**
     * Returns the users IP Address.
     *
     * @return string
     */
    protected function ipAddress()
    {
        return $_SERVER['X-Forwarded-For'] ?? $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Returns the users browser agent.
     *
     * @return string
     */
    protected function browserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'];
    }

    /**
     * Returns the auth cookie contents.
     *
     * @return string
     */
    protected function getCookie()
    {
        return $_COOKIE[$this->cookie] ?? false;
    }

    /**
     * Encrypts the auth cookie and sets it.
     *
     * @return void
     */
    protected function setCookie()
    {
        $cookie = openssl_encrypt(json_encode([
            'expires' => $this->getCookieDuration(),
            'hash'    => $this->getHash(),
            'ip'      => $this->ipAddress() ?? false,
            'agent'   => $this->browserAgent() ?? false
        ]), $this->cipher, $this->secret, false, $this->vector);

        return setcookie($this->cookie, $cookie, $this->getCookieDuration(), COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
    }

    /**
     * Removes the auth cookie if it is set.
     *
     * @return void
     */
    protected function unsetCookie()
    {
        return setcookie($this->cookie, '', -1, COOKIEPATH, COOKIE_DOMAIN);
    }

    /**
     * Verifies the auth cookie if it is set.
     *
     * @return boolean
     */
    protected function verifyCookie()
    {
        if (!$this->parseCookie() || $this->parseCookie()->expires < current_time('timestamp')) {
            return false;
        }

        if ($this->parseCookie()->hash !== $this->getHash()) {
            return false;
        }

        return true;
    }

    /**
     * Decrypts our auth cookie payload if it is set.
     *
     * @return array
     */
    protected function parseCookie()
    {
        if (!$cookie = openssl_decrypt($this->getCookie(), $this->cipher, $this->config->secret, false, $this->vector)) {
            return false;
        }

        return (object) json_decode($cookie, true);
    }

    /**
     * Returns the expiration age for the auth cookie.
     *
     * @param  integer $days
     * @return integer
     */
    protected function getCookieDuration($days = 1)
    {
        return current_time('timestamp') + (86400 * $days);
    }
}

/**
 * Initalize with after_setup_theme to assure Sage is loaded.
 */
add_action('init', function () {
    PasswordProtected::getInstance();
}, 0);
