<?php
/**
 * CAS Authentication
 *
 * This plugin replaces the RoundCube login page with authentication requests
 * to a CAS server, which enables logging into RoundCube with identities
 * authenticated by the CAS server and acts as a CAS proxy to relay authenticated
 * credentials to the IMAP backend.
 *
 * @version 0.4.2
 * @author Alex Li (li@hcs.harvard.edu)
 * 
 */

class cas_authentication extends rcube_plugin {
    // fields
    private $cas_inited;
    
    /**
     * Initialize plugin
     *
     */
    function init() {
        // initialize plugin fields
        $cas_inited = false;
        
        // load plugin configurations
        $this->load_config();
        
        // add application hooks
        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('render_page', array($this, 'render_page'));
        $this->add_hook('authenticate', array($this, 'authenticate'));
        $this->add_hook('login_after', array($this, 'login_after'));
        $this->add_hook('login_failed', array($this, 'login_failed'));
        $this->add_hook('logout_after', array($this, 'logout_after'));
        $this->add_hook('imap_connect', array($this, 'imap_connect'));
    }

    /**
     * Handle plugin-specific actions
     * These actions are handled at the startup hook rather than registered as
     * custom actions because the user session does not necessarily exist when
     * these actions need to be handled.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function startup($args) {
        // intercept PGT callback action
        if ($args['action'] == 'pgtcallback') {
            // initialize CAS client
            $this->cas_init();
            
            // retrieve and store PGT if present
            phpCAS::forceAuthentication();
            
            // end script
            exit;
        }
        
        // intercept CAS logout action
        else if ($args['action'] == 'caslogout') {
            // initialize CAS client
            $this->cas_init();

            // logout from CAS server
            phpCAS::logout();

            // end script
            exit;
        }

        return $args;
    }
    
    /**
     * Intercept page rendering
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function render_page($args) {
        // intercept login template rendering in order to replace login form with CAS request
        if ($args['template'] == 'login') {
            // retrieve rcmail instance
            $rcmail = rcmail::get_instance();
            
            // save request url to a cookie
            $url = get_input_value('_url', RCUBE_INPUT_POST);
            if (empty($url) && !preg_match('/_task=logout/', $_SERVER['QUERY_STRING'])) {
                $url = $_SERVER['QUERY_STRING'];
            }
            setcookie('cas_url', $url);

            // redirect to login action
            $rcmail->output->redirect(array('action' => 'login', 'task' => 'mail'));
        }
        
        return $args;
    }

    /**
     * Inject authentication credentials
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function authenticate($args) {
        // retrieve configurations
        $cfg = rcmail::get_instance()->config->all();
        
        // initialize CAS client
        $this->cas_init();

        // attempt to authenticate with CAS server
        if (phpCAS::forceAuthentication()) {
            // retrieve authenticated credentials
            $args['user'] = phpCAS::getUser();
            if ($cfg['cas_proxy']) {
                $args['pass'] = '';
            }
            else {
                $args['pass'] = $cfg['cas_imap_password'];
            }
        }
        
        return $args;
    }
    
    /**
     * Inject post-login redirection url
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function login_after($args) {
        // restore original request parameters
        $query = array();
        if ($url = $_COOKIE['cas_url']) {
            parse_str($url, $query);
            $args = $query;
        }
        
        return $args;
    }
    
    /**
     * Intercept login failure
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function login_failed($args) {
        // retrieve rcmail instance
        $rcmail = rcmail::get_instance();
        
        // compose error page content
        global $__page_content, $__error_title, $__error_text;
        $__error_title = "IMAP LOGIN FAILED";
        $__error_text  = <<<EOF
Could not log into your IMAP service. The service may be interrupted, or you may not be authorized to access the service.<br />
Please contact the administrator of your IMAP service.<br />
Or log out by clicking on the button below, then try again with a different user name.<br />
EOF;
        $__page_content = <<<EOF
<div>
<h3 class="error-title">$__error_title</h3>
<p class="error-text">$__error_text</p>
<form name="form" action="./" method="get">
<input type="hidden" name="_action" value="caslogout" />
<p style="text-align:center;"><input type="submit" class="button mainaction" value="Logout" /></p>
</form>
</div>
EOF;
        
        // redirect to error page
        $rcmail->output->reset();
        $rcmail->output->send('error');
        
        // kill current session
        $rcmail->kill_session();
        
        // end script
        exit;
    }
    
    /**
     * Perform post-logout actions
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function logout_after($args) {
        // retrieve rcmail instance
        $rcmail = rcmail::get_instance();

        // redirect to CAS logout action
        $rcmail->output->redirect(array('action' => 'caslogout'));
    }
    
    /**
     * Inject IMAP authentication credentials
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function imap_connect($args) {
        // retrieve configurations
        $cfg = rcmail::get_instance()->config->all();
        
        // RoundCube is acting as CAS proxy
        if ($cfg['cas_proxy']) {
            // a proxy ticket has been retrieved, the IMAP server caches proxy tickets, and this is the first connection attempt
            if ($_SESSION['cas_pt'][php_uname('n')] && $cfg['cas_imap_caching'] && $args['attempt'] == 1) {
                // use existing proxy ticket in session
                $args['pass'] = $_SESSION['cas_pt'][php_uname('n')];
            }

            // no proxy tickets have been retrieved, the IMAP server doesn't cache proxy tickets, or the first connection attempt has failed
            else {
                // initialize CAS client
                $this->cas_init();

                // retrieve a new proxy ticket and store it in session
                if (phpCAS::forceAuthentication()) {
                    $_SESSION['cas_pt'][php_uname('n')] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
                    $args['pass'] = $_SESSION['cas_pt'][php_uname('n')];
                }
            }
            
            // enable retry on the first connection attempt only
            if ($args['attempt'] <= 1) {
                $args['retry'] = true;
            }
        }
        
        return $args;
    }
    
    /**
     * Initialize CAS client
     * 
     */
    private function cas_init() {
        if (!$this->cas_inited) {
            // retrieve configurations
            $cfg = rcmail::get_instance()->config->all();

            // include phpCAS
            require_once('CAS.php');
            
            // initialize CAS client
            if ($cfg['cas_proxy']) {
                phpCAS::proxy(CAS_VERSION_2_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], false);

                // set URL for PGT callback
                phpCAS::setFixedCallbackURL($this->generate_url(array('action' => 'pgtcallback')));
                
                // set PGT storage
                phpCAS::setPGTStorageFile('xml', $cfg['cas_pgt_dir']);
            }
            else {
                phpCAS::client(CAS_VERSION_2_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], false);
            }

            // set service URL for authorization with CAS server
            phpCAS::setFixedServiceURL($this->generate_url(array('action' => 'login', 'task' => 'mail')));

            // set SSL validation for the CAS server
            if ($cfg['cas_validation'] == 'self') {
                phpCAS::setCasServerCert($cfg['cas_cert']);
            }
            else if ($cfg['cas_validation'] == 'ca') {
                phpCAS::setCasServerCACert($cfg['cas_cert']);
            }
            else {
                phpCAS::setNoCasServerValidation();
            }

            // set login and logout URLs of the CAS server
            phpCAS::setServerLoginURL($cfg['cas_login_url']);
            phpCAS::setServerLogoutURL($cfg['cas_logout_url']);

            $this->cas_inited = true;
        }
    }
    
    /**
     * Build full URLs to this instance of RoundCube for use with CAS servers
     * 
     * @param array $params url parameters as key-value pairs
     * @return string full Roundcube URL
     */
    private function generate_url($params) {
        $s = ($_SERVER['HTTPS'] == 'on') ? 's' : '';
        $protocol = $this->strleft(strtolower($_SERVER['SERVER_PROTOCOL']), '/') . $s;
        $port = (($_SERVER['SERVER_PORT'] == '80' && $_SERVER['HTTPS'] != 'on') ||
                 ($_SERVER['SERVER_PORT'] == '443' && $_SERVER['HTTPS'] == 'on')) ? 
                '' : (':' .$_SERVER['SERVER_PORT']);
        $path = $this->strleft($_SERVER['REQUEST_URI'], '?');
        $parsed_params = '';
        $delm = '?';
        foreach (array_reverse($params) as $key => $val) {
            if (!empty($val)) {
                $parsed_key = $key[0] == '_' ? $key : '_' . $key;
                $parsed_params .= $delm . urlencode($parsed_key) . '=' . urlencode($val);
                $delm = '&';
            }
        }
        return $protocol . '://' . $_SERVER['SERVER_NAME'] . $port . $path . $parsed_params;
    }

    private function strleft($s1, $s2) {
        $length = strpos($s1, $s2);
        if ($length) {
            return substr($s1, 0, $length);
        }
        else {
            return $s1;
        }
    }
}
?>
