<?php

namespace phpLDAPpass\LDAP;


class PasswordUpdater
{
    /**
     * @var array
     */
    protected $settings = array();

    public function __construct(array $settings = array())
    {
        $this->settings = $settings + array(
                'server' => 'localhost',
                'port' => 389,
                'version' => 3,
                'base' => '',
                'ssl' => false,
            );
    }

    /**
     * @return resource
     */
    protected function connect()
    {
        $conn = ldap_connect($this->settings['server'], $this->settings['port']);
        ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, $this->settings['version']);
        if ('start_tls' === $this->settings['ssl']) {
            ldap_start_tls($conn);
        }

        return $conn;
    }

    /**
     * @param $clear_text
     * @return string
     */
    protected function encodePassword($clear_text) {
        $salt = base64_encode(openssl_random_pseudo_bytes(6, $secure));
        while(!$secure){
            $salt = base64_encode(openssl_random_pseudo_bytes(6, $secure));
        }
        $salt = substr($salt, 0, 4);

        return sprintf('{SSHA}%s', base64_encode(sha1($clear_text . $salt, true) . $salt));
    }

    public function update(User $user, $current_pass, $new_password)
    {
        $enc_new_pass = $this->encodePassword($new_password);

        $conn = $this->connect();

        if (false === @ldap_bind($conn, $user->dn, $current_pass)) {
            return false;
        }

        $entry['userPassword'] = $enc_new_pass;

        if (@ldap_modify($conn, $user->dn, $entry)) {
            return $enc_new_pass;
        }

        return false;
    }

}
