<?php

namespace phpLDAPpass\LDAP;


class Authenticator
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
                'filter' => '(&(uid=%s)(objectClass=posixAccount))',
                'binddn' => null,
                'bindpw' => null,
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

    public function auth($user, $password)
    {
        $conn = $this->connect();

        if (false === @ldap_bind($conn, $this->settings['binddn'], $this->settings['bindpw'])) {
            return false;
        }

        $results = @ldap_search($conn, $this->settings['base'], sprintf($this->settings['filter'], $user), array('dn'), 0);

        if (false === $results) {
            return false;
        }

        $entries = @ldap_get_entries($conn, $results);
        @ldap_free_result($results);

        if (false === $entries || 1 !== $entries['count']) {
            return false;
        }

        $dn = $entries[0]['dn'];

        if (@ldap_bind($conn, $dn, $password)) {
            $results = @ldap_read($conn, $dn, '(objectclass=*)', array('cn', 'uid', 'userPassword'), 0);

            if (false === $results) {
                return false;
            }

            $entries = @ldap_get_entries($conn, $results);
            @ldap_free_result($results);

            if (false === $entries || 1 !== $entries['count']) {
                return false;
            }

            return new User($dn, $entries[0]['uid'][0], $entries[0]['cn'][0], $entries[0]['userpassword'][0], true);
        }

        return false;
    }
}
