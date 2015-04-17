<?php

namespace phpLDAPpass\LDAP;


class Connection
{

    /**
     * @var array
     */
    protected $settings = array();

    /**
     * @var resource
     */
    protected $conn;

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
     * @return array
     */
    public function getSettings()
    {
        return $this->settings;
    }

    /**
     * @return resource
     */
    public function getConnection()
    {
        if (!is_resource($this->conn)) {
            $this->connect();
        }

        return $this->conn;
    }

    /**
     * @return resource
     * @throws LDAPException
     */
    protected function connect()
    {
        $this->conn = ldap_connect($this->settings['server'], $this->settings['port']);
        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, $this->settings['version']);
        if ('start_tls' === $this->settings['ssl']) {
            ldap_start_tls($this->conn);
        }

        if (true !== @ldap_bind($this->conn, $this->settings['binddn'], $this->settings['bindpw'])) {
            throw new LDAPException(sprintf('Could not bind to the LDAP server: %s', ldap_error($this->conn)));
        }
    }

    public function restart($full = true)
    {
        if ($full) {
            if (is_resource($this->conn)) {
                ldap_close($this->conn);
                $this->conn = null;
            }
        } else {
            if (!is_resource($this->conn)) {
                return;
            }

            if (true !== @ldap_bind($this->conn, $this->settings['binddn'], $this->settings['bindpw'])) {
                throw new LDAPException(sprintf('Could not bind to the LDAP server: %s', ldap_error($this->conn)));
            }
        }
    }

}
