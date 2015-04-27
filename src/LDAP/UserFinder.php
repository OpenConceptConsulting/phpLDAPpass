<?php

namespace phpLDAPpass\LDAP;


class UserFinder
{
    /**
     * @var Connection
     */
    protected $connection;

    /**
     * @param Connection $connection
     */
    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    /**
     * @param Connection $connection
     * @return static
     */
    public static function create(Connection $connection)
    {
        return new static($connection);
    }

    /**
     * @param string $username
     * @return bool|User
     */
    public function find($username)
    {
        $settings = $this->connection->getSettings();
        $conn = $this->connection->getConnection();

        $username = ldap_escape($username, '', LDAP_ESCAPE_FILTER);

        $results = @ldap_search(
            $conn,
            $settings['base'],
            sprintf($settings['filter'], $username),
            array('dn', 'cn', 'uid', 'mail'),
            0
        );

        if (false === $results) {
            return false;
        }

        $entries = @ldap_get_entries($conn, $results);
        @ldap_free_result($results);

        if (false === $entries || 1 !== $entries['count']) {
            return false;
        }

        return new User(
            $entries[0]['dn'],
            $entries[0]['uid'][0],
            $entries[0]['cn'][0],
            isset($entries[0]['mail'][0]) ? $entries[0]['mail'][0] : null
        );
    }

}
