<?php

namespace phpLDAPpass\LDAP;


class Authenticator
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
     * @param string $username
     * @param string $password
     * @return bool|User
     */
    public function auth($username, $password)
    {
        $user = UserFinder::create($this->connection)->find($username);
        $conn = $this->connection->getConnection();

        if ($user instanceof User && @ldap_bind($conn, $user->getDn(), $password)) {
            $user->setAuthenticated(true);
            return $user;
        }

        return false;
    }
}
