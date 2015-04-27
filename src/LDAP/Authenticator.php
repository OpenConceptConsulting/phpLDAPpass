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

        // Security check: remove null bytes in password
        // @see https://net.educause.edu/ir/library/pdf/csd4875.pdf
        $password = str_replace("\0", '', $password);

        if ($user instanceof User && !empty($password) && @ldap_bind($conn, $user->getDn(), $password)) {
            $user->setAuthenticated(true);
            return $user;
        }

        return false;
    }
}
