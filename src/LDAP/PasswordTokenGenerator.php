<?php

namespace phpLDAPpass\LDAP;


class PasswordTokenGenerator
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
     * @return \phpLDAPpass\LDAP\TokenFactory
     */
    public function getToken($username)
    {
        $user = UserFinder::create($this->connection)->find($username);

        if ($user instanceof User) {
            return new TokenFactory($user);
        }

        return false;
    }

}
