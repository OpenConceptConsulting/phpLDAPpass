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
     * @return \phpLDAPpass\LDAP\Token
     */
    public function getToken($username)
    {
        $user = UserFinder::create($this->connection)->find($username);

        if ($user instanceof User) {
            return new Token($user);
        }

        return false;
    }

}
