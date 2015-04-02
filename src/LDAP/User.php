<?php

namespace phpLDAPpass\LDAP;


class User
{
    /**
     * Corresponds to dn in LDAP.
     * @var string
     */
    public $dn;

    /**
     * Corresponds to cn in LDAP.
     * @var string
     */
    public $displayName;

    /**
     * Corresponds to uid in LDAP.
     * @var string
     */
    public $username;

    /**
     * Corresponds to userPassword in LDAP.
     * @var string
     */
    public $password;

    /**
     * @var bool
     */
    public $isAuthenticated = false;

    /**
     * @param string $dn
     * @param string $username
     * @param string $displayName
     * @param string $password
     * @param bool $isAuthenticated
     */
    function __construct($dn = null, $username = null, $displayName = null, $password = null, $isAuthenticated = false)
    {
        $this->dn = $dn;
        $this->username = $username;
        $this->displayName = $displayName;
        $this->password = $password;
        $this->isAuthenticated = $isAuthenticated;
    }
}
