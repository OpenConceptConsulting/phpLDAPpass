<?php

namespace phpLDAPpass\LDAP;


class User
{
    /**
     * Corresponds to dn in LDAP.
     * @var string
     */
    protected $dn;

    /**
     * Corresponds to cn in LDAP.
     * @var string
     */
    protected $displayName;

    /**
     * Corresponds to uid in LDAP.
     * @var string
     */
    protected $username;

    /**
     * Corresponds to mail in LDAP.
     * @var string
     */
    protected $mail;

    /**
     * @var bool
     */
    protected $authenticated = false;

    /**
     * @param string $dn
     * @param string $username
     * @param string $displayName
     * @param string $mail
     * @param bool $isAuthenticated
     */
    function __construct($dn = null, $username = null, $displayName = null, $mail = null, $isAuthenticated = false)
    {
        $this->dn = $dn;
        $this->username = $username;
        $this->displayName = $displayName;
        $this->mail = $mail;
        $this->authenticated = $isAuthenticated;
    }

    /**
     * @return string
     */
    public function getDn()
    {
        return $this->dn;
    }

    /**
     * @return string
     */
    public function getDisplayName()
    {
        return $this->displayName;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return boolean
     */
    public function isAuthenticated()
    {
        return $this->authenticated;
    }

    /**
     * @return string
     */
    public function getMail()
    {
        return $this->mail;
    }

    /**
     * @param boolean $authenticated
     */
    public function setAuthenticated($authenticated)
    {
        $this->authenticated = $authenticated;
    }
}
