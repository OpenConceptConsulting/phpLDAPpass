<?php

namespace phpLDAPpass\LDAP;


class PasswordUpdater
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

    /**
     * @param User $user
     * @param string $current_pass
     * @param string $new_password
     * @return bool|string
     */
    public function update(User $user, $current_pass, $new_password)
    {
        $conn = $this->connection->getConnection();

        // Security check: remove null bytes in password
        // @see https://net.educause.edu/ir/library/pdf/csd4875.pdf
        $current_pass = str_replace("\0", '', $current_pass);

        if (true !== @ldap_bind($conn, $user->getDn(), $current_pass)) {
            return false;
        }

        $enc_new_pass = $this->encodePassword($new_password);
        $entry['userPassword'] = $enc_new_pass;

        if (@ldap_modify($conn, $user->getDn(), $entry)) {
            return $enc_new_pass;
        }

        return false;
    }

}
