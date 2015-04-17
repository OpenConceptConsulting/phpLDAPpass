<?php

namespace phpLDAPpass\LDAP;


class RootPasswordUpdater extends PasswordUpdater
{
    /**
     * This version discards the given current_pass, and updates the password as the initial bind user.
     *
     * @param User $user
     * @param string $current_pass
     * @param string $new_password
     * @return bool|string
     */
    public function update(User $user, $current_pass, $new_password)
    {
        $conn = $this->connection->getConnection();

        $enc_new_pass = $this->encodePassword($new_password);
        $entry['userPassword'] = $enc_new_pass;

        if (@ldap_modify($conn, $user->getDn(), $entry)) {
            return $enc_new_pass;
        }

        return false;
    }

}
