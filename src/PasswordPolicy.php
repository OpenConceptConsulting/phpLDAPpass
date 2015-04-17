<?php

namespace phpLDAPpass;


class PasswordPolicy
{

    /**
     * @var array
     */
    protected $settings = array();

    public function __construct(array $settings = array())
    {
        $this->settings = $settings + array(
                'min_length' => false,
                'alpha' => false,
                'upper' => false,
                'lower' => false,
                'digit' => false,
                'special' => false,
            );
    }

    /**
     * @param string $password
     * @return bool
     * @throws PasswordPolicyException
     */
    public function check($password)
    {
        if (false !== $this->settings['min_length']) {
            if (strlen($password) < $this->settings['min_length']) {
                throw new PasswordPolicyException(
                    sprintf(
                        'Your password is too short. Please make it %d characters minimum.',
                        $this->settings['min_length']
                    )
                );
            }
        }

        if (false !== $this->settings['alpha']) {
            if (preg_match_all('@[a-zA-Z]@', $password, $matches) < $this->settings['alpha']) {
                throw new PasswordPolicyException(
                    sprintf(
                        'Your password does not contain enough alpha characters. You need at least %d.',
                        $this->settings['alpha']
                    )
                );
            }
        }

        if (false !== $this->settings['lower']) {
            if (preg_match_all('@[a-z]@', $password, $matches) < $this->settings['lower']) {
                throw new PasswordPolicyException(
                    sprintf(
                        'Your password does not contain enough lowercase alpha characters. You need at least %d.',
                        $this->settings['lower']
                    )
                );
            }
        }

        if (false !== $this->settings['upper']) {
            if (preg_match_all('@[A-Z]@', $password, $matches) < $this->settings['upper']) {
                throw new PasswordPolicyException(
                    sprintf(
                        'Your password does not contain enough uppercase alpha characters. You need at least %d.',
                        $this->settings['upper']
                    )
                );
            }
        }

        if (false !== $this->settings['digit']) {
            if (preg_match_all('@[0-9]@', $password, $matches) < $this->settings['digit']) {
                throw new PasswordPolicyException(
                    sprintf(
                        'Your password does not contain enough digit characters. You need at least %d.',
                        $this->settings['digit']
                    )
                );
            }
        }

        if (false !== $this->settings['special']) {
            if (preg_match_all('@[^a-zA-Z0-9]@', $password, $matches) < $this->settings['special']) {
                throw new PasswordPolicyException(
                    sprintf(
                        'Your password does not contain enough special characters. You need at least %d.',
                        $this->settings['special']
                    )
                );
            }
        }

        return true;
    }

}
