<?php

namespace phpLDAPpass\LDAP;


class PasswordPolicy
{

    const PASS = 1;
    const FAIL_MIN_LENGTH = -1;
    const FAIL_ALPHA = -2;
    const FAIL_LOWER = -3;
    const FAIL_UPPER = -4;
    const FAIL_DIGIT = -5;
    const FAIL_SPECIAL = -6;

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
     * @return int
     */
    public function check($password) {
        if (false !== $this->settings['min_length']) {
            if (strlen($password) < $this->settings['min_length']) {
                return static::FAIL_MIN_LENGTH;
            }
        }

        if (false !== $this->settings['alpha']) {
            if (preg_match_all('@[[:alpha:]]@', $password, $matches) < $this->settings['alpha']) {
                return static::FAIL_ALPHA;
            }
        }

        if (false !== $this->settings['lower']) {
            if (preg_match_all('@[[:lower:]]@', $password, $matches) < $this->settings['lower']) {
                return static::FAIL_LOWER;
            }
        }

        if (false !== $this->settings['upper']) {
            if (preg_match_all('@[[:upper:]]@', $password, $matches) < $this->settings['upper']) {
                return static::FAIL_UPPER;
            }
        }

        if (false !== $this->settings['digit']) {
            if (preg_match_all('@[[:digit:]]@', $password, $matches) < $this->settings['digit']) {
                return static::FAIL_DIGIT;
            }
        }

        if (false !== $this->settings['special']) {
            if (preg_match_all('@[^a-zA-Z0-9]@', $password, $matches) < $this->settings['special']) {
                return static::FAIL_SPECIAL;
            }
        }

        return true;
    }

}
