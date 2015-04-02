<?php

$local = include __DIR__ . '/config.local.php';
if (!is_array($local)) {
    $local = array();
}

return array_replace_recursive(
    array(
        'slim' => array(
            'templates.path' => __DIR__ . '/templates',
            'cookies.lifetime' => '20 minutes',
        ),
        'site' => array(
            'name' => 'phpLDAPpass LDAP Self-Serve Password Change',
            'brand' => 'phpLDAPpass',
            'login' => 'To change your LDAP password using the Self-Serve password change tool, you must first login using your existing LDAP Credentials.'
        ),
        'ldap' => array(
        ),
        'password' => array(
        ),
        'twig' => array(
            'environment' => array(
                'auto_reload' => true,
                'charset' => 'utf-8',
                'debug' => false,
            ),
        ),
    ),
    $local
);
