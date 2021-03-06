<?php

namespace phpLDAPpass;


use phpLDAPpass\LDAP\TokenFactory;

class TokenEmailer
{

    /**
     * @var \phpLDAPpass\LDAP\TokenFactory
     */
    protected $tokenFactory;
    /**
     * @var array
     */
    protected $settings;

    /**
     * @param \phpLDAPpass\LDAP\TokenFactory $tokenFactory
     * @param array $settings
     */
    function __construct(TokenFactory $tokenFactory, array $settings = array())
    {
        $this->tokenFactory = $tokenFactory;
        $this->settings = $settings + array(
                'subject' => 'LDAP Password Reset',
                'from' => 'phpLDAPpass@localhost',
                'host' => 'localhost',
                'port' => '25'
            );
    }

    /**
     * @param \Twig_Environment $twig
     * @return bool
     */
    function mail(\Twig_Environment $twig)
    {
        $token = $this->tokenFactory->getToken();

        $message = new \Swift_Message($this->settings['subject']);
        $message->setFrom($this->settings['from']);
        $message->setTo($this->tokenFactory->getUser()->getMail(), $this->tokenFactory->getUser()->getDisplayName());

        $context = array(
            'user' => $this->tokenFactory->getUser(),
            'token' => $token,
            'enctoken' => urlencode($token),
        );

        $message->setBody($twig->render('email/forgot.html.twig', $context), 'text/html');
        $message->addPart($twig->render('email/forgot.text.twig', $context), 'text/plain');

        $transport = new \Swift_SmtpTransport($this->settings['host'], $this->settings['port']);

        if (array_key_exists('username', $this->settings)) {
            $transport->setUsername($this->settings['username']);
        }
        if (array_key_exists('password', $this->settings)) {
            $transport->setPassword($this->settings['password']);
        }
        if (array_key_exists('encryption', $this->settings)) {
            $transport->setEncryption($this->settings['encryption']);
        }
        if (array_key_exists('domain', $this->settings)) {
            $transport->setLocalDomain($this->settings['domain']);
        }
        if (array_key_exists('auth', $this->settings)) {
            $transport->setAuthMode($this->settings['auth']);
        }

        $mailer = new \Swift_Mailer($transport);

        return 1 === $mailer->send($message);
    }


}
