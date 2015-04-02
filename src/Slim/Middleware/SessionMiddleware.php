<?php

namespace phpLDAPpass\Slim\Middleware;

use phpLDAPpass\LDAP\User;

class SessionMiddleware extends \Slim\Middleware
{

    /**
     * Call
     *
     * Perform actions specific to this middleware and optionally
     * call the next downstream middleware.
     */
    public function call()
    {
        $settings = $this->app->container['settings'];

        $lifetime = is_string($settings['cookies.lifetime']) ?
            strtotime($settings['cookies.lifetime']) : $settings['cookies.lifetime'];

        session_set_cookie_params(
            $lifetime,
            $settings['cookies.path'],
            $settings['cookies.domain'],
            $settings['cookies.secure'],
            $settings['cookies.httponly']
        );

        session_start();

        if (empty($_SESSION['user'])) {
            $_SESSION['user'] = new User();
        }

        $view = $this->app->view();
        $view->set('user', $_SESSION['user']);

        $this->next->call();
    }
}
