<?php

use phpLDAPpass\LDAP\Authenticator;
use phpLDAPpass\LDAP\PasswordPolicy;
use phpLDAPpass\LDAP\PasswordUpdater;
use phpLDAPpass\Slim\Middleware\SessionMiddleware;
use Slim\Extras\Middleware\CsrfGuard;
use Slim\Slim;
use Slim\Views\Twig;
use Slim\Views\TwigExtension;

require __DIR__ . '/../vendor/autoload.php';

// Setup

$config = require __DIR__ . '/../config.php';

$app = new Slim(
    array(
        'view' => new Twig(),
        'debug' => true,
    ) + $config['slim']
);

$app->add(new CsrfGuard());
$app->add(new SessionMiddleware());

/** @var Twig $view */
$view = $app->view();

$view->set('site', $config['site']);

$view->parserOptions = $config['twig']['environment'];

$view->parserExtensions = array(
    new TwigExtension(),
);

// Routing

$app->get(
    '/',
    function () use ($app) {
        /** @var \phpLDAPpass\LDAP\User $user */
        $user = $_SESSION['user'];
        if (!$user->isAuthenticated) {
            $app->redirectTo('login', array(), 307);
        }

        $app->render('index.html.twig');
    }
)->setName('root');

$app->post(
    '/changepass',
    function () use ($app, $config) {
        /** @var \phpLDAPpass\LDAP\User $user */
        $user = $_SESSION['user'];
        if (!$user->isAuthenticated) {
            $app->flash('error', 'You must be signed in.');
            $app->redirectTo('login');

            return;
        }

        $current_pass = $app->request()->post('current_password', '');

        if (empty($current_pass)) {
            $app->flashNow('error', 'You must type your existing password.');
            $app->render('index.html.twig');

            return;
        }

        $new_pass = $app->request()->post('new_password', '');

        if ($app->request()->post('new_password_confirmation', '') !== $new_pass) {
            $app->flashNow('error', "Your new password and the confirmation don't match.");
            $app->render('index.html.twig');

            return;
        }

        $policy = new PasswordPolicy($config['password']);

        switch ($policy->check($new_pass)) {
            case PasswordPolicy::PASS:
                // pass
                break;
            case PasswordPolicy::FAIL_MIN_LENGTH:
                $app->flashNow(
                    'error',
                    sprintf(
                        'Your password is too short. Please make it %d characters minimum.',
                        $config['password']['min_length']
                    )
                );
                $app->render('index.html.twig');

                return;
            case PasswordPolicy::FAIL_ALPHA:
                $app->flashNow(
                    'error',
                    sprintf(
                    'Your password does not contain enough alpha characters. You need at least %d.',
                        $config['password']['alpha']
                    )
                );
                $app->render('index.html.twig');

                return;
            case PasswordPolicy::FAIL_LOWER:
                $app->flashNow(
                    'error',
                    sprintf(
                        'Your password does not contain enough lowercase alpha characters. You need at least %d.',
                        $config['password']['lower']
                    )
                );
                $app->render('index.html.twig');

                return;
            case PasswordPolicy::FAIL_UPPER:
                $app->flashNow(
                    'error',
                    sprintf(
                        'Your password does not contain enough alpha characters. You need at least %d.',
                        $config['password']['upper']
                    )
                );
                $app->render('index.html.twig');

                return;
            case PasswordPolicy::FAIL_DIGIT:
                $app->flashNow(
                    'error',
                    sprintf(
                        'Your password does not contain enough digit characters. You need at least %d.',
                        $config['password']['digit']
                    )
                );
                $app->render('index.html.twig');

                return;
            case PasswordPolicy::FAIL_SPECIAL:
                $app->flashNow(
                    'error',
                    sprintf(
                        'Your password does not contain enough special characters. You need at least %d.',
                        $config['password']['special']
                    )
                );
                $app->render('index.html.twig');

                return;
            default:
                $app->flashNow('error', 'Your password failed to match the specified requirements.');
                $app->render('index.html.twig');

                return;
        }

        $updater = new PasswordUpdater($config['ldap']);

        if (false !== $pass = $updater->update($user, $current_pass, $new_pass)) {
            $app->flash('message', 'Your LDAP password was updated.');
            $_SESSION['user']->password = $user->password = $pass;
            $app->redirectTo('root');

            return;
        }

        $app->flashNow('error', 'There was a problem updating your password.');
        $app->render('index.html.twig');
    }
)->setName('changepass');

$app->map(
    '/login',
    function () use ($app, $config) {
        if ($app->request()->isPost()) {
            $username = $app->request()->post('username');
            $password = $app->request()->post('password');

            if (empty($username) || empty($password)) {
                $app->flashNow('error', 'You need to enter both your username and password.');
            } else {
                $auth = new Authenticator($config['ldap']);
                if (false !== $user = $auth->auth($username, $password)) {
                    $_SESSION['user'] = $user;
                    session_regenerate_id();
                    $app->redirectTo('root');
                } else {
                    $app->flashNow('error', 'Login failed.');
                }
            }
        }
        $app->render('login.html.twig');
    }
)->via('GET', 'POST')->setName('login');

$app->get(
    '/logout',
    function () use ($app) {
        unset($_SESSION['user']);
        session_regenerate_id(true);

        $app->redirectTo('root');
    }
)->setName('logout');

$app->run();
