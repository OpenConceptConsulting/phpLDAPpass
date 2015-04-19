<?php

use phpLDAPpass\LDAP\Authenticator;
use phpLDAPpass\LDAP\Connection;
use phpLDAPpass\LDAP\PasswordTokenGenerator;
use phpLDAPpass\LDAP\PasswordUpdater;
use phpLDAPpass\LDAP\RootPasswordUpdater;
use phpLDAPpass\LDAP\User;
use phpLDAPpass\LDAP\UserFinder;
use phpLDAPpass\PasswordPolicy;
use phpLDAPpass\PasswordPolicyException;
use phpLDAPpass\TokenEmailer;

$app->get(
    '/',
    function () use ($app) {
        /** @var User $user */
        $user = $_SESSION['user'];
        if (!$user->isAuthenticated()) {
            $app->redirectTo('login', array(), 307);
        }

        $app->render('index.html.twig');
    }
)->setName('root');

$app->post(
    '/change',
    function () use ($app, $config) {
        /** @var User $user */
        $user = $_SESSION['user'];
        if (!$user->isAuthenticated()) {
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

        if ($app->request()->post('new_password_confirmation', null) !== $new_pass) {
            $app->flashNow('error', "Your new password and the confirmation don't match.");
            $app->render('index.html.twig');

            return;
        }

        $policy = new PasswordPolicy($config['password']);

        try {
            $policy->check($new_pass);
        } catch (PasswordPolicyException $e) {
            $app->flashNow('error', $e->getMessage());
            $app->render('index.html.twig');

            return;
        }

        $conn = new Connection($config['ldap']);
        $updater = new PasswordUpdater($conn);

        if (false !== $updater->update($user, $current_pass, $new_pass)) {
            $app->flash('message', 'Your LDAP password was updated.');
            $app->redirectTo('root');

            return;
        }

        $app->flashNow('error', 'There was a problem updating your password.');
        $app->render('index.html.twig');
    }
)->setName('process_change');

$app->get(
    '/forgot',
    function () use ($app, $config) {
        /** @var User $user */
        $user = $_SESSION['user'];
        if ($user->isAuthenticated()) {
            $app->flash('error', "You can't be signed in.");
            $app->redirectTo('root', array(), 307);

            return;
        }

        $app->render('forgot.html.twig');
    }
)->setName('forgot');

$app->post(
    '/forgot',
    function () use ($app, $view, $config) {
        /** @var User $user */
        $user = $_SESSION['user'];
        if ($user->isAuthenticated()) {
            $app->flash('error', "You can't be signed in.");
            $app->redirectTo('root', array(), 307);

            return;
        }

        $username = $app->request()->post('username');

        if (empty($username)) {
            $app->flashNow('error', 'You need to enter your username.');
        } else {
            $conn = new Connection($config['ldap']);
            $tokenGenerator = new PasswordTokenGenerator($conn);
            if (false !== $token = $tokenGenerator->getToken($username)) {
                $emailer = new TokenEmailer($token, $config['email']);
                if ('development' === $app->getMode()) {
                    $tok = $token->getTok();
                    $app->flash('message', $tok);
                    $app->redirectTo('reset', array('tok' => $tok));
                }
                if ($emailer->mail($view->getEnvironment())) {
                    $app->flash('message', 'Password reset link sent.');
                    $app->redirectTo('login');
                }
            }
            $app->flashNow('error', 'User not found or could not send the password reset link.');
        }

        $app->render('forgot.html.twig');
    }
)->setName('process_forgot');

$app->get(
    '/reset/:tok',
    function ($tok) use ($app) {
        $app->view()->set('tok', $tok);
        $app->render('reset.html.twig');
    }
)->setName('reset');

$app->post(
    '/reset',
    function () use ($app, $config) {
        $tok = $app->request()->post('tok', '');
        $app->view()->set('tok', $tok);

        $username = $app->request()->post('username', '');
        if (empty($username)) {
            $app->flashNow('error', 'You must type your username.');
            $app->render('reset.html.twig');

            return;
        }

        $new_pass = $app->request()->post('new_password', '');
        if ($app->request()->post('new_password_confirmation', null) !== $new_pass) {
            $app->flashNow('error', "Your new password and the confirmation don't match.");
            $app->render('reset.html.twig');

            return;
        }

        $policy = new PasswordPolicy($config['password']);

        try {
            $policy->check($new_pass);
        } catch (PasswordPolicyException $e) {
            $app->flashNow('error', $e->getMessage());
            $app->render('reset.html.twig');

            return;
        }

        $conn = new Connection($config['ldap']);
        $user = UserFinder::create($conn)->find($username);

        if (!($user instanceof User)) {
            $app->flashNow('error', 'Invalid username.');
            $app->render('reset.html.twig');

            return;
        }

        $token = new \phpLDAPpass\LDAP\Token($user);

        if (!$token->checkTok(urldecode($tok))) {
            $app->flash('error', 'Invalid token.');
            $app->redirectTo('login');
        }

        $updater = new RootPasswordUpdater($conn);

        if (false !== $updater->update($user, null, $new_pass)) {
            $app->flash('message', 'Your LDAP password was updated.');
            $app->redirectTo('login');

            return;
        }

        $app->flashNow('error', 'There was a problem updating your password.');
        $app->render('reset.html.twig');
    }
)->setName('process_reset');

$app->get(
    '/login',
    function () use ($app) {
        $app->render('login.html.twig');
    }
)->setName('login');

$app->post(
    '/login',
    function () use ($app, $config) {
        $username = $app->request()->post('username');
        $password = $app->request()->post('password');

        if (empty($username) || empty($password)) {
            $app->flashNow('error', 'You need to enter both your username and password.');
        } else {
            $conn = new Connection($config['ldap']);
            $auth = new Authenticator($conn);
            if (false !== $user = $auth->auth($username, $password)) {
                $_SESSION['user'] = $user;
                session_regenerate_id();
                $app->redirectTo('root');
            } else {
                $app->flashNow('error', 'Login failed.');
            }
        }

        $app->render('login.html.twig');
    }
)->setName('process_login');

$app->get(
    '/logout',
    function () use ($app) {
        unset($_SESSION['user']);
        session_regenerate_id(true);

        $app->redirectTo('root');
    }
)->setName('logout');
