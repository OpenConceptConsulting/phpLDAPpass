<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/LDAP/ldap_escape.php';

$config = require __DIR__ . '/../config.php';

$app = new \Slim\Slim(
    array(
        'view'  => new \Slim\Views\Twig(),
        'debug' => false,
        'mode'  => 'production',
    ) + $config['slim']
);

$app->configureMode(
    'development',
    function () use ($app) {
        $app->config('debug', true);
    }
);

$app->add(new \phpLDAPpass\Slim\Middleware\CsrfMiddleware());
$app->add(new \phpLDAPpass\Slim\Middleware\SessionMiddleware());

/** @var \Slim\Views\Twig $view */
$view = $app->view();

$view->parserOptions = $config['twig']['environment'];

$view->parserExtensions = array(
    new \Slim\Views\TwigExtension(),
);

$view->getEnvironment()->addGlobal('site', $config['site']);

require __DIR__ . '/routes.php';

return $app;
