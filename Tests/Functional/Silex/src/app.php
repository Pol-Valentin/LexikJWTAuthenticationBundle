<?php

use Silex\Application;
use Silex\Provider\AssetServiceProvider;
use Silex\Provider\TwigServiceProvider;
use Silex\Provider\ServiceControllerServiceProvider;
use Silex\Provider\HttpFragmentServiceProvider;
use Lexik\ServiceProvider\LexikJWTAuthenticationServiceProvider;

$app = new Application();
$app->register(new ServiceControllerServiceProvider());
$app->register(new AssetServiceProvider());
$app->register(new TwigServiceProvider());
$app->register(new HttpFragmentServiceProvider());
$app['twig'] = $app->extend('twig', function ($twig, $app) {
    // add custom globals, filters, tags, ...

    return $twig;
});

$app->register(new \Silex\Provider\SecurityServiceProvider());
$app->register(new LexikJWTAuthenticationServiceProvider(), [

]);
$app['security.firewalls'] = [
    'login' => [
        'pattern' => '^/login',
        'stateless' => true,
        'anonymous' => true,
        'form_login' => [
            'check_path' => '/login_check',
            'require_previous_session' => false,
            'success_handler' => 'lexik_jwt_authentication.handler.authentication_success',
            'failure_handler' => 'lexik_jwt_authentication.handler.authentication_failure',
        ]
    ],
    'api' => [
        'pattern' => '^/api',
        'stateless' => true,
        'anonymous' => true,
        'guard' => [
            'authenticators' => [
                'lexik_jwt_authentication.handler.authentication_failure'
            ]
        ],
    ]
];

$app['security.access_rules'] = array(
    array('^/login', 'IS_AUTHENTICATED_ANONYMOUSLY'),
    array('^/api', 'IS_AUTHENTICATED_FULLY'),
);

return $app;
