<?php

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

//Request::setTrustedProxies(array('127.0.0.1'));

$app->get('/login_check', function () use ($app) {
    throw new \RuntimeException('loginCheckAction() should never be called directly.');
})
    ->bind('login_check');


$app->get('api/secured', function () use ($app){
    return new Response();
})
    ->bind('secured');

$app->error(function (\Exception $e, Request $request, $code) use ($app) {
    if ($app['debug']) {
        return;
    }

    return new Response('', $code);
});
