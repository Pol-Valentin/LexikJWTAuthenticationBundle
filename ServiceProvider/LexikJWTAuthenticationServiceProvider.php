<?php

namespace Lexik\ServiceProvider;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\DefaultEncoder;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Provider\JWTProvider;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Firewall\JWTListener;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Guard\JWTTokenAuthenticator;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Authentication\AuthenticationFailureHandler;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Authentication\AuthenticationSuccessHandler;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\EntryPoint\JWTEntryPoint;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWSProvider\DefaultJWSProvider;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWSProvider\LcobucciJWSProvider;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTManager;
use Lexik\Bundle\JWTAuthenticationBundle\Services\KeyLoader\OpenSSLKeyLoader;
use Lexik\Bundle\JWTAuthenticationBundle\Services\KeyLoader\RawKeyLoader;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\AuthorizationHeaderTokenExtractor;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\ChainTokenExtractor;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\CookieTokenExtractor;
use Lexik\Bundle\JWTAuthenticationBundle\TokenExtractor\QueryParameterTokenExtractor;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Api\BootableProviderInterface;
use Silex\Application;

class LexikJWTAuthenticationServiceProvider implements ServiceProviderInterface, BootableProviderInterface
{
    public function register(Container $app)
    {
        $defaultOptions = [
            'lexik_jwt_authentication.private_key_path' => null,
            'lexik_jwt_authentication.public_key_path' => null,
            'lexik_jwt_authentication.pass_phrase' => '',
            'lexik_jwt_authentication.token_ttl' => 3600,
            'lexik_jwt_authentication.user_identity_field' => 'username',
            'lexik_jwt_authentication.encoder.service' => 'lexik_jwt_authentication.encoder.default',
            'lexik_jwt_authentication.encoder.crypto_engine' => 'openssl',
            'lexik_jwt_authentication.encoder.signature_algorithm' => 'RS256',
            'lexik_jwt_authentication.token_extractors.authorization_header.enabled' => true,
            'lexik_jwt_authentication.token_extractors.authorization_header.prefix' => 'Bearer',
            'lexik_jwt_authentication.token_extractors.authorization_header.name' => 'Authorization',
            'lexik_jwt_authentication.token_extractors.cookie.enabled' => false,
            'lexik_jwt_authentication.token_extractors.cookie.name' => 'BEARER',
            'lexik_jwt_authentication.token_extractors.query_parameter.enabled' => false,
            'lexik_jwt_authentication.token_extractors.query_parameter.name' => 'bearer',
        ];

        $app['lexik_jwt_authentication.encoder.abstract'] = $app->protect(function ($jwsProviderName) use ($app) {
            return new DefaultEncoder($app[$jwsProviderName]);
        });

        $app['lexik_jwt_authentication.encoder.default'] = function () use ($app) {
            return $app['lexik_jwt_authentication.encoder.abstract']('lexik_jwt_authentication.jws_provider.default');
        };

        $app['lexik_jwt_authentication.encoder.lcobucci'] = function () use ($app) {
            return $app['lexik_jwt_authentication.encoder.abstract']('lexik_jwt_authentication.jws_provider.lcobucci');
        };

        $app['lexik_jwt_authentication.jwt_manager'] = function () use ($app, $defaultOptions) {
            $jwtManager = new JWTManager(
                $app['lexik_jwt_authentication.encoder'],
                $app['dispatcher']
            );

            $jwtManager->setUserIdentityField(isset($app['lexik_jwt_authentication.user_identity_field']) ? $app['lexik_jwt_authentication.user_identity_field'] : $defaultOptions['lexik_jwt_authentication.user_identity_field']);

            return $jwtManager;
        };

        $app['lexik_jwt_authentication.jws_provider.default'] = function () use ($app, $defaultOptions) {
            return new DefaultJWSProvider(
                $app['lexik_jwt_authentication.key_loader'],
                isset($app['lexik_jwt_authentication.encoder.crypto_engine']) ? $app['lexik_jwt_authentication.encoder.crypto_engine'] : $defaultOptions['lexik_jwt_authentication.encoder.crypto_engine'],
                isset($app['lexik_jwt_authentication.encoder.signature_algorithm']) ? $app['lexik_jwt_authentication.encoder.signature_algorithm'] : $defaultOptions['lexik_jwt_authentication.encoder.signature_algorithm'],
                isset($app['lexik_jwt_authentication.token_ttl']) ? $app['lexik_jwt_authentication.token_ttl'] : $defaultOptions['lexik_jwt_authentication.token_ttl']
            );
        };

        $app['lexik_jwt_authentication.jws_provider.lcobucci'] = function () use ($app) {
            return new LcobucciJWSProvider(
                $app['lexik_jwt_authentication.key_loader'],
                $app['lexik_jwt_authentication.encoder.crypto_engine'],
                $app['lexik_jwt_authentication.encoder.signature_algorithm'],
                $app['lexik_jwt_authentication.token_ttl']
            );
        };

        $app['lexik_jwt_authentication.security.guard.jwt_token_authenticator.abstract'] = function () use ($app) {
            return new JWTTokenAuthenticator(
                $app['lexik_jwt_authentication.jwt_manager'],
                $app['dispatcher'],
                $app['lexik_jwt_authentication.extractor.chain_extractor']
            );
        };

        $app['lexik_jwt_authentication.security.guard.jwt_token_authenticator'] = function () use ($app) {
            return $app['lexik_jwt_authentication.security.guard.jwt_token_authenticator.abstract'];
        };

        $app['lexik_jwt_authentication.handler.authentication_success'] = function () use ($app) {

            $authenticationSuccessHandler = new AuthenticationSuccessHandler(
                $app['lexik_jwt_authentication.jwt_manager'],
                $app['dispatcher']
            );
            $authenticationSuccessHandler->setLogger($app['logger']);

            return $authenticationSuccessHandler;
        };

        $app['lexik_jwt_authentication.handler.authentication_failure'] = function () use ($app) {
            $authenticationFailureHandler = new AuthenticationFailureHandler(
                $app['dispatcher']
            );
            $authenticationFailureHandler->setLogger($app['logger']);

            return $authenticationFailureHandler;
        };

        $app['lexik_jwt_authentication.key_loader.openssl'] = function () use ($app, $defaultOptions) {
            return new OpenSSLKeyLoader(
                isset($app['lexik_jwt_authentication.private_key_path']) ? $app['lexik_jwt_authentication.private_key_path'] : $defaultOptions['lexik_jwt_authentication.private_key_path'],
                isset($app['lexik_jwt_authentication.public_key_path']) ? $app['lexik_jwt_authentication.public_key_path'] : $defaultOptions['lexik_jwt_authentication.public_key_path'],
                isset($app['lexik_jwt_authentication.pass_phrase']) ? $app['lexik_jwt_authentication.pass_phrase'] : $defaultOptions['lexik_jwt_authentication.pass_phrase']
            );
        };

        $app['lexik_jwt_authentication.key_loader.raw'] = function () use ($app, $defaultOptions) {
            return new RawKeyLoader(
                isset($app['lexik_jwt_authentication.private_key_path']) ? $app['lexik_jwt_authentication.private_key_path'] : $defaultOptions['lexik_jwt_authentication.private_key_path'],
                isset($app['lexik_jwt_authentication.public_key_path']) ? $app['lexik_jwt_authentication.public_key_path'] : $defaultOptions['lexik_jwt_authentication.public_key_path'],
                isset($app['lexik_jwt_authentication.pass_phrase']) ? $app['lexik_jwt_authentication.pass_phrase'] : $defaultOptions['lexik_jwt_authentication.pass_phrase']
            );
        };

        $app['lexik_jwt_authentication.security.authentication.provider'] = $app->protect(
            function ($userProviderServiceName) use ($app, $defaultOptions) {
                //@TODO deprecated
                $jwtProvider = new JWTProvider(
                    $app[$userProviderServiceName],
                    $app['lexik_jwt_authentication.jwt_manager'],
                    $app['dispatcher']
                );
                $jwtProvider->setUserIdentityField(isset($app['lexik_jwt_authentication.user_identity_field']) ? $app['lexik_jwt_authentication.user_identity_field'] : $defaultOptions['lexik_jwt_authentication.user_identity_field']);

                return $jwtProvider;
            }
        );

        $app['lexik_jwt_authentication.security.authentication.listener'] = $app->protect(
            function ($optionsArgumentName) use ($app) {
                //@TODO deprecated
                $JWTListener = new JWTListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    $app[$optionsArgumentName]
                );

                $JWTListener->setDispatcher($app['dispatcher']);

                return $JWTListener;
            }
        );

        $app['lexik_jwt_authentication.security.authentication.entry_point'] = $app->protect(
            function () use ($app) {
                //@TODO deprecated
                return new JWTEntryPoint();
            }
        );

        $app['lexik_jwt_authentication.extractor.authorization_header_extractor'] = function () use ($app, $defaultOptions) {
            return new AuthorizationHeaderTokenExtractor(
                isset($app['lexik_jwt_authentication.token_extractors.authorization_header.prefix']) ? $app['lexik_jwt_authentication.token_extractors.authorization_header.prefix'] : $defaultOptions['lexik_jwt_authentication.token_extractors.authorization_header.prefix'],
                isset($app['lexik_jwt_authentication.token_extractors.authorization_header.name']) ? $app['lexik_jwt_authentication.token_extractors.authorization_header.name'] : $defaultOptions['lexik_jwt_authentication.token_extractors.authorization_header.name']
            );
        };

        $app['lexik_jwt_authentication.extractor.query_parameter_extractor'] = function () use ($app, $defaultOptions) {
            return new QueryParameterTokenExtractor(
                isset($app['lexik_jwt_authentication.token_extractors.query_parameter.name']) ? $app['lexik_jwt_authentication.token_extractors.query_parameter.name'] : $defaultOptions['lexik_jwt_authentication.token_extractors.query_parameter.name']
            );
        };

        $app['lexik_jwt_authentication.extractor.cookie_extractor'] = function () use ($app, $defaultOptions) {
            return new CookieTokenExtractor(
                isset($app['lexik_jwt_authentication.token_extractors.cookie.name']) ? $app['lexik_jwt_authentication.token_extractors.cookie.name'] : $defaultOptions['lexik_jwt_authentication.token_extractors.cookie.name']
            );
        };

        $app['lexik_jwt_authentication.extractor.chain_extractor'] = function ($extractorServiceNameCollection) use ($app) {
            $extractors = [];
            foreach ($extractorServiceNameCollection as $extractorServiceName) {
                $extractors[] = $app[$extractorServiceName];
            }

            return new ChainTokenExtractor(
                $extractors
            );
        };

        //Use given config
        $app['lexik_jwt_authentication.encoder'] = function () use ($app, $defaultOptions) {
            return $app[
            isset($app['lexik_jwt_authentication.encoder.service']) ?
                $app['lexik_jwt_authentication.encoder.service'] :
                $defaultOptions['lexik_jwt_authentication.encoder.service']
            ];
        };
        $app['lexik_jwt_authentication.key_loader'] = function () use ($app, $defaultOptions) {
            return $app['lexik_jwt_authentication.key_loader.'
            . (
            'openssl' === isset($app['lexik_jwt_authentication.encoder.crypto_engine']) ? $app['lexik_jwt_authentication.encoder.crypto_engine'] : $defaultOptions['lexik_jwt_authentication.encoder.crypto_engine'] ?
                isset($app['lexik_jwt_authentication.encoder.crypto_engine']) ? $app['lexik_jwt_authentication.encoder.crypto_engine'] : $defaultOptions['lexik_jwt_authentication.encoder.crypto_engine'] :
                'raw'
            )];
        };


        //Authentication provider factory
        $app['security.authentication_listener.factory.lexik_jwt'] = $app->protect(
            function ($name, $config) use ($app) {
                $providerId = 'security.authentication.provider.jwt.' . $name;
                $app[$providerId] = function () use ($app, $name) {
                    return $app['lexik_jwt_authentication.security.authentication.provider'](
                        $app['security.user_provider.' . $name]
                    );
                };

                $listenerId = 'security.authentication.listener.jwt.' . $name;
                $app[$listenerId] = function () use ($app, $config) {
                    return $app['lexik_jwt_authentication.security.authentication.listener'](
                        $config
                    );
                };

                $defaultEntryPoint = null;
                $entryPointId = $defaultEntryPoint;
                if ($config['create_entry_point']) {
                    //@TODO createEntryPoint
                    $entryPointId = $this->createEntryPoint($app, $name, $defaultEntryPoint);
                }

                if ($config['authorization_header']['enabled']) {
                    $authorizationHeaderExtractorId = 'lexik_jwt_authentication.extractor.authorization_header_extractor.' . $name;
                    $app[$authorizationHeaderExtractorId] = function () use ($app, $config) {
                        return $app['lexik_jwt_authentication.extractor.authorization_header_extractor'](
                            $config['authorization_header']['prefix'],
                            $config['authorization_header']['name']
                        );
                    };
                    $app[$listenerId] = $app->extend($listenerId, function ($listener) use ($app, $authorizationHeaderExtractorId) {
                        $listener->addTokenExtractor([$app[$authorizationHeaderExtractorId]]);

                        return $listener;
                    });
                }

                if ($config['query_parameter']['enabled']) {
                    $queryParameterExtractorId = 'lexik_jwt_authentication.extractor.query_parameter_extractor.' . $name;
                    $app[$queryParameterExtractorId] = function () use ($app, $config) {
                        return $app['lexik_jwt_authentication.extractor.query_parameter_extractor'](
                            $config['query_parameter']['name']
                        );
                    };
                    $app[$listenerId] = $app->extend($listenerId, function ($listener) use ($app, $queryParameterExtractorId) {
                        $listener->addTokenExtractor([$app[$queryParameterExtractorId]]);

                        return $listener;
                    });
                }

                if ($config['cookie']['enabled']) {
                    $cookieExtractorId = 'lexik_jwt_authentication.extractor.cookie_extractor.' . $name;
                    $app[$cookieExtractorId] = function () use ($app, $config) {
                        return $app['lexik_jwt_authentication.extractor.cookie_extractor'](
                            $config['cookie']['name']
                        );
                    };
                    $app[$listenerId] = $app->extend($listenerId, function ($listener) use ($app, $cookieExtractorId) {
                        $listener->addTokenExtractor([$app[$cookieExtractorId]]);

                        return $listener;
                    });
                }
                return [$providerId, $listenerId, $entryPointId, 'pre_auth'];
            }
        );
    }

    public function boot(Application $app)
    {
        if (isset($app['lexik_jwt_authentication.token_extractors.authorization_header.enabled'])) {
            $app->extend('lexik_jwt_authentication.extractor.chain_extractor', function ($chainExtractor) use ($app) {
                $chainExtractor->addExtractor($app['lexik_jwt_authentication.extractor.authorization_header_extractor']);

                return $chainExtractor;
            });
        }

        if (isset($app['lexik_jwt_authentication.token_extractors.query_parameter.enabled'])) {
            $app->extend('lexik_jwt_authentication.extractor.chain_extractor', function ($chainExtractor) use ($app) {
                $chainExtractor->addExtractor($app['lexik_jwt_authentication.extractor.query_parameter_extractor']);

                return $chainExtractor;
            });
        }

        if (isset($app['lexik_jwt_authentication.token_extractors.cookie.enabled'])) {
            $app->extend('lexik_jwt_authentication.extractor.chain_extractor', function ($chainExtractor) use ($app) {
                $chainExtractor->addExtractor($app['lexik_jwt_authentication.extractor.cookie_extractor']);

                return $chainExtractor;
            });
        }
    }

}