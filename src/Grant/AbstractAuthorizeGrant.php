<?php

/**
 * Abstract authorization grant.
 *
 * @author      Julián Gutiérrez <juliangut@gmail.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

declare(strict_types=1);

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ServerRequestInterface;

use function http_build_query;

abstract class AbstractAuthorizeGrant extends AbstractGrant
{
    protected string $queryDelimiter = '?';

    /**
     * @param array<array-key,mixed> $params
     */
    public function makeRedirectUri(string $uri, array $params = []): string
    {
        $uri .= str_contains($uri, $this->queryDelimiter) ? '&' : $this->queryDelimiter;

        return $uri . http_build_query($params);
    }

    /**
     * @throws OAuthServerException
     */
    protected function createAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $client = $this->getClientEntity($request);

        $redirectUri = $this->getRedirectUri($request, $client);

        $stateParameter = $this->getQueryStringParameter('state', $request);

        $scopes = $this->validateScopes(
            $this->getQueryStringParameter('scope', $request, $this->defaultScope),
            $this->makeRedirectUri(
                $redirectUri ?? $this->getClientRedirectUri($client),
                $stateParameter !== null ? ['state' => $stateParameter] : []
            )
        );

        $authorizationRequest = new AuthorizationRequest();

        $authorizationRequest->setGrantTypeId($this->getIdentifier());
        $authorizationRequest->setClient($client);
        $authorizationRequest->setRedirectUri($redirectUri);

        if ($stateParameter !== null) {
            $authorizationRequest->setState($stateParameter);
        }

        $authorizationRequest->setScopes($scopes);

        return $authorizationRequest;
    }

    /**
     * Get the client redirect URI.
     */
    protected function getClientRedirectUri(ClientEntityInterface $client): string
    {
        return is_array($client->getRedirectUri())
            ? $client->getRedirectUri()[0]
            : $client->getRedirectUri();
    }

    /**
     * @throws OAuthServerException
     */
    protected function getClientId(ServerRequestInterface $request): ?string
    {
        return $this->getQueryStringParameter(
            'client_id',
            $request,
            $this->getServerParameter('PHP_AUTH_USER', $request)
        );
    }

    /**
     * @throws OAuthServerException
     */
    protected function getClientEntity(ServerRequestInterface $request): ClientEntityInterface
    {
        $clientId = $this->getClientId($request);

        if ($clientId === null) {
            throw OAuthServerException::invalidRequest('client_id');
        }

        return $this->getClientEntityOrFail($clientId, $request);
    }

    /**
     * @throws OAuthServerException
     */
    protected function getRedirectUri(ServerRequestInterface $request, ClientEntityInterface $client): ?string
    {
        $redirectUri = $this->getQueryStringParameter('redirect_uri', $request);

        if (!is_null($redirectUri)) {
            $this->validateRedirectUri($redirectUri, $client, $request);
        } elseif (
            $client->getRedirectUri() === '' ||
            (is_array($client->getRedirectUri()) && count($client->getRedirectUri()) !== 1)
        ) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));

            throw OAuthServerException::invalidClient($request);
        }

        return $redirectUri;
    }

    /**
     * {@inheritdoc}
     */
    public function canRespondToAuthorizationRequest(ServerRequestInterface $request): bool
    {
        return (
            isset($request->getQueryParams()['response_type'])
            && $request->getQueryParams()['response_type'] === $this->getResponseTypeIdentifier()
            && isset($request->getQueryParams()['client_id'])
        );
    }

    abstract public function getResponseTypeIdentifier(): string;
}
