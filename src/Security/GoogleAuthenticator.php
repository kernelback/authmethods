<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use League\OAuth2\Client\Provider\Google;
use KnpU\OAuth2ClientBundle\Client\Provider\GoogleClient;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class GoogleAuthenticator extends OAuth2Authenticator
{
    private UrlGeneratorInterface $urlGenerator;
    private GoogleClient $client;
    private RequestStack $requestStack;

    public function __construct(UrlGeneratorInterface $urlGenerator, GoogleClient $client, RequestStack $requestStack)
    {
        $this->urlGenerator = $urlGenerator;
        $this->client = $client;
        $this->requestStack = $requestStack;
    }

    protected function getOAuth2Provider(): Google
    {
        return new Google([
            'clientId'     => $_ENV['GOOGLE_CLIENT_ID'],
            'clientSecret' => $_ENV['GOOGLE_CLIENT_SECRET'],
            'redirectUri'  => $this->urlGenerator->generate('connect_google_check', [], UrlGeneratorInterface::ABSOLUTE_URL),
        ]);
    }

    /**
     * Récupère l'utilisateur connecté via Google OAuth2
     */
    private function getGoogleUser(Request $request)
    {
        $session = $this->requestStack->getSession();
        $expectedState = $session->get('OAUTH2_STATE');
        $actualState = $request->query->get('state');

        if (!$expectedState || $expectedState !== $actualState) {
            throw new AuthenticationException('Invalid OAuth2 state. Please try logging in again.');
        }

        // Récupération du Token OAuth2 et de l'utilisateur
        $accessToken = $this->client->getAccessToken();
        return $this->client->fetchUserFromToken($accessToken);
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $googleUser = $this->getGoogleUser($request);
    
        dump($googleUser); // ✅ Vérifier si l'utilisateur est récupéré
        die(); // ✅ Bloque l'exécution ici pour voir le résultat
    
        return new SelfValidatingPassport(new UserBadge($googleUser->getId()));
    }
    

    public function supports(Request $request): bool
    {
        return 'connect_google_check' === $request->attributes->get('_route');
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        dump($token); // ✅ Vérifier si l'utilisateur est bien authentifié
        die(); // ✅ Bloque ici pour voir ce qu'il se passe
    
        $targetPath = $this->getTargetPath($request->getSession(), $firewallName);
        return new RedirectResponse($targetPath ?: $this->urlGenerator->generate('admin_index'));
    }
    

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new RedirectResponse($this->urlGenerator->generate('security_login'));
    }
}
