<?php


namespace App\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class AccessDeniedHandler implements AccessDeniedHandlerInterface
{
    private RouterInterface $router;

    public function __construct(RouterInterface $router)
    {
        $this->router = $router;
    }

    #[Route('/access-denied', name: 'access_denied')]
    public function handle(Request $request, AccessDeniedException $exception): RedirectResponse
    {
        // Redirige vers la page de connexion avec un message d'erreur
        return new RedirectResponse($this->router->generate('security_login'));
    }
}
