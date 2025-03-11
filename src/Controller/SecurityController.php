<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

final class SecurityController extends AbstractController
{
    use TargetPathTrait;

    /**
     * Page de connexion (remplacée par OAuth2 Google)
     */
    #[Route('/login', name: 'security_login')]
    public function login(
        #[CurrentUser] ?User $user,
        Request $request,
        AuthenticationUtils $helper
    ): Response {
        // Si l'utilisateur est déjà connecté, le rediriger vers l'administration
        if ($user) {
            return $this->redirectToRoute('admin_index');
        }

        return $this->render('security/login.html.twig', [
            'error' => $helper->getLastAuthenticationError(),
        ]);
    }

    /**
     * Route de redirection vers Google OAuth2
     */
    #[Route('/connect/google', name: 'connect_google')]
    public function connectGoogle(): Response
    {
        return $this->redirectToRoute('connect_google_check');
    }

    /**
     * Callback après authentification Google
     */
    #[Route('/connect/google/check', name: 'connect_google_check')]
    public function connectGoogleCheck(): Response
    {
        // Après connexion réussie, redirection vers l’administration
        return $this->redirectToRoute('admin_index');
    }

    /**
     * Déconnexion de l'utilisateur
     */
    #[Route('/logout', name: 'security_logout', methods: ['GET'])]
    public function logout(): void
    {
        // Symfony gère la déconnexion automatiquement, cette méthode ne sera jamais exécutée.
    }
}
