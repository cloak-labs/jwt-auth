<?php

namespace CloakWP\JWTAuth;

use CloakWP\JWTAuth\Contracts\RefreshTokenManager as RefreshTokenManagerContract;
use CloakWP\JWTAuth\Config\JWTAuthConfig;
use CloakWP\JWTAuth\Exceptions\JWTAuthException;
use WP_User;
use WP_REST_Request;

class RefreshTokenManager implements RefreshTokenManagerContract
{
  public function __construct(private JWTAuthConfig $config)
  {
  }

  public function sendRefreshToken(WP_User $user, WP_REST_Request $request): void
  {
    $refreshToken = bin2hex(random_bytes(32));
    $expires = time() + $this->config->refreshTokenExpiration;

    setcookie('refresh_token', $user->ID . '.' . $refreshToken, [
      'expires' => $expires,
      'path' => COOKIEPATH,
      'domain' => COOKIE_DOMAIN,
      'secure' => is_ssl(),
      'httponly' => true,
    ]);

    $device = $request->get_param('device') ?: '';
    $userRefreshTokens = get_user_meta($user->ID, 'jwt_auth_refresh_tokens', true) ?: [];
    $userRefreshTokens[$device] = [
      'token' => $refreshToken,
      'expires' => $expires,
    ];
    update_user_meta($user->ID, 'jwt_auth_refresh_tokens', $userRefreshTokens);
  }

  public function validateRefreshToken(string $refreshToken): WP_User
  {
    $parts = explode('.', $refreshToken);
    if (count($parts) !== 2 || empty(intval($parts[0])) || empty($parts[1])) {
      throw new JWTAuthException('Invalid refresh token format', 401);
    }

    [$userId, $token] = $parts;
    $user = get_user_by('id', $userId);

    if (!$user) {
      throw new JWTAuthException('User not found', 401);
    }

    $userRefreshTokens = get_user_meta($user->ID, 'jwt_auth_refresh_tokens', true) ?: [];
    $validToken = false;

    foreach ($userRefreshTokens as $device => $tokenData) {
      if ($tokenData['token'] === $token && $tokenData['expires'] > time()) {
        $validToken = true;
        break;
      }
    }

    if (!$validToken) {
      throw new JWTAuthException('Invalid or expired refresh token', 401);
    }

    return $user;
  }
}