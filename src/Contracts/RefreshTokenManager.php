<?php

namespace CloakWP\JWTAuth\Contracts;

use WP_User;
use WP_REST_Request;

interface RefreshTokenManager
{
  public function sendRefreshToken(WP_User $user, WP_REST_Request $request): void;
  public function validateRefreshToken(string $refreshToken): WP_User;
}