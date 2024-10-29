<?php

namespace CloakWP\JWTAuth;

use CloakWP\JWTAuth\Contracts\TokenValidator as TokenValidatorContract;
use CloakWP\JWTAuth\Config\JWTAuthConfig;
use CloakWP\JWTAuth\Exceptions\JWTAuthException;
use WP_User;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class TokenValidator implements TokenValidatorContract
{
  public function __construct(private JWTAuthConfig $config)
  {
  }

  public function validateToken(string $token): WP_User
  {
    try {
      $decoded = JWT::decode($token, new Key($this->config->secretKey, 'HS256'));

      if ($decoded->iss !== $this->config->iss) {
        throw new JWTAuthException('The iss does not match with this server', 401);
      }

      if (!isset($decoded->data->user->id)) {
        throw new JWTAuthException('User ID not found in the token', 401);
      }

      $user = get_user_by('id', $decoded->data->user->id);

      if (!$user) {
        throw new JWTAuthException('User not found', 401);
      }

      return $user;
    } catch (\Exception $e) {
      throw new JWTAuthException('Invalid token: ' . $e->getMessage(), 401);
    }
  }
}