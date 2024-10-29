<?php

namespace CloakWP\JWTAuth;

use CloakWP\JWTAuth\Contracts\TokenGenerator as TokenGeneratorContract;
use CloakWP\JWTAuth\Config\JWTAuthConfig;
use CloakWP\JWTAuth\Exceptions\JWTAuthException;
use WP_User;
use Firebase\JWT\JWT;

class TokenGenerator implements TokenGeneratorContract
{
  public function __construct(private JWTAuthConfig $config)
  {
  }

  public function generateToken(WP_User $user): string
  {
    $issuedAt = time();
    $notBefore = apply_filters('jwt_auth_not_before', $issuedAt, $issuedAt);
    $expire = $issuedAt + $this->config->tokenExpiration;

    $payload = [
      'iss' => $this->config->iss,
      'iat' => $issuedAt,
      'nbf' => $notBefore,
      'exp' => $expire,
      'data' => [
        'user' => [
          'id' => $user->ID,
        ],
      ],
    ];

    try {
      return JWT::encode(apply_filters('jwt_auth_payload', $payload, $user), $this->config->secretKey, 'HS256');
    } catch (\Exception $e) {
      throw new JWTAuthException('Error generating token: ' . $e->getMessage(), 500);
    }
  }
}