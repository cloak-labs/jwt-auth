<?php

namespace CloakWP\JWTAuth\Config;

class JWTAuthConfig
{
  public function __construct(
    public readonly string $secretKey,
    public readonly int $tokenExpiration,
    public readonly int $refreshTokenExpiration,
    public readonly bool $enableCors,
    public readonly string $iss,
  ) {
  }

  public static function fromDefaults(): self
  {
    return new self(
      secretKey: defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : '',
      tokenExpiration: defined('JWT_AUTH_EXPIRE') ? JWT_AUTH_EXPIRE : 300,
      refreshTokenExpiration: defined('JWT_AUTH_REFRESH_EXPIRE') ? JWT_AUTH_REFRESH_EXPIRE : 86400,
      enableCors: defined('JWT_AUTH_CORS_ENABLE') ? JWT_AUTH_CORS_ENABLE : false,
      iss: apply_filters('jwt_auth_iss', get_bloginfo('url')),
    );
  }
}