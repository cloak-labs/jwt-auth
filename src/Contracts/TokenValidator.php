<?php

namespace CloakWP\JWTAuth\Contracts;

use WP_User;

interface TokenValidator
{
  public function validateToken(string $token): WP_User;
}