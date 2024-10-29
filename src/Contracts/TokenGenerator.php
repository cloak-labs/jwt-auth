<?php

namespace CloakWP\JWTAuth\Contracts;

use WP_User;

interface TokenGenerator
{
  public function generateToken(WP_User $user): string;
}