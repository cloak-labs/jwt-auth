<?php

namespace CloakWP\JWTAuth\Contracts;

use WP_User;
use WP_REST_Request;

interface AuthenticationHandler
{
  public function authenticateUser(WP_REST_Request $request): WP_User;
}