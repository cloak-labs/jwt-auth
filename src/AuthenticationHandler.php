<?php

namespace CloakWP\JWTAuth;

use CloakWP\JWTAuth\Contracts\AuthenticationHandler as AuthenticationHandlerContract;
use CloakWP\JWTAuth\Exceptions\JWTAuthException;
use WP_User;
use WP_REST_Request;

class AuthenticationHandler implements AuthenticationHandlerContract
{
  public function authenticateUser(WP_REST_Request $request): WP_User
  {
    $username = $request->get_param('username');
    $password = $request->get_param('password');
    $customAuth = $request->get_param('custom_auth');

    if ($customAuth) {
      $user = apply_filters('jwt_auth_do_custom_auth', new \WP_Error(), $username, $password, $customAuth);
    } else {
      $user = wp_authenticate($username, $password);
    }

    if (is_wp_error($user)) {
      throw new JWTAuthException($user->get_error_message(), 401);
    }

    return $user;
  }
}