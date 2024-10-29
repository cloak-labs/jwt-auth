<?php

namespace CloakWP\JWTAuth;

use CloakWP\JWTAuth\Contracts\CORSHandler as CORSHandlerContract;

class CORSHandler implements CORSHandlerContract
{
  private $allowedHeaders;

  public function __construct()
  {
    $this->allowedHeaders = apply_filters('jwt_auth_cors_allow_headers', 'Authorization, Content-Type, X-Requested-With, Accept, Origin, Cookie');
  }

  public function addCORSSupport(): void
  {
    global $wp_version;

    if (version_compare($wp_version, '5.5.0', '>=')) {
      add_filter('rest_allowed_cors_headers', [$this, 'addAllowedCorsHeaders']);
    } else {
      add_filter('rest_pre_serve_request', [$this, 'handlePreServeRequest'], 10, 4);
    }
  }

  public function handlePreServeRequest($served, $result, $request, $server): bool
  {
    $origin = get_http_origin();
    if ($origin) {
      header('Access-Control-Allow-Origin: ' . esc_url_raw($origin));
      header('Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE');
      header('Access-Control-Allow-Credentials: true');
      header('Access-Control-Allow-Headers: ' . $this->allowedHeaders);
    }

    if ('OPTIONS' === $request->get_method() && defined('REST_REQUEST') && REST_REQUEST) {
      return true;
    }

    return $served;
  }

  public function addAllowedCorsHeaders(array $headers): array
  {
    $split = preg_split("/[\s,]+/", $this->allowedHeaders);
    return array_unique(array_merge($headers, $split));
  }
}