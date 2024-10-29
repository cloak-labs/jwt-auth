<?php
/**
 * Setup JWT-Auth.
 *
 * @package jwt-auth
 */

namespace CloakWP\JWTAuth;

use CloakWP\JWTAuth\Contracts\TokenGenerator as TokenGeneratorContract;
use CloakWP\JWTAuth\Contracts\TokenValidator as TokenValidatorContract;
use CloakWP\JWTAuth\Contracts\RefreshTokenManager as RefreshTokenManagerContract;
use CloakWP\JWTAuth\Contracts\AuthenticationHandler as AuthenticationHandlerContract;
use CloakWP\JWTAuth\Contracts\CORSHandler as CORSHandlerContract;
use CloakWP\JWTAuth\Config\JWTAuthConfig;
use CloakWP\JWTAuth\Exceptions\JWTAuthException;
use WP_REST_Request;
use WP_REST_Response;
use WP_User;


class JWTAuth
{
  private bool $isInitialized = false;

  public function __construct(
    private TokenGeneratorContract $tokenGenerator,
    private TokenValidatorContract $tokenValidator,
    private RefreshTokenManagerContract $refreshTokenManager,
    private AuthenticationHandlerContract $authenticationHandler,
    private CORSHandlerContract $corsHandler,
    private JWTAuthConfig $config,
  ) {
  }

  public static function fromDefaults(JWTAuthConfig|null $config = null): self
  {
    if (!$config)
      $config = JWTAuthConfig::fromDefaults();

    return new self(
      new TokenGenerator($config),
      new TokenValidator($config),
      new RefreshTokenManager($config),
      new AuthenticationHandler(),
      new CORSHandler(),
      $config,
    );
  }

  public function init(): void
  {
    if ($this->isInitialized) {
      return;
    }

    add_action('rest_api_init', [$this, 'registerRestRoutes']);
    add_filter('determine_current_user', [$this, 'determineCurrentUser'], 10);
    if ($this->config->enableCors) {
      $this->corsHandler->addCORSSupport();
    }

    $this->isInitialized = true;
  }

  public function isInitialized(): bool
  {
    return $this->isInitialized;
  }

  public function registerRestRoutes(string $namespace = 'jwt-auth/v1'): void
  {
    register_rest_route(
      $namespace,
      'token',
      [
        'methods' => 'POST',
        'callback' => [$this, 'getToken'],
        'permission_callback' => '__return_true',
      ]
    );

    register_rest_route(
      $namespace,
      'token/validate',
      [
        'methods' => 'POST',
        'callback' => [$this, 'validateToken'],
        'permission_callback' => '__return_true',
      ]
    );

    register_rest_route(
      $namespace,
      'token/refresh',
      [
        'methods' => 'POST',
        'callback' => [$this, 'refreshToken'],
        'permission_callback' => '__return_true',
      ]
    );
  }

  public function getToken(WP_REST_Request $request): WP_REST_Response
  {
    try {
      $this->validateConfig();
      $user = $this->authenticationHandler->authenticateUser($request);
      $token = $this->tokenGenerator->generateToken($user);
      $this->refreshTokenManager->sendRefreshToken($user, $request);
      return $this->createSuccessResponse($token, $user);
    } catch (JWTAuthException $e) {
      return $this->createErrorResponse($e);
    }
  }

  public function validateToken(WP_REST_Request $request): WP_REST_Response
  {
    try {
      $token = $this->getTokenFromRequest($request);
      $user = $this->tokenValidator->validateToken($token);
      return $this->createSuccessResponse('Token is valid', $user);
    } catch (JWTAuthException $e) {
      return $this->createErrorResponse($e);
    }
  }

  public function refreshToken(WP_REST_Request $request): WP_REST_Response
  {
    try {
      $refreshToken = $this->getRefreshTokenFromCookie();
      $user = $this->refreshTokenManager->validateRefreshToken($refreshToken);
      $newToken = $this->tokenGenerator->generateToken($user);
      $this->refreshTokenManager->sendRefreshToken($user, $request);
      return $this->createSuccessResponse($newToken, $user);
    } catch (JWTAuthException $e) {
      return $this->createErrorResponse($e);
    }
  }

  public function determineCurrentUser($user_id)
  {
    if ($this->shouldSkipAuthentication($user_id)) {
      return $user_id;
    }

    try {
      $token = $this->getTokenFromRequest(null);
      $user = $this->tokenValidator->validateToken($token);
      return $user->ID;
    } catch (JWTAuthException $e) {
      return $user_id;
    }
  }

  private function validateConfig(): void
  {
    if (!$this->config->secretKey) {
      throw new JWTAuthException('JWT is not configured properly.', 500);
    }
  }

  private function createSuccessResponse($data, WP_User $user): WP_REST_Response
  {
    $response = [
      'success' => true,
      'statusCode' => 200,
      'code' => 'jwt_auth_valid_credential',
      'message' => __('Credential is valid', 'jwt-auth'),
      'data' => [
        'token' => $data,
        'id' => $user->ID,
        'email' => $user->user_email,
        'nicename' => $user->user_nicename,
        'firstName' => $user->first_name,
        'lastName' => $user->last_name,
        'displayName' => $user->display_name,
      ],
    ];

    return new WP_REST_Response($response);
  }

  private function createErrorResponse(JWTAuthException $e): WP_REST_Response
  {
    return new WP_REST_Response(
      [
        'success' => false,
        'statusCode' => $e->getCode(),
        'code' => $e->getErrorCode(),
        'message' => $e->getMessage(),
        'data' => [],
      ],
      $e->getCode()
    );
  }

  private function getTokenFromRequest(?WP_REST_Request $request): string
  {
    $headerKey = apply_filters('jwt_auth_authorization_header', 'HTTP_AUTHORIZATION');
    $auth = $request ? $request->get_header($headerKey) : null;

    if (!$auth) {
      // Check $_SERVER for the authorization header
      $auth = isset($_SERVER[$headerKey]) ? sanitize_text_field(wp_unslash($_SERVER[$headerKey])) : null;

      // Double check for different auth header string (server dependent)
      if (!$auth) {
        $auth = isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION']) ? sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) : null;
      }
    }

    if (!$auth) {
      throw new JWTAuthException('Authorization header not found.', 401);
    }

    if (!preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
      throw new JWTAuthException('Invalid authorization header format.', 401);
    }

    return $matches[1];
  }

  private function getRefreshTokenFromCookie(): string
  {
    $refreshToken = $_COOKIE['refresh_token'] ?? null;

    if (!$refreshToken) {
      throw new JWTAuthException('Refresh token not found.', 401);
    }

    return $refreshToken;
  }

  private function shouldSkipAuthentication($user_id): bool
  {
    $restPrefix = get_option('permalink_structure') ? rest_get_url_prefix() : '?rest_route=/';
    $requestUri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']));
    $isRestRequest = strpos($requestUri, $restPrefix) !== false;

    return !$isRestRequest || $user_id || $this->isTokenValidationRequest();
  }

  private function isTokenValidationRequest(): bool
  {
    $request_uri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI']));
    return strpos($request_uri, 'token/validate') !== false;
  }
}