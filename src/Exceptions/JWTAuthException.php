<?php

namespace CloakWP\JWTAuth\Exceptions;

use Exception;

class JWTAuthException extends Exception
{
  private string $errorCode;

  public function __construct(string $message, int $code = 0, string $errorCode = '')
  {
    parent::__construct($message, $code);
    $this->errorCode = $errorCode ?: 'jwt_auth_' . strtolower(str_replace(' ', '_', $message));
  }

  public function getErrorCode(): string
  {
    return $this->errorCode;
  }
}