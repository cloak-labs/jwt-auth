<?php

namespace CloakWP\JWTAuth\Contracts;

interface CORSHandler
{
  public function addCORSSupport(): void;
}