<?php

namespace Rootshell\Cvss\ValueObjects;

final class CvssResults
{
    public function __construct(
        public float $baseScore,
        public float $temporalScore,
        public float $environmentalScore
    ) {
    }
}
