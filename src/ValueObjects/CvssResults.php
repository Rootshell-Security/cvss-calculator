<?php

namespace Rootshell\Cvss\ValueObjects;

class CvssResults
{
    public float $baseScore;

    public float $temporalScore;

    public float $environmentalScore;

    public function __construct(float $baseScore, float $temporalScore, float $environmentalScore) {
        $this->baseScore = $baseScore;
        $this->temporalScore = $temporalScore;
        $this->environmentalScore = $environmentalScore;
    }
}