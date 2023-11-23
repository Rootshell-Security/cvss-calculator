<?php

namespace Rootshell\Cvss\Calculators;

use Rootshell\Cvss\ValueObjects\CvssObject;

interface CvssCalculator
{
    public function calculateBaseScore(CvssObject $cvssObject): float;
    public function calculateTemporalScore(CvssObject $cvssObject): float;
    public function calculateEnvironmentalScore(CvssObject $cvssObject): float;
}