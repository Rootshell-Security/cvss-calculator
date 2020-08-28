<?php


namespace Rootshell\Cvss\Calculators;


use Rootshell\Cvss\ValueObjects\CvssObject;

interface CvssCalculator
{
    public function calculateBaseScore(CvssObject $cvssObject);
    public function calculateTemporalScore(CvssObject $cvssObject);
    public function calculateEnvironmentalScore(CvssObject $cvssObject);
}