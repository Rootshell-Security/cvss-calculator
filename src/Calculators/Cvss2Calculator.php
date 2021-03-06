<?php


namespace Rootshell\Cvss\Calculators;


use Rootshell\Cvss\Cvss;
use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss2Calculator implements CvssCalculator
{

    public function calculateBaseScore(CvssObject $cvssObject): float
    {
        $cvssObject->impact = $this->calculateImpact($cvssObject);

        return round(((0.6 * $cvssObject->impact) + (0.4 * $this->calculateBaseExploitability($cvssObject)) - 1.5) * $this->calculateFImpact($cvssObject), 1);
    }

    public function calculateImpact(CvssObject $cvssObject): float
    {
        return 10.41 * (1 - (1 - $cvssObject->confidentiality) * (1 - $cvssObject->integrity) * (1 - $cvssObject->availability));
    }

    public function calculateBaseExploitability(CvssObject $cvssObject): float
    {
        return 20 * $cvssObject->accessVector * $cvssObject->accessComplexity * $cvssObject->authentication;
    }

    public function calculateFImpact(CvssObject $cvssObject): float
    {
        return $cvssObject->impact === 0 ?: 1.176;
    }

    public function calculateTemporalScore(CvssObject $cvssObject): float
    {
        return round($cvssObject->baseScore * $cvssObject->exploitability * $cvssObject->remediationLevel * $cvssObject->reportConfidence, 1);
    }

    public function calculateEnvironmentalScore(CvssObject $cvssObject): float
    {
        $adjustedTemporal = $this->calculateAdjustedTemporal($cvssObject);

        return round(($adjustedTemporal + (10 - $adjustedTemporal) * $cvssObject->collateralDamagePotential) * $cvssObject->targetDistribution, 1);
    }

    public function calculateAdjustedTemporal(CvssObject $cvssObject): float
    {
        return $this->calculateAdjustedBase($cvssObject) * $cvssObject->exploitability * $cvssObject->remediationLevel * $cvssObject->reportConfidence;
    }

    public function calculateAdjustedBase(CvssObject $cvssObject): float
    {
        return round(((0.6 * $this->calculateAdjustedImpact($cvssObject)) + (0.4 * $this->calculateBaseExploitability($cvssObject)) - 1.5) * $this->calculateFImpact($cvssObject), 1);
    }

    public function calculateAdjustedImpact(CvssObject $cvssObject): float
    {
        return min(10, 10.41 * (1 - (1 - $cvssObject->confidentiality * $cvssObject->confidentialityRequirement) * (1 - $cvssObject->integrity * $cvssObject->integrityRequirement) * (1 - $cvssObject->availability * $cvssObject->availabilityRequirement)));
    }
}