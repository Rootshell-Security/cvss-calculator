<?php


namespace Rootshell\Cvss\Calculators;


use Rootshell\Cvss\Cvss;
use Rootshell\Cvss\ValueObjects\Cvss23Object;
use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss2Calculator implements CvssCalculator
{

    public function calculateBaseScore(CvssObject $cvssObject): float
    {
        if (!$cvssObject instanceof Cvss23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $cvssObject->impact = $this->calculateImpact($cvssObject);

        return round(((0.6 * $cvssObject->impact) + (0.4 * $this->calculateBaseExploitability($cvssObject)) - 1.5) * $this->calculateFImpact($cvssObject), 1);
    }

    private function calculateImpact(Cvss23Object $cvssObject): float
    {
        return 10.41 * (1 - (1 - $cvssObject->confidentiality) * (1 - $cvssObject->integrity) * (1 - $cvssObject->availability));
    }

    private function calculateBaseExploitability(Cvss23Object $cvssObject): float
    {
        return 20 * $cvssObject->accessVector * $cvssObject->accessComplexity * $cvssObject->authentication;
    }

    private function calculateFImpact(Cvss23Object $cvssObject): float
    {
        return $cvssObject->impact === 0.0 ? 0.0 : 1.176;
    }

    public function calculateTemporalScore(CvssObject $cvssObject): float
    {
        if (!$cvssObject instanceof Cvss23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        return round($cvssObject->baseScore * $cvssObject->exploitability * $cvssObject->remediationLevel * $cvssObject->reportConfidence, 1);
    }

    public function calculateEnvironmentalScore(CvssObject $cvssObject): float
    {
        if (!$cvssObject instanceof Cvss23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $adjustedTemporal = $this->calculateAdjustedTemporal($cvssObject);

        return round(($adjustedTemporal + (10 - $adjustedTemporal) * $cvssObject->collateralDamagePotential) * $cvssObject->targetDistribution, 1);
    }

    private function calculateAdjustedTemporal(Cvss23Object $cvssObject): float
    {
        return $this->calculateAdjustedBase($cvssObject) * $cvssObject->exploitability * $cvssObject->remediationLevel * $cvssObject->reportConfidence;
    }

    private function calculateAdjustedBase(Cvss23Object $cvssObject): float
    {
        return round(((0.6 * $this->calculateAdjustedImpact($cvssObject)) + (0.4 * $this->calculateBaseExploitability($cvssObject)) - 1.5) * $this->calculateFImpact($cvssObject), 1);
    }

    private function calculateAdjustedImpact(Cvss23Object $cvssObject): float
    {
        return min(10, 10.41 * (1 - (1 - $cvssObject->confidentiality * $cvssObject->confidentialityRequirement) * (1 - $cvssObject->integrity * $cvssObject->integrityRequirement) * (1 - $cvssObject->availability * $cvssObject->availabilityRequirement)));
    }
}