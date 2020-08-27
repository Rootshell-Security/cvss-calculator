<?php

declare(strict_types=1);

namespace Rootshell\Cvss\ValueObjects;

class CvssObject
{
    public const VERSION_31 = '3.1';
    public const VERSION_30 = '3.0';
    public const SCOPE_UNCHANGED = 'U';
    public const SCOPE_CHANGED = 'C';

    public string $version;

    public string $scope;

    public string $modifiedScope;

    public float $attackVector;

    public float $accessVector;

    public float $authentication;

    public float $attackComplexity;

    public float $privilegesRequired;

    public float $userInteraction;

    public float $confidentiality;

    public float $integrity;

    public float $availability;

    public float $impact;

    public float $exploitability;

    public float $impactSubScore;

    public float $baseScore;

    public float $exploitCodeMaturity;

    public float $remediationLevel;

    public float $reportConfidence;

    public float $temporalScore;

    public float $confidentialityRequirement;

    public float $integrityRequirement;

    public float $availabilityRequirement;

    public float $modifiedAttackVector;

    public float $modifiedAttackComplexity;

    public float $modifiedPrivilegesRequired;

    public float $modifiedUserInteraction;

    public float $modifiedConfidentiality;

    public float $modifiedIntegrity;

    public float $modifiedAvailability;

    public float $modifiedImpactSubScore;

    public float $modifiedImpact;

    public float $modifiedExploitability;

    public float $collateralDamagePotential;

    public float $targetDistribution;

    public float $environmentalScore;

    public function getResults(): CvssResults
    {
        return new CvssResults($this->baseScore, $this->temporalScore, $this->environmentalScore);
    }
}
