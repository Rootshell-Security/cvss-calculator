<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Calculators;

use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss30Calculator extends AbstractCvss3Calculator
{
    public function calculateModifiedImpactSubScore(CvssObject $cvssObject): float
    {
        return min(
            1 - ((1 - $cvssObject->confidentialityRequirement * $cvssObject->modifiedConfidentiality) *
                (1 - $cvssObject->integrityRequirement * $cvssObject->modifiedIntegrity) *
                (1 - $cvssObject->availabilityRequirement * $cvssObject->modifiedAvailability)),
            0.915
        );
    }

    public function calculateModifiedImpact(CvssObject $cvssObject): float
    {
        if ($cvssObject->modifiedScope === CvssObject::SCOPE_UNCHANGED) {
            return 6.42 * $cvssObject->modifiedImpactSubScore;
        }

        return 7.52 * ($cvssObject->modifiedImpactSubScore - 0.029) - 3.25 * (($cvssObject->modifiedImpactSubScore - 0.02) ** 15);
    }

    public function roundUp(float $number): float
    {
        return round(ceil($number * 10) / 10, 1);
    }
}
