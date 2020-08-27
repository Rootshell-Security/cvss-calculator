<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Calculators;

use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss31Calculator extends AbstractCvss3Calculator
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

        return 7.52 * ($cvssObject->modifiedImpactSubScore - 0.029) - 3.25 * (($cvssObject->modifiedImpactSubScore * 0.9731 - 0.02) ** 13);
    }

    public function roundUp(float $number): float
    {
        $intInput = round($number * 100000);
        return $intInput % 10000 === 0 ? $intInput / 100000.0 : (floor($intInput / 10000) + 1) / 10.0;
    }
}
