<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Calculators;

use http\Exception\RuntimeException;
use Rootshell\Cvss\ValueObjects\Cvss23Object;
use Rootshell\Cvss\ValueObjects\CvssObject;

final class Cvss30Calculator extends AbstractCvss3Calculator
{
    #[\Override]
    public function calculateModifiedImpactSubScore(CvssObject $cvssObject): float
    {
        if (!$cvssObject instanceof Cvss23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        return min(
            1 - ((1 - $cvssObject->confidentialityRequirement * $cvssObject->modifiedConfidentiality) *
                (1 - $cvssObject->integrityRequirement * $cvssObject->modifiedIntegrity) *
                (1 - $cvssObject->availabilityRequirement * $cvssObject->modifiedAvailability)),
            0.915
        );
    }

    #[\Override]
    public function calculateModifiedImpact(CvssObject $cvssObject): float
    {
        if (!$cvssObject instanceof Cvss23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        if ($cvssObject->modifiedScope === Cvss23Object::SCOPE_UNCHANGED) {
            return 6.42 * $cvssObject->modifiedImpactSubScore;
        }

        return 7.52 * ($cvssObject->modifiedImpactSubScore - 0.029) - 3.25 * (($cvssObject->modifiedImpactSubScore - 0.02) ** 15);
    }

    #[\Override]
    public function roundUp(float $number): float
    {
        return round(ceil($number * 10) / 10, 1);
    }
}
