<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Parsers;

use Rootshell\Cvss\Exceptions\CvssException;
use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss31Parser
{
    private const NETWORK = 'N';
    private const ADJACENT = 'A';
    private const LOCAL = 'L';
    private const PHYSICAL = 'P';

    private const NONE = 'N';
    private const REQUIRED = 'R';

    private const LOW = 'L';
    private const MEDIUM = 'M';
    private const HIGH = 'H';

    private const NOT_DEFINED = 'X';
    private const FUNCTIONAL = 'F';
    private const PROOF_OF_CONCEPT = 'P';
    private const UNPROVEN = 'U';

    private const UNAVAILABLE = 'U';
    private const WORKAROUND = 'W';
    private const TEMPORARY_FIX = 'T';
    private const OFFICIAL_FIX = 'O';

    private const CONFIRMED = 'C';
    private const REASONABLE  = 'R';
    private const UNKNOWN = 'U';

    private const BASE_ATTACK_VECTOR = 'AV';
    private const BASE_ATTACK_COMPLEXITY = 'AC';
    private const BASE_PRIVILEGES_REQUIRED = 'PR';
    private const BASE_USER_INTERACTION = 'UI';
    private const BASE_SCOPE = 'S';
    private const BASE_CONFIDENTIALITY = 'C';
    private const BASE_INTEGRITY = 'I';
    private const BASE_AVAILABILITY = 'A';

    private const TEMPORAL_EXPLOIT_CODE_MATURITY = 'E';
    private const TEMPORAL_REMEDIATION_LEVEL = 'RL';
    private const TEMPORAL_REPORT_CONFIDENCE = 'RC';

    private const ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT = 'CR';
    private const ENVIRONMENTAL_INTEGRITY_REQUIREMENT = 'IR';
    private const ENVIRONMENTAL_AVAILABILITY_REQUIREMENT = 'AR';
    private const ENVIRONMENTAL_MODIFIED_ATTACK_VECTOR = 'MAV';
    private const ENVIRONMENTAL_MODIFIED_ATTACK_COMPLEXITY = 'MAC';
    private const ENVIRONMENTAL_MODIFIED_PRIVILEGES_REQUIRED = 'MPR';
    private const ENVIRONMENTAL_MODIFIED_USER_INTERACTION = 'MUI';
    private const ENVIRONMENTAL_MODIFIED_SCOPE = 'MS';
    private const ENVIRONMENTAL_MODIFIED_CONFIDENTIALITY = 'MC';
    private const ENVIRONMENTAL_MODIFIED_INTEGRITY = 'MI';
    private const ENVIRONMENTAL_MODIFIED_AVAILABILITY = 'MA';

    public function parseVector(string $vector): CvssObject
    {
        $cvssObject = new CvssObject;
        $cvssObject = $this->parseBaseValues($vector, $cvssObject);
        $cvssObject = $this->parseTemporalValues($vector, $cvssObject);
        $cvssObject = $this->parseEnvironmentalValues($vector, $cvssObject);

        return $cvssObject;
    }

    private function parseBaseValues(string $vector, CvssObject $cvssObject): CvssObject
    {
        $cvssObject->modifiedScope = $cvssObject->scope = $this->findValueInVector($vector, self::BASE_SCOPE);
        $cvssObject->modifiedAttackVector = $cvssObject->attackVector = $this->parseAttackVector($this->findValueInVector($vector, self::BASE_ATTACK_VECTOR));
        $cvssObject->modifiedAttackComplexity = $cvssObject->attackComplexity = $this->parseAttackComplexity($this->findValueInVector($vector, self::BASE_ATTACK_COMPLEXITY));
        $cvssObject->modifiedPrivilegesRequired = $cvssObject->privilegesRequired = $this->parsePrivilegesRequired($this->findValueInVector($vector, self::BASE_PRIVILEGES_REQUIRED), $cvssObject->scope);
        $cvssObject->modifiedUserInteraction = $cvssObject->userInteraction = $this->parseUserInteraction($this->findValueInVector($vector, self::BASE_USER_INTERACTION));
        $cvssObject->modifiedConfidentiality = $cvssObject->confidentiality = $this->parseConfidentialityIntegrityOrAvailability($this->findValueInVector($vector, self::BASE_CONFIDENTIALITY));
        $cvssObject->modifiedIntegrity = $cvssObject->integrity = $this->parseConfidentialityIntegrityOrAvailability($this->findValueInVector($vector, self::BASE_INTEGRITY));
        $cvssObject->modifiedAvailability = $cvssObject->availability = $this->parseConfidentialityIntegrityOrAvailability($this->findValueInVector($vector, self::BASE_AVAILABILITY));

        return $cvssObject;
    }

    private function parseTemporalValues(string $vector, CvssObject $cvssObject): CvssObject
    {
        $cvssObject->exploitCodeMaturity = $this->parseExploitCodeMaturity($this->findOptionalValueInVector($vector, self::TEMPORAL_EXPLOIT_CODE_MATURITY));
        $cvssObject->remediationLevel = $this->parseRemediationLevel($this->findOptionalValueInVector($vector, self::TEMPORAL_REMEDIATION_LEVEL));
        $cvssObject->reportConfidence = $this->parseReportConfidence($this->findOptionalValueInVector($vector, self::TEMPORAL_REPORT_CONFIDENCE));

        return $cvssObject;
    }

    private function parseEnvironmentalValues(string $vector, CvssObject $cvssObject): CvssObject
    {
        $modifiedScopeValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_SCOPE);

        if ($modifiedScopeValue && $modifiedScopeValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedScope = $modifiedScopeValue;
        }

        $cvssObject->confidentialityRequirement = $this->parseConfidentialityIntegrityOrAvailabilityRequirements($this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT));
        $cvssObject->integrityRequirement = $this->parseConfidentialityIntegrityOrAvailabilityRequirements($this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_INTEGRITY_REQUIREMENT));
        $cvssObject->availabilityRequirement = $this->parseConfidentialityIntegrityOrAvailabilityRequirements($this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_AVAILABILITY_REQUIREMENT));

        $modifiedAttackVectorValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_ATTACK_VECTOR);
        $modifiedAttackComplexityValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_ATTACK_COMPLEXITY);
        $modifiedPrivilegesRequiredValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_PRIVILEGES_REQUIRED);
        $modifiedUserInteractionValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_USER_INTERACTION);
        $modifiedConfidentialityValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_CONFIDENTIALITY);
        $modifiedIntegrityValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_INTEGRITY);
        $modifiedAvailabilityValue = $this->findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_AVAILABILITY);

        if ($modifiedAttackVectorValue && $modifiedAttackVectorValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedAttackVector = $this->parseAttackVector($modifiedAttackVectorValue);
        }

        if ($modifiedAttackComplexityValue && $modifiedAttackComplexityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedAttackComplexity = $this->parseAttackComplexity($modifiedAttackComplexityValue);
        }

        if ($modifiedPrivilegesRequiredValue && $modifiedPrivilegesRequiredValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedPrivilegesRequired = $this->parsePrivilegesRequired($modifiedPrivilegesRequiredValue, $cvssObject->modifiedScope);
        }

        if ($modifiedUserInteractionValue && $modifiedUserInteractionValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedUserInteraction = $this->parseUserInteraction($modifiedUserInteractionValue);
        }

        if ($modifiedConfidentialityValue && $modifiedConfidentialityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedConfidentiality = $this->parseConfidentialityIntegrityOrAvailability($modifiedConfidentialityValue);
        }

        if ($modifiedIntegrityValue && $modifiedIntegrityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedIntegrity = $this->parseConfidentialityIntegrityOrAvailability($modifiedIntegrityValue);
        }

        if ($modifiedAvailabilityValue && $modifiedAvailabilityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedAvailability = $this->parseConfidentialityIntegrityOrAvailability($modifiedAvailabilityValue);
        }

        return $cvssObject;
    }

    private function findValueInVector(string $vector, string $section): string
    {
        $regex = '/(?<=\/' . $section . ':)(.)/';
        preg_match($regex, $vector, $matches);

        if (!isset($matches[0])) {
            throw CvssException::missingValue();
        }

        return $matches[0];
    }

    private function findOptionalValueInVector(string $vector, string $section): ?string
    {
        $regex = '/(?<=\/' . $section . ':)(.)/';
        preg_match($regex, $vector, $matches);

        return $matches[0] ?? null;
    }

    private function parseAttackVector(string $value): float
    {
        switch ($value) {
            case self::NETWORK:
                return 0.85;

            case self::ADJACENT:
                return 0.62;

            case self::LOCAL:
                return 0.55;

            case self::PHYSICAL:
                return 0.2;
        }

        throw CvssException::invalidValue();
    }

    private function parseAttackComplexity(string $value): float
    {
        switch ($value) {
            case self::LOW:
                return 0.77;

            case self::HIGH:
                return 0.44;
        }

        throw CvssException::invalidValue();
    }

    private function parsePrivilegesRequired(string $value, string $scope): float
    {
        switch ($value) {
            case self::NONE:
                return 0.85;

            case self::LOW:
                return $scope === CvssObject::SCOPE_UNCHANGED ? 0.62 : 0.68;

            case self::HIGH:
                return $scope === CvssObject::SCOPE_UNCHANGED ? 0.27 : 0.5;
        }

        throw CvssException::invalidValue();
    }

    private function parseUserInteraction(string $value): float
    {
        switch ($value) {
            case self::NONE:
                return 0.85;

            case self::REQUIRED:
                return 0.62;
        }

        throw CvssException::invalidValue();
    }

    private function parseConfidentialityIntegrityOrAvailability(string $value): float
    {
        switch ($value) {
            case self::HIGH:
                return 0.56;

            case self::LOW:
                return 0.22;

            case self::NONE:
                return 0;
        }

        throw CvssException::invalidValue();
    }

    private function parseExploitCodeMaturity(?string $value): float
    {
        switch ($value) {
            case self::FUNCTIONAL:
                return 0.97;

            case self::PROOF_OF_CONCEPT:
                return 0.94;

            case self::UNPROVEN:
                return 0.91;

            default:
                return 1;
        }
    }

    private function parseRemediationLevel(?string $value): float
    {
        switch ($value) {
            case self::WORKAROUND:
                return 0.97;

            case self::TEMPORARY_FIX:
                return 0.96;

            case self::OFFICIAL_FIX:
                return 0.95;

            default:
                return 1;
        }
    }

    private function parseReportConfidence(?string $value): float
    {
        switch ($value) {
            case self::REASONABLE:
                return 0.96;

            case self::UNKNOWN:
                return 0.92;

            default:
                return 1;
        }
    }

    private function parseConfidentialityIntegrityOrAvailabilityRequirements(?string $value): float
    {
        switch ($value) {
            case self::HIGH:
                return 1.5;

            case self::LOW:
                return 0.5;

            default:
                return 1;
        }
    }
}
