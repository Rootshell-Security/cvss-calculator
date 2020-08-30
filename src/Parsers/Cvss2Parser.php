<?php


namespace Rootshell\Cvss\Parsers;


use Rootshell\Cvss\Exceptions\CvssException;
use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss2Parser
{
    private const NETWORK = 'N';
    private const ADJACENT = 'A';
    private const LOCAL = 'L';

    private const LOW = 'L';
    private const MEDIUM = 'M';
    private const HIGH = 'H';

    private const MULTIPLE = 'M';
    private const SINGLE = 'S';
    private const NONE = 'N';

    private const PARTIAL = 'P';
    private const COMPLETE = 'C';

    private const UNPROVEN = 'U';
    private const PROOF_OF_CONCEPT = 'POC';
    private const FUNCTIONAL = 'F';
    private const NOT_DEFINED = 'ND';

    private const OFFICIAL_FIX = 'OF';
    private const TEMPORARY_FIX = 'TF';
    private const WORKAROUND = 'W';
    private const UNAVAILABLE = 'U';

    private const UNCONFIRMED = 'UC';
    private const UNCORROBORATED = 'UR';
    private const CONFIRMED = 'C';

    private const LOW_MEDIUM = 'LM';
    private const MEDIUM_HIGH = 'MH';

    private const BASE_ACCESS_VECTOR = 'AV';
    private const BASE_ATTACK_COMPLEXITY = 'AC';
    private const BASE_AUTHENTICATION = 'Au';
    private const BASE_CONFIDENTIALITY = 'C';
    private const BASE_INTEGRITY = 'I';
    private const BASE_AVAILABILITY = 'A';

    private const TEMPORAL_EXPLOITABILITY = 'E';
    private const TEMPORAL_REMEDIATION_LEVEL = 'RL';
    private const TEMPORAL_REPORT_CONFIDENCE = 'RC';

    private const ENVIRONMENTAL_COLLATERAL_DAMAGE_POTENTIAL  = 'CDP';
    private const ENVIRONMENTAL_TARGET_DISTRIBUTION = 'TD';
    private const ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT = 'CR';
    private const ENVIRONMENTAL_INTEGRITY_REQUIREMENT = 'IR';
    private const ENVIRONMENTAL_AVAILABILITY_REQUIREMENT = 'AR';


    public static function parseVector(string $vector): CvssObject
    {
        $cvssObject = new CvssObject;
        $cvssObject = self::parseBaseValues($vector, $cvssObject);
        $cvssObject = self::parseTemporalValues($vector, $cvssObject);
        $cvssObject = self::parseEnvironmentalValues($vector, $cvssObject);

        return $cvssObject;
    }

    private static function parseBaseValues(string $vector, CvssObject $cvssObject): CvssObject
    {
        $cvssObject->accessVector = self::parseAccessVector(self::findValueInVector($vector, self::BASE_ACCESS_VECTOR));
        $cvssObject->accessComplexity = self::parseAccessComplexity(self::findValueInVector($vector, self::BASE_ATTACK_COMPLEXITY));
        $cvssObject->authentication = self::parseAuthentication(self::findValueInVector($vector, self::BASE_AUTHENTICATION));
        $cvssObject->confidentiality = self::parseConfidentialityIntegrityAvailabilityImpact(self::findValueInVector($vector, self::BASE_CONFIDENTIALITY));
        $cvssObject->integrity = self::parseConfidentialityIntegrityAvailabilityImpact(self::findValueInVector($vector, self::BASE_INTEGRITY));
        $cvssObject->availability = self::parseConfidentialityIntegrityAvailabilityImpact(self::findValueInVector($vector, self::BASE_AVAILABILITY));
        return $cvssObject;
    }

    private static function parseTemporalValues(string $vector, CvssObject $cvssObject): CvssObject
    {
        $cvssObject->exploitability = self::parseExploitability(self::findOptionalValueInVector($vector, self::TEMPORAL_EXPLOITABILITY));
        $cvssObject->remediationLevel = self::parseRemediationLevel(self::findOptionalValueInVector($vector, self::TEMPORAL_REMEDIATION_LEVEL));
        $cvssObject->reportConfidence = self::parseReportConfidence(self::findOptionalValueInVector($vector, self::TEMPORAL_REPORT_CONFIDENCE));

        return $cvssObject;
    }

    private static function parseEnvironmentalValues(string $vector, CvssObject $cvssObject): CvssObject
    {
        $cvssObject->collateralDamagePotential = self::parseCollateralDamagePotential(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_COLLATERAL_DAMAGE_POTENTIAL));
        $cvssObject->targetDistribution = self::parseTargetDistribution(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_TARGET_DISTRIBUTION));
        $cvssObject->confidentialityRequirement = self::parseSecurityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT));
        $cvssObject->integrityRequirement = self::parseSecurityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_INTEGRITY_REQUIREMENT));
        $cvssObject->availabilityRequirement = self::parseSecurityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_AVAILABILITY_REQUIREMENT));

        return $cvssObject;
    }


    private static function findValueInVector(string $vector, string $section): string
    {
        $regex = '/(?<=\/' . $section . ':)(.*?)(?=\/|$)/';
        preg_match($regex, '/' . $vector, $matches);

        if (!isset($matches[0])) {
            throw CvssException::missingValue();
        }

        return $matches[0];
    }

    private static function findOptionalValueInVector(string $vector, string $section): ?string
    {
        $regex = '/(?<=\/' . $section . ':)(.*?)(?=\/|$)/';
        preg_match($regex, '/' . $vector, $matches);

        return $matches[0] ?? null;
    }

    public static function parseAccessVector(string $value): float
    {
        switch ($value) {
            case self::NETWORK:
                return 1;

            case self::ADJACENT:
                return 0.646;

            case self::LOCAL:
                return 0.395;
        }

        throw CvssException::invalidValue();
    }

    public static function parseAccessComplexity(string $value): float
    {
        switch ($value) {
            case self::HIGH:
                return 0.35;

            case self::MEDIUM:
                return 0.61;

            case self::LOW:
                return 0.71;
        }

        throw CvssException::invalidValue();
    }

    public static function parseAuthentication(string $value): float
    {
        switch ($value) {
            case self::MULTIPLE:
                return 0.45;

            case self::SINGLE:
                return 0.56;

            case self::NONE:
                return 0.704;
        }

        throw CvssException::invalidValue();
    }

    public static function parseConfidentialityIntegrityAvailabilityImpact(string $value): float
    {
        switch ($value) {
            case self::COMPLETE:
                return 0.660;

            case self::PARTIAL:
                return 0.275;

            case self::NONE:
                return 0.0;
        }

        throw CvssException::invalidValue();
    }

    public static function parseExploitability(?string $value): float
    {
        switch ($value) {
            case self::UNPROVEN:
                return 0.85;

            case self::PROOF_OF_CONCEPT:
                return 0.9;

            case self::FUNCTIONAL:
                return 0.95;

            default:
                return 1.0;
        }
    }

    public static function parseRemediationLevel(?string $value): float
    {
        switch ($value) {
            case self::OFFICIAL_FIX:
                return 0.87;

            case self::TEMPORARY_FIX:
                return 0.90;

            case self::WORKAROUND:
                return 0.95;

            default:
                return 1.0;
        }
    }

    public static function parseReportConfidence(?string $value): float
    {
        switch ($value) {
            case self::UNCONFIRMED:
                return 0.90;

            case self::UNCORROBORATED:
                return 0.95;

            default:
                return 1.0;
        }
    }

    public static function parseCollateralDamagePotential(?string $value): float
    {
        switch ($value) {
            case self::LOW:
                return 0.1;

            case self::LOW_MEDIUM:
                return 0.3;

            case self::MEDIUM_HIGH:
                return 0.4;

            case self::HIGH:
                return 0.5;

            default:
                return 0;
        }
    }

    public static function parseTargetDistribution(?string $value): float
    {
        switch ($value) {
            case self::NONE:
                return 0;

            case self::LOW:
                return 0.25;

            case self::MEDIUM:
                return 0.75;

            default:
                return 1.0;
        }
    }

    public static function parseSecurityRequirements(?string $value): float
    {
        switch ($value) {
            case self::LOW:
                return 0.5;

            case self::HIGH:
                return 1.51;

            default:
                return 1.0;
        }
    }

}