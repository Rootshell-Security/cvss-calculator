<?php

namespace Rootshell\Cvss\Calculators;

use http\Exception\RuntimeException;
use LanguageServerProtocol\PackageDescriptor;
use Rootshell\Cvss\Parsers\Cvss40Parser;
use Rootshell\Cvss\ValueObjects\Cvss4Distance;
use Rootshell\Cvss\ValueObjects\Cvss4Object;
use Rootshell\Cvss\ValueObjects\CvssObject;

class Cvss40Calculator implements CvssCalculator
{
    private array $vectorLookup = [
        '000000' => 10.0,
        '000001' => 9.9,
        '000010' => 9.8,
        '000011' => 9.5,
        '000020' => 9.5,
        '000021' => 9.2,
        '000100' => 10.0,
        '000101' => 9.6,
        '000110' => 9.3,
        '000111' => 8.7,
        '000120' => 9.1,
        '000121' => 8.1,
        '000200' => 9.3,
        '000201' => 9.0,
        '000210' => 8.9,
        '000211' => 8,
        '000220' => 8.1,
        '000221' => 6.8,
        '001000' => 9.8,
        '001001' => 9.5,
        '001010' => 9.5,
        '001011' => 9.2,
        '001020' => 9.0,
        '001021' => 8.4,
        '001100' => 9.3,
        '001101' => 9.2,
        '001110' => 8.9,
        '001111' => 8.1,
        '001120' => 8.1,
        '001121' => 6.5,
        '001200' => 8.8,
        '001201' => 8.0,
        '001210' => 7.8,
        '001211' => 7.0,
        '001220' => 6.9,
        '001221' => 4.8,
        '002001' => 9.2,
        '002011' => 8.2,
        '002021' => 7.2,
        '002101' => 7.9,
        '002111' => 6.9,
        '002121' => 5.0,
        '002201' => 6.9,
        '002211' => 5.5,
        '002221' => 2.7,
        '010000' => 9.9,
        '010001' => 9.7,
        '010010' => 9.5,
        '010011' => 9.2,
        '010020' => 9.2,
        '010021' => 8.5,
        '010100' => 9.5,
        '010101' => 9.1,
        '010110' => 9.0,
        '010111' => 8.3,
        '010120' => 8.4,
        '010121' => 7.1,
        '010200' => 9.2,
        '010201' => 8.1,
        '010210' => 8.2,
        '010211' => 7.1,
        '010220' => 7.2,
        '010221' => 5.3,
        '011000' => 9.5,
        '011001' => 9.3,
        '011010' => 9.2,
        '011011' => 8.5,
        '011020' => 8.5,
        '011021' => 7.3,
        '011100' => 9.2,
        '011101' => 8.2,
        '011110' => 8.0,
        '011111' => 7.2,
        '011120' => 7.0,
        '011121' => 5.9,
        '011200' => 8.4,
        '011201' => 7.0,
        '011210' => 7.1,
        '011211' => 5.2,
        '011220' => 5.0,
        '011221' => 3.0,
        '012001' => 8.6,
        '012011' => 7.5,
        '012021' => 5.2,
        '012101' => 7.1,
        '012111' => 5.2,
        '012121' => 2.9,
        '012201' => 6.3,
        '012211' => 2.9,
        '012221' => 1.7,
        '100000' => 9.8,
        '100001' => 9.5,
        '100010' => 9.4,
        '100011' => 8.7,
        '100020' => 9.1,
        '100021' => 8.1,
        '100100' => 9.4,
        '100101' => 8.9,
        '100110' => 8.6,
        '100111' => 7.4,
        '100120' => 7.7,
        '100121' => 6.4,
        '100200' => 8.7,
        '100201' => 7.5,
        '100210' => 7.4,
        '100211' => 6.3,
        '100220' => 6.3,
        '100221' => 4.9,
        '101000' => 9.4,
        '101001' => 8.9,
        '101010' => 8.8,
        '101011' => 7.7,
        '101020' => 7.6,
        '101021' => 6.7,
        '101100' => 8.6,
        '101101' => 7.6,
        '101110' => 7.4,
        '101111' => 5.8,
        '101120' => 5.9,
        '101121' => 5.0,
        '101200' => 7.2,
        '101201' => 5.7,
        '101210' => 5.7,
        '101211' => 5.2,
        '101220' => 5.2,
        '101221' => 2.5,
        '102001' => 8.3,
        '102011' => 7.0,
        '102021' => 5.4,
        '102101' => 6.5,
        '102111' => 5.8,
        '102121' => 2.6,
        '102201' => 5.3,
        '102211' => 2.1,
        '102221' => 1.3,
        '110000' => 9.5,
        '110001' => 9.0,
        '110010' => 8.8,
        '110011' => 7.6,
        '110020' => 7.6,
        '110021' => 7.0,
        '110100' => 9.0,
        '110101' => 7.7,
        '110110' => 7.5,
        '110111' => 6.2,
        '110120' => 6.1,
        '110121' => 5.3,
        '110200' => 7.7,
        '110201' => 6.6,
        '110210' => 6.8,
        '110211' => 5.9,
        '110220' => 5.2,
        '110221' => 3.0,
        '111000' => 8.9,
        '111001' => 7.8,
        '111010' => 7.6,
        '111011' => 6.7,
        '111020' => 6.2,
        '111021' => 5.8,
        '111100' => 7.4,
        '111101' => 5.9,
        '111110' => 5.7,
        '111111' => 5.7,
        '111120' => 4.7,
        '111121' => 2.3,
        '111200' => 6.1,
        '111201' => 5.2,
        '111210' => 5.7,
        '111211' => 2.9,
        '111220' => 2.4,
        '111221' => 1.6,
        '112001' => 7.1,
        '112011' => 5.9,
        '112021' => 3.0,
        '112101' => 5.8,
        '112111' => 2.6,
        '112121' => 1.5,
        '112201' => 2.3,
        '112211' => 1.3,
        '112221' => 0.6,
        '200000' => 9.3,
        '200001' => 8.7,
        '200010' => 8.6,
        '200011' => 7.2,
        '200020' => 7.5,
        '200021' => 5.8,
        '200100' => 8.6,
        '200101' => 7.4,
        '200110' => 7.4,
        '200111' => 6.1,
        '200120' => 5.6,
        '200121' => 3.4,
        '200200' => 7.0,
        '200201' => 5.4,
        '200210' => 5.2,
        '200211' => 4.0,
        '200220' => 4.0,
        '200221' => 2.2,
        '201000' => 8.5,
        '201001' => 7.5,
        '201010' => 7.4,
        '201011' => 5.5,
        '201020' => 6.2,
        '201021' => 5.1,
        '201100' => 7.2,
        '201101' => 5.7,
        '201110' => 5.5,
        '201111' => 4.1,
        '201120' => 4.6,
        '201121' => 1.9,
        '201200' => 5.3,
        '201201' => 3.6,
        '201210' => 3.4,
        '201211' => 1.9,
        '201220' => 1.9,
        '201221' => 0.8,
        '202001' => 6.4,
        '202011' => 5.1,
        '202021' => 2.0,
        '202101' => 4.7,
        '202111' => 2.1,
        '202121' => 1.1,
        '202201' => 2.4,
        '202211' => 0.9,
        '202221' => 0.4,
        '210000' => 8.8,
        '210001' => 7.5,
        '210010' => 7.3,
        '210011' => 5.3,
        '210020' => 6.0,
        '210021' => 5.0,
        '210100' => 7.3,
        '210101' => 5.5,
        '210110' => 5.9,
        '210111' => 4.0,
        '210120' => 4.1,
        '210121' => 2.0,
        '210200' => 5.4,
        '210201' => 4.3,
        '210210' => 4.5,
        '210211' => 2.2,
        '210220' => 2.0,
        '210221' => 1.1,
        '211000' => 7.5,
        '211001' => 5.5,
        '211010' => 5.8,
        '211011' => 4.5,
        '211020' => 4.0,
        '211021' => 2.1,
        '211100' => 6.1,
        '211101' => 5.1,
        '211110' => 4.8,
        '211111' => 1.8,
        '211120' => 2.0,
        '211121' => 0.9,
        '211200' => 4.6,
        '211201' => 1.8,
        '211210' => 1.7,
        '211211' => 0.7,
        '211220' => 0.8,
        '211221' => 0.2,
        '212001' => 5.3,
        '212011' => 2.4,
        '212021' => 1.4,
        '212101' => 2.4,
        '212111' => 1.2,
        '212121' => 0.5,
        '212201' => 1.0,
        '212211' => 0.3,
        '212221' => 0.1,
    ];

    private array $maxComposed = [
        1 => [
            '0' => ['AV:N/PR:N/UI:N/'],
            '1' => ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
            '2' => ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']
        ],
        2 => [
            '0' => ['AC:L/AT:N/'],
            '1' => ['AC:H/AT:N/', 'AC:L/AT:P/']
        ],
        3 => [
            '0' => ['0' => ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'], '1' => ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']],
            '1' => ['0' => ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'], '1' => ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/']],
            '2' => ['1' => ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']],
        ],
        4 => [
            '0' => ['SC:H/SI:S/SA:S/'],
            '1' => ['SC:H/SI:H/SA:H/'],
            '2' => ['SC:L/SI:L/SA:L/']
        ],
        5 => [
            '0' => ['E:A/'],
            '1' => ['E:P/'],
            '2' => ['E:U/'],
        ],
    ];

    private array $maxSeverity = [
        1 => [
            '0' => 1,
            '1' => 4,
            '2' => 5,
        ],
        2 => [
            '0' => 1,
            '1' => 2
        ],
        3 => [
            '0' => ['0' => 7, '1' => 6],
            '1' => ['0' => 8, '1' => 8],
            '2' => ['1' => 10],
        ],
        4 => [
            '0' => 6,
            '1' => 5,
            '2' => 4,
        ],
        5 => [
            '0' => 1,
            '1' => 1,
            '2' => 1,
        ],
    ];

    public function calculateBaseScore(CvssObject $cvssObject): float
    {
        if (!$cvssObject instanceof Cvss4Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $initialValue = $this->lookupMicroVector($cvssObject->getMicroVector());

        if (!is_float($initialValue)) {
            throw new \RuntimeException('Invalid initial value');
        }

        $lowerVectors = $cvssObject->getLowerVectors();

        if (
            !is_string($lowerVectors[1]) ||
            !is_string($lowerVectors[2]) ||
            !is_string($lowerVectors[3]) ||
            !is_string($lowerVectors[4]) ||
            !is_string($lowerVectors[5])
        ) {
            throw new \RuntimeException('Invalid Lower Vector Generated');
        }

        $lowerVectorValues = [
            1 => $this->lookupMicroVector($lowerVectors[1]),
            2 => $this->lookupMicroVector($lowerVectors[2]),
            3 => $this->lookupMicroVector($lowerVectors[3]),
            4 => $this->lookupMicroVector($lowerVectors[4]),
            5 => $this->lookupMicroVector($lowerVectors[5]),
        ];

        if ($cvssObject->eq3 === '0' && $cvssObject->eq6 === '0' && isset($lowerVectors[6]) && is_string($lowerVectors[6])) {
            $lowerVectorValues[3] = $this->calculateHighestEqValue($lowerVectors[3], $lowerVectors[6]);
        }

        $maxVector = $this->getMaxVector($cvssObject);
        $severityDistance = $this->calculateSeverityDistance($cvssObject, $maxVector);

        $availableDistance = $this->calculateAvailableDistance($initialValue, $lowerVectorValues);
        $finalValue = $initialValue - $this->calculateMeanDistance($cvssObject, $severityDistance, $availableDistance);

        if ($finalValue < 0.0) {
            return 0.0;
        }

        if ($finalValue > 10.0) {
            return 10.0;
        }

        return round($finalValue, 1);
    }

    public function calculateTemporalScore(CvssObject $cvssObject): float
    {
        return $this->calculateBaseScore($cvssObject);
    }

    public function calculateEnvironmentalScore(CvssObject $cvssObject): float
    {
        return $this->calculateBaseScore($cvssObject);
    }

    private function lookupMicroVector(string $vector): ?float
    {
        if (!isset($this->vectorLookup[$vector]) || !is_float($this->vectorLookup[$vector])) {
            return null;
        }

        return $this->vectorLookup[$vector];
    }

    private function calculateHighestEqValue(string $leftVector, string $rightVector): ?float
    {
        $eqThreeScore = $this->lookupMicroVector($leftVector);
        $eqSixScore = $this->lookupMicroVector($rightVector);

        if ($eqThreeScore > $eqSixScore) {
            return $eqThreeScore;
        }

        return $eqSixScore;
    }

    private function getMaxVector(Cvss4Object $cvssObject): Cvss4Object
    {
        if (
            !isset(
                $this->maxComposed[1][$cvssObject->eq1],
                $this->maxComposed[2][$cvssObject->eq2],
                $this->maxComposed[3][$cvssObject->eq3][$cvssObject->eq6],
                $this->maxComposed[4][$cvssObject->eq4],
                $this->maxComposed[5][$cvssObject->eq5]
            ) ||
            !is_array($this->maxComposed[1][$cvssObject->eq1]) ||
            !is_array($this->maxComposed[2][$cvssObject->eq2]) ||
            !is_array($this->maxComposed[3][$cvssObject->eq3][$cvssObject->eq6]) ||
            !is_array($this->maxComposed[4][$cvssObject->eq4]) ||
            !is_array($this->maxComposed[5][$cvssObject->eq5])
        ) {
            throw new \RuntimeException('Error');
        }
        $parser = new Cvss40Parser();

        /** @var string $eq1Vector */
        foreach ($this->maxComposed[1][$cvssObject->eq1] as $eq1Vector) {
            /** @var string $eq2Vector */
            foreach ($this->maxComposed[2][$cvssObject->eq2] as $eq2Vector) {
                /** @var string $eq3Vector */
                foreach ($this->maxComposed[3][$cvssObject->eq3][$cvssObject->eq6] as $eq3Vector) {
                    /** @var string $eq4Vector */
                    foreach ($this->maxComposed[4][$cvssObject->eq4] as $eq4Vector) {
                        /** @var string $eq5Vector */
                        foreach ($this->maxComposed[5][$cvssObject->eq5] as $eq5Vector) {
                            $maxVector = $parser->parseVector($eq1Vector . $eq2Vector . $eq3Vector . $eq4Vector . $eq5Vector);
                            if ($maxVector->validMaxVector($cvssObject)) {
                                return $maxVector;
                            }
                        }
                    }
                }
            }
        }

        return new Cvss4Object('', '', '', '', '', '');
    }

    /**
     * @param float $initalValue
     * @param float[]|null[] $lowerValues
     * @return Cvss4Distance
     */
    private function calculateAvailableDistance(float $initalValue, array $lowerValues): Cvss4Distance
    {
        $availableDistance = new Cvss4Distance();

        if ($lowerValues[1]) {
            $availableDistance->eqOne = $initalValue - $lowerValues[1];
        }
        if ($lowerValues[2]) {
            $availableDistance->eqTwo = $initalValue - $lowerValues[2];
        }
        if ($lowerValues[3]) {
            $availableDistance->eqThree = $initalValue - $lowerValues[3];
        }
        if ($lowerValues[4]) {
            $availableDistance->eqFour = $initalValue - $lowerValues[4];
        }
        if ($lowerValues[5]) {
            $availableDistance->eqFive = $initalValue - $lowerValues[5];
        }

        return $availableDistance;
    }

    private function calculateSeverityDistance(Cvss4Object $cvssObject, Cvss4Object $maxVector): Cvss4Distance
    {
        return new Cvss4Distance(
            eqOne: $maxVector->getSeverityDistanceAV($cvssObject) +
            $maxVector->getSeverityDistancePR($cvssObject) +
            $maxVector->getSeverityDistanceUI($cvssObject),
            eqTwo: $maxVector->getSeverityDistanceAC($cvssObject) + $maxVector->getSeverityDistanceAT($cvssObject),
            eqThree: $maxVector->getSeverityDistanceVC($cvssObject) +
            $maxVector->getSeverityDistanceVI($cvssObject) +
            $maxVector->getSeverityDistanceVA($cvssObject) +
            $maxVector->getSeverityDistanceCR($cvssObject) +
            $maxVector->getSeverityDistanceIR($cvssObject) +
            $maxVector->getSeverityDistanceAR($cvssObject),
            eqFour: $maxVector->getSeverityDistanceSC($cvssObject) +
            $maxVector->getSeverityDistanceSI($cvssObject) +
            $maxVector->getSeverityDistanceSA($cvssObject)
        );
    }

    private function calculateMeanDistance(Cvss4Object $cvssObject, Cvss4Distance $severityDistance, Cvss4Distance $availableDistance): float
    {
        $normalisedSeverity = new Cvss4Distance();
        $existingLower = 0;

        if ($availableDistance->eqOne) {
            $existingLower++;

            if (!isset($this->maxSeverity[1][$cvssObject->eq1]) || !is_int($this->maxSeverity[1][$cvssObject->eq1])) {
                throw new \RuntimeException('Invalid Max severity');
            }

            $maxSeverityOne = $this->maxSeverity[1][$cvssObject->eq1] * 0.1;
            $normalisedSeverity->eqOne = $availableDistance->eqOne * ($severityDistance->eqOne / $maxSeverityOne);
        }

        if ($availableDistance->eqTwo) {
            $existingLower++;

            if (!isset($this->maxSeverity[2][$cvssObject->eq2]) || !is_int($this->maxSeverity[2][$cvssObject->eq2])) {
                throw new \RuntimeException('Invalid Max severity');
            }

            $maxSeverityTwo = $this->maxSeverity[2][$cvssObject->eq2] * 0.1;
            $normalisedSeverity->eqTwo = $availableDistance->eqTwo * ($severityDistance->eqTwo / $maxSeverityTwo);
        }

        if ($availableDistance->eqThree) {
            $existingLower++;

            if (!isset($this->maxSeverity[3][$cvssObject->eq3][$cvssObject->eq6]) || !is_int($this->maxSeverity[3][$cvssObject->eq3][$cvssObject->eq6])) {
                throw new \RuntimeException('Invalid Max severity');
            }

            $maxSeverityThree = $this->maxSeverity[3][$cvssObject->eq3][$cvssObject->eq6] * 0.1;
            $normalisedSeverity->eqThree = $availableDistance->eqThree * ($severityDistance->eqThree / $maxSeverityThree);
        }

        if ($availableDistance->eqFour) {
            $existingLower++;

            if (!isset($this->maxSeverity[4][$cvssObject->eq4]) || !is_int($this->maxSeverity[4][$cvssObject->eq4])) {
                throw new \RuntimeException('Invalid Max severity');
            }

            $maxSeverityFour = $this->maxSeverity[4][$cvssObject->eq4] * 0.1;
            $normalisedSeverity->eqFour = $availableDistance->eqFour * ($severityDistance->eqFour / $maxSeverityFour);
        }

        if ($availableDistance->eqFive) {
            $existingLower++;
            $normalisedSeverity->eqFive = 0;
        }

        if ($existingLower === 0) {
            return 0.0;
        }

        return (
                $normalisedSeverity->eqOne +
                $normalisedSeverity->eqTwo +
                $normalisedSeverity->eqThree +
                $normalisedSeverity->eqFour +
                $normalisedSeverity->eqFive
            ) / $existingLower;
    }
}
