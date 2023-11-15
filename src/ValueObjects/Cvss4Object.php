<?php

namespace Rootshell\Cvss\ValueObjects;

class Cvss4Object extends CvssObject
{
    public function __construct(
        public string $eq1,
        public string $eq2,
        public string $eq3,
        public string $eq4,
        public string $eq5,
        public string $eq6,
        public ?float $av = null,
        public ?float $pr = null,
        public ?float $ui = null,
        public ?float $ac = null,
        public ?float $at = null,
        public ?float $vc = null,
        public ?float $vi = null,
        public ?float $va = null,
        public ?float $sc = null,
        public ?float $si = null,
        public ?float $sa = null,
        public ?float $cr = null,
        public ?float $ir = null,
        public ?float $ar = null,
        public ?float $e = null,
    ) {
    }

    public function getMicroVector(): string
    {
        return $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . $this->eq6;
    }

    public function getLowerVectors(): array
    {
        $vectors = [
            1 => ((int)$this->eq1 + 1) . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . $this->eq6,
            2 => $this->eq1 . ((int)$this->eq2 + 1) . $this->eq3 . $this->eq4 . $this->eq5 . $this->eq6,
            4 => $this->eq1 . $this->eq2 . $this->eq3 . ((int)$this->eq4 + 1) . $this->eq5 . $this->eq6,
            5 => $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . ((int)$this->eq5 + 1) . $this->eq6,
        ];

        if ($this->eq3 === '0' && $this->eq6 === '0') {
            $vectors[3] = $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . ((int)$this->eq6 + 1);
            $vectors[6] = $this->eq1 . $this->eq2 . ((int)$this->eq3 + 1) . $this->eq4 . $this->eq5 . $this->eq6;

            return $vectors;
        }

        $vectors[3] = match ($this->eq3 . $this->eq6) {
            '11', '01' => $this->eq1 . $this->eq2 . ((int)$this->eq3 + 1) . $this->eq4 . $this->eq5 . $this->eq6,
            '10' => $this->eq1 . $this->eq2 . $this->eq3 . $this->eq4 . $this->eq5 . ((int)$this->eq6 + 1),
            default => $this->eq1 . $this->eq2 . ((int)$this->eq3 + 1) . $this->eq4 . $this->eq5 . ((int)$this->eq6 + 1),
        };

        return $vectors;
    }
}