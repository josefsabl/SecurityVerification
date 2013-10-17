<?php

namespace Tests\Integration\Arachne\Verifier;

use Codeception\TestCase\Test;

abstract class BaseTest extends Test
{

	/** @var \TestGuy */
	protected $guy;

	protected function _before()
	{
		$this->guy = $this->codeGuy;
	}

}
