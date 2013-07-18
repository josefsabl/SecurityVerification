<?php

namespace Tests\Integration\Arachne\Verifier;

abstract class BaseTest extends \Codeception\TestCase\Test
{

	/** @var \TestGuy */
	protected $guy;

	protected function _before()
	{
		$this->guy = $this->codeGuy;
	}

}
