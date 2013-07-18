<?php

namespace Tests\Integration\Arachne\Verifier;

final class SecurityAnnotationHandlerTest extends BaseTest
{

	public function _before()
	{
		parent::_before();
		$this->guy->grabService('Nette\Security\User');
	}

	public function testSomething()
	{

	}

}
