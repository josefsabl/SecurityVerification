<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\SecurityVerification\Rules\SecurityVerificationHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\TestCase\Test;
use Mockery;
use Nette\Application\Request;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class UnknownRuleTest extends Test
{

	/** @var SecurityVerificationHandler */
	private $handler;

	protected function _before()
	{
		$firewallResolver = Mockery::mock(ResolverInterface::class);
		$authorizatorResolver = Mockery::mock(ResolverInterface::class);

		$this->handler = new SecurityVerificationHandler($firewallResolver, $authorizatorResolver);
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\InvalidArgumentException
	 */
	public function testUnknownRule()
	{
		$rule = Mockery::mock(RuleInterface::class);
		$request = new Request('Test', 'GET', []);

		$this->handler->checkRule($rule, $request);
	}

}
