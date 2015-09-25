<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\FirewallInterface;
use Arachne\SecurityVerification\Rules\Identity;
use Arachne\SecurityVerification\Rules\IdentityRuleHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\MockeryModule\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;
use Nette\Security\IIdentity;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class IdentityRuleTest extends Test
{

	/** @var IdentityRuleHandler */
	private $handler;

	/** @var MockInterface */
	private $firewall;

	protected function _before()
	{
		$this->firewall = Mockery::mock(FirewallInterface::class);

		$firewallResolver = Mockery::mock(ResolverInterface::class);
		$firewallResolver
			->shouldReceive('resolve')
			->with('Admin')
			->andReturn($this->firewall);

		$this->handler = new IdentityRuleHandler($firewallResolver);
	}

	public function testIdentityTrue()
	{
		$rule = new Identity();
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('getIdentity')
			->once()
			->andReturn(Mockery::mock(IIdentity::class));

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\Verifier\Exception\VerificationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testIdentityFalse()
	{
		$rule = new Identity();
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('getIdentity')
			->once()
			->andReturn();

		$this->handler->checkRule($rule, $request);
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
