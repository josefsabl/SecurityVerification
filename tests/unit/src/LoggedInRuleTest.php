<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\FirewallInterface;
use Arachne\SecurityVerification\Rules\LoggedIn;
use Arachne\SecurityVerification\Rules\SecurityVerificationHandler;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class LoggedInRuleTest extends Test
{

	/** @var SecurityVerificationHandler */
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
			->once()
			->andReturn($this->firewall);

		$authorizatorResolver = Mockery::mock(ResolverInterface::class);

		$this->handler = new SecurityVerificationHandler($firewallResolver, $authorizatorResolver);
	}

	public function testLoggedInTrue()
	{
		$rule = new LoggedIn();
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	public function testNotLoggedInTrue()
	{
		$rule = new LoggedIn();
		$rule->flag = FALSE;
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(FALSE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedAuthenticationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testLoggedInFalse()
	{
		$rule = new LoggedIn();
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(FALSE);

		$this->handler->checkRule($rule, $request);
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedNoAuthenticationException
	 * @expectedExceptionMessage User must not be logged in for this request.
	 */
	public function testNotLoggedInFalse()
	{
		$rule = new LoggedIn();
		$rule->flag = FALSE;
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(TRUE);

		$this->handler->checkRule($rule, $request);
	}

}
