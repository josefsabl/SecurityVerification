<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\FirewallInterface;
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\Rules\InRole;
use Arachne\SecurityVerification\Rules\SecurityVerificationHandler;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class InRoleRuleTest extends Test
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

	public function testInRoleTrue()
	{
		$rule = new InRole();
		$rule->role = 'role';
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('isInRole')
			->with('role')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testInRoleFalse()
	{
		$rule = new InRole();
		$rule->role = 'role';
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('isInRole')
			->with('role')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($rule, $request);
		} catch (FailedRoleAuthorizationException $e) {
			$this->assertSame('role', $e->getRole());
			throw $e;
		}
	}

}
