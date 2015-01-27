<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\FirewallInterface;
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\Rules\Role;
use Arachne\SecurityVerification\Rules\RoleRuleHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class RoleRuleTest extends Test
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
			->andReturn($this->firewall);

		$this->handler = new RoleRuleHandler($firewallResolver);
	}

	public function testRoleTrue()
	{
		$rule = new Role();
		$rule->role = 'role';
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('getIdentity->getRoles')
			->once()
			->andReturn([ 'role' ]);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testRoleFalse()
	{
		$rule = new Role();
		$rule->role = 'role';
		$request = new Request('Admin:Test', 'GET', []);

		$this->firewall
			->shouldReceive('getIdentity->getRoles')
			->once()
			->andReturn([]);

		try {
			$this->handler->checkRule($rule, $request);
		} catch (FailedRoleAuthorizationException $e) {
			$this->assertSame('role', $e->getRole());
			throw $e;
		}
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
