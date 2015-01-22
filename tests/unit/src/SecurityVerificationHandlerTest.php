<?php

namespace Tests\Unit;

use Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException;
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\Rules\Allowed;
use Arachne\SecurityVerification\Rules\InRole;
use Arachne\SecurityVerification\Rules\LoggedIn;
use Arachne\SecurityVerification\Rules\SecurityVerificationHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;
use Nette\Security\IResource;
use Nette\Security\User;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationHandlerTest extends Test
{

	/** @var SecurityVerificationHandler */
	private $handler;

	/** @var MockInterface */
	private $user;

	protected function _before()
	{
		$this->user = Mockery::mock(User::class);
		$this->handler = new SecurityVerificationHandler($this->user);
	}

	public function testAllowedTrue()
	{
		$rule = new Allowed();
		$rule->resource = 'resource';
		$rule->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'resource / privilege' is not granted.
	 */
	public function testAllowedFalse()
	{
		$rule = new Allowed();
		$rule->resource = 'resource';
		$rule->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($rule, $request);
		} catch (FailedPrivilegeAuthorizationException $e) {
			$this->assertSame('resource', $e->getResource());
			$this->assertSame('privilege', $e->getPrivilege());
			throw $e;
		}
	}

	public function testAllowedThis()
	{
		$rule = new Allowed();
		$rule->resource = '$this';
		$rule->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'Test / privilege' is not granted.
	 */
	public function testAllowedThisFalse()
	{
		$rule = new Allowed();
		$rule->resource = '$this';
		$rule->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);
		$this->user
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($rule, $request);
		} catch (FailedPrivilegeAuthorizationException $e) {
			$this->assertSame('Test', $e->getResource());
			$this->assertSame('privilege', $e->getPrivilege());
			throw $e;
		}
	}

	public function testAllowedResource()
	{
		$rule = new Allowed();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$entity = Mockery::mock(IResource::class);
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->user
			->shouldReceive('isAllowed')
			->with($entity, 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'entity / privilege' is not granted.
	 */
	public function testAllowedResourceFalse()
	{
		$rule = new Allowed();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$entity = Mockery::mock(IResource::class);
		$entity
			->shouldReceive('getResourceId')
			->once()
			->andReturn('entity');
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->user
			->shouldReceive('isAllowed')
			->with($entity, 'privilege')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($rule, $request);
		} catch (FailedPrivilegeAuthorizationException $e) {
			$this->assertSame($entity, $e->getResource());
			$this->assertSame('privilege', $e->getPrivilege());
			throw $e;
		}
	}

	/**
	 * @expectedException Symfony\Component\PropertyAccess\Exception\NoSuchPropertyException
	 */
	public function testAllowedWrongParameter()
	{
		$rule = new Allowed();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->handler->checkRule($rule, $request);
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Resource '$entity' is not an instance of Nette\Security\IResource.
	 */
	public function testAllowedMissingParameter()
	{
		$rule = new Allowed();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$entity = Mockery::mock();
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->handler->checkRule($rule, $request);
	}

	public function testInRoleTrue()
	{
		$rule = new InRole();
		$rule->role = 'role';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isInRole')
			->with('role')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testInRoleFalse()
	{
		$rule = new InRole();
		$rule->role = 'role';
		$request = new Request('Test', 'GET', []);

		$this->user
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

	public function testLoggedInTrue()
	{
		$rule = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	public function testNotLoggedInTrue()
	{
		$rule = new LoggedIn();
		$rule->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(FALSE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedAuthenticationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testLoggedInFalse()
	{
		$rule = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(FALSE);

		$this->handler->checkRule($rule, $request);
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedNoAuthenticationException
	 * @expectedExceptionMessage User must not be logged in for this request.
	 */
	public function testNotLoggedInFalse()
	{
		$rule = new LoggedIn();
		$rule->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(TRUE);

		$this->handler->checkRule($rule, $request);
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\InvalidArgumentException
	 */
	public function testUnknownRule()
	{
		$rule = Mockery::mock(RuleInterface::class);
		$request = new Request('Test', 'GET', []);

		$this->handler->checkRule($rule, $request);
	}

}
