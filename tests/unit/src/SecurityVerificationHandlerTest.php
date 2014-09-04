<?php

namespace Tests\Unit;

use Arachne\SecurityVerification\Allowed;
use Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException;
use Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException;
use Arachne\SecurityVerification\InRole;
use Arachne\SecurityVerification\LoggedIn;
use Arachne\SecurityVerification\SecurityVerificationHandler;
use Arachne\Verifier\IRule;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;
use Nette\Security\IResource;
use Nette\Security\User;

/**
 * @author Jáchym Toušek
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
		$annotation = new Allowed();
		$annotation->resource = 'resource';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'resource / privilege' is not granted.
	 */
	public function testAllowedFalse()
	{
		$annotation = new Allowed();
		$annotation->resource = 'resource';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($annotation, $request);
		} catch (FailedPrivilegeAuthorizationException $e) {
			$this->assertSame('resource', $e->getResource());
			$this->assertSame('privilege', $e->getPrivilege());
			throw  $e;
		}
	}

	public function testAllowedThis()
	{
		$annotation = new Allowed();
		$annotation->resource = '$this';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'Test / privilege' is not granted.
	 */
	public function testAllowedThisFalse()
	{
		$annotation = new Allowed();
		$annotation->resource = '$this';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);
		$this->user
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($annotation, $request);
		} catch (FailedPrivilegeAuthorizationException $e) {
			$this->assertSame('Test', $e->getResource());
			$this->assertSame('privilege', $e->getPrivilege());
			throw  $e;
		}
	}

	public function testAllowedResource()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$entity = Mockery::mock(IResource::class);
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->user
			->shouldReceive('isAllowed')
			->with($entity, 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'entity / privilege' is not granted.
	 */
	public function testAllowedResourceFalse()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
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
			$this->handler->checkRule($annotation, $request);
		} catch (FailedPrivilegeAuthorizationException $e) {
			$this->assertSame($entity, $e->getResource());
			$this->assertSame('privilege', $e->getPrivilege());
			throw  $e;
		}
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Missing parameter '$entity' in given request.
	 */
	public function testAllowedWrongParameter()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->handler->checkRule($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Parameter '$entity' is not an instance of Nette\Security\IResource.
	 */
	public function testAllowedMissingParameter()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$entity = Mockery::mock();
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->handler->checkRule($annotation, $request);
	}

	public function testInRoleTrue()
	{
		$annotation = new InRole();
		$annotation->role = 'role';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isInRole')
			->with('role')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedRoleAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testInRoleFalse()
	{
		$annotation = new InRole();
		$annotation->role = 'role';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isInRole')
			->with('role')
			->once()
			->andReturn(FALSE);

		try {
			$this->handler->checkRule($annotation, $request);
		} catch (FailedRoleAuthorizationException $e) {
			$this->assertSame('role', $e->getRole());
			throw  $e;
		}
	}

	public function testLoggedInTrue()
	{
		$annotation = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($annotation, $request));
	}

	public function testNotLoggedInTrue()
	{
		$annotation = new LoggedIn();
		$annotation->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(FALSE);

		$this->assertNull($this->handler->checkRule($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedAuthenticationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testLoggedInFalse()
	{
		$annotation = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(FALSE);

		$this->handler->checkRule($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\FailedNoAuthenticationException
	 * @expectedExceptionMessage User must not be logged in for this request.
	 */
	public function testNotLoggedInFalse()
	{
		$annotation = new LoggedIn();
		$annotation->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isLoggedIn')
			->once()
			->andReturn(TRUE);

		$this->handler->checkRule($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityVerification\Exception\InvalidArgumentException
	 */
	public function testUnknownAnnotation()
	{
		$annotation = Mockery::mock(IRule::class);
		$request = new Request('Test', 'GET', []);

		$this->handler->checkRule($annotation, $request);
	}

}
