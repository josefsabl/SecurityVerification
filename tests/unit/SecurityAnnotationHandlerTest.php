<?php

namespace Tests\Unit;

use Arachne\SecurityAnnotations\Allowed;
use Arachne\SecurityAnnotations\InRole;
use Arachne\SecurityAnnotations\LoggedIn;
use Arachne\SecurityAnnotations\SecurityAnnotationHandler;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;

class SecurityAnnotationHandlerTest extends BaseTest
{

	/** @var SecurityAnnotationHandler */
	private $handler;

	/** @var MockInterface */
	private $user;

	/** @var MockInterface */
	private $storage;

	protected function _before()
	{
		$this->storage = Mockery::mock('Nette\Security\IUserStorage');
		$this->user = Mockery::mock('Nette\Security\User', [ $this->storage ]);
		$this->handler = new SecurityAnnotationHandler($this->user);
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

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\FailedAuthorizationException
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

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testInRoleTrue()
	{
		$annotation = new InRole();
		$annotation->role = 'role';
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isInRole directly because it's final
		$this->user
			->shouldReceive('getRoles')
			->withAnyArgs()
			->once()
			->andReturn([ 'role' ]);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\FailedAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testInRoleFalse()
	{
		$annotation = new InRole();
		$annotation->role = 'role';
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isInRole directly because it's final
		$this->user
			->shouldReceive('getRoles')
			->withAnyArgs()
			->once()
			->andReturn([]);

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testLoggedInTrue()
	{
		$annotation = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	public function testNotLoggedInTrue()
	{
		$annotation = new LoggedIn();
		$annotation->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(FALSE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\FailedAuthenticationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testLoggedInFalse()
	{
		$annotation = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\FailedNoAuthenticationException
	 * @expectedExceptionMessage User must not be logged in for this request.
	 */
	public function testNotLoggedInFalse()
	{
		$annotation = new LoggedIn();
		$annotation->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(TRUE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\InvalidArgumentException
	 */
	public function testUnknown()
	{
		$annotation = Mockery::mock('Arachne\Verifier\IAnnotation');
		$request = new Request('Test', 'GET', []);

		$this->handler->checkAnnotation($annotation, $request);
	}

}
