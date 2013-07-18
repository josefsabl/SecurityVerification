<?php

namespace Tests\Arachne\Verifier;

use Mockery;

final class SecurityAnnotationHandlerTest extends BaseTest
{

	/** @var \Arachne\SecurityAnnotations\SecurityAnnotationHandler */
	private $handler;

	/** @var \Mockery\MockInterface */
	private $user;

	/** @var \Mockery\MockInterface */
	private $storage;

	protected function _before()
	{
		$this->storage = Mockery::mock('Nette\Security\IUserStorage');
		$this->user = Mockery::mock('Nette\Security\User', [ $this->storage ]);
		$this->handler = new \Arachne\SecurityAnnotations\SecurityAnnotationHandler($this->user);
	}

	public function testAllowedTrue()
	{
		$annotation = new \Arachne\SecurityAnnotations\Allowed('resource', 'privilege');
		$request = new \Nette\Application\Request('Test', 'GET', []);

		$this->user
				->shouldReceive('isAllowed')
				->with('resource', 'privilege')
				->once()
				->andReturn(TRUE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityAnnotations\FailedAuthorizationException
	 * @expectedExceptionMessage Required privilege 'resource / privilege' is not granted.
	 */
	public function testAllowedFalse()
	{
		$annotation = new \Arachne\SecurityAnnotations\Allowed('resource', 'privilege');
		$request = new \Nette\Application\Request('Test', 'GET', []);

		$this->user
				->shouldReceive('isAllowed')
				->with('resource', 'privilege')
				->once()
				->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testInRoleTrue()
	{
		$annotation = new \Arachne\SecurityAnnotations\InRole('role');
		$request = new \Nette\Application\Request('Test', 'GET', []);

		// can't redefine User::isInRole directly because it's final
		$this->user
				->shouldReceive('getRoles')
				->withAnyArgs()
				->once()
				->andReturn([ 'role' ]);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityAnnotations\FailedAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testInRoleFalse()
	{
		$annotation = new \Arachne\SecurityAnnotations\InRole('role');
		$request = new \Nette\Application\Request('Test', 'GET', []);

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
		$annotation = new \Arachne\SecurityAnnotations\LoggedIn(TRUE);
		$request = new \Nette\Application\Request('Test', 'GET', []);

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
		$annotation = new \Arachne\SecurityAnnotations\LoggedIn(FALSE);
		$request = new \Nette\Application\Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
				->shouldReceive('isAuthenticated')
				->withAnyArgs()
				->once()
				->andReturn(FALSE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityAnnotations\FailedAuthenticationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testLoggedInFalse()
	{
		$annotation = new \Arachne\SecurityAnnotations\LoggedIn(TRUE);
		$request = new \Nette\Application\Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
				->shouldReceive('isAuthenticated')
				->withAnyArgs()
				->once()
				->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException \Arachne\SecurityAnnotations\FailedAuthenticationException
	 * @expectedExceptionMessage User must not be logged in for this request.
	 */
	public function testNotLoggedInFalse()
	{
		$annotation = new \Arachne\SecurityAnnotations\LoggedIn(FALSE);
		$request = new \Nette\Application\Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
				->shouldReceive('isAuthenticated')
				->withAnyArgs()
				->once()
				->andReturn(TRUE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException \Arachne\SecurityAnnotations\InvalidArgumentException
	 */
	public function testUnknown()
	{
		$annotation = Mockery::mock('Arachne\Verifier\IAnnotation');
		$request = new \Nette\Application\Request('Test', 'GET', []);

		$this->handler->checkAnnotation($annotation, $request);
	}

}
