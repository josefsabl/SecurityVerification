<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\AuthorizatorInterface;
use Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException;
use Arachne\SecurityVerification\Rules\Allowed;
use Arachne\SecurityVerification\Rules\AllowedRuleHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;
use Nette\Security\IIdentity;
use Nette\Security\IResource;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class AllowedRuleTest extends Test
{

	/** @var SecurityVerificationHandler */
	private $handler;

	/** @var MockInterface */
	private $authorizator;

	protected function _before()
	{
		$this->authorizator = Mockery::mock(AuthorizatorInterface::class);

		$authorizatorResolver = Mockery::mock(ResolverInterface::class);
		$authorizatorResolver
			->shouldReceive('resolve')
			->with('Admin')
			->andReturn($this->authorizator);

		$this->handler = new AllowedRuleHandler($authorizatorResolver);
	}

	public function testAllowedTrue()
	{
		$rule = new Allowed();
		$rule->resource = 'resource';
		$rule->privilege = 'privilege';
		$request = new Request('Admin:Test', 'GET', []);

		$this->authorizator
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'resource / privilege' is not granted.
	 */
	public function testAllowedFalse()
	{
		$rule = new Allowed();
		$rule->resource = 'resource';
		$rule->privilege = 'privilege';
		$request = new Request('Admin:Test', 'GET', []);

		$this->authorizator
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
		$request = new Request('Admin:Test', 'GET', []);

		$this->authorizator
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
	 * @expectedExceptionMessage Required privilege 'Test / privilege' is not granted.
	 */
	public function testAllowedThisFalse()
	{
		$rule = new Allowed();
		$rule->resource = '$this';
		$rule->privilege = 'privilege';
		$request = new Request('Admin:Test', 'GET', []);

		$this->authorizator
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
		$request = new Request('Admin:Test', 'GET', [
			'entity' => $entity,
		]);

		$this->authorizator
			->shouldReceive('isAllowed')
			->with($entity, 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkRule($rule, $request));
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\FailedPrivilegeAuthorizationException
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

		$request = new Request('Admin:Test', 'GET', [
			'entity' => $entity,
		]);

		$this->authorizator
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
	 * @expectedException \Symfony\Component\PropertyAccess\Exception\NoSuchPropertyException
	 */
	public function testAllowedWrongParameter()
	{
		$rule = new Allowed();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$request = new Request('Admin:Test', 'GET', []);

		$this->handler->checkRule($rule, $request);
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Resource '$entity' is not an instance of Nette\Security\IResource.
	 */
	public function testAllowedMissingParameter()
	{
		$rule = new Allowed();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$entity = Mockery::mock();
		$request = new Request('Admin:Test', 'GET', [
			'entity' => $entity,
		]);

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
