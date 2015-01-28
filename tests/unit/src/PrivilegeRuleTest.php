<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\AuthorizatorInterface;
use Arachne\SecurityVerification\Rules\Privilege;
use Arachne\SecurityVerification\Rules\PrivilegeRuleHandler;
use Arachne\Verifier\Exception\VerificationException;
use Arachne\Verifier\RuleInterface;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;
use Nette\Security\IResource;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class PrivilegeRuleTest extends Test
{

	/** @var PrivilegeRuleHandler */
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

		$this->handler = new PrivilegeRuleHandler($authorizatorResolver);
	}

	public function testPrivilegeTrue()
	{
		$rule = new Privilege();
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
	 * @expectedException \Arachne\Verifier\Exception\VerificationException
	 * @expectedExceptionMessage Required privilege 'resource / privilege' is not granted.
	 */
	public function testPrivilegeFalse()
	{
		$rule = new Privilege();
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
		} catch (VerificationException $e) {
			$this->assertSame($rule, $e->getRule());
			throw $e;
		}
	}

	public function testPrivilegeThis()
	{
		$rule = new Privilege();
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
	 * @expectedException \Arachne\Verifier\Exception\VerificationException
	 * @expectedExceptionMessage Required privilege 'Test / privilege' is not granted.
	 */
	public function testPrivilegeThisFalse()
	{
		$rule = new Privilege();
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
		} catch (VerificationException $e) {
			$this->assertSame($rule, $e->getRule());
			throw $e;
		}
	}

	public function testPrivilegeResource()
	{
		$rule = new Privilege();
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
	 * @expectedException \Arachne\Verifier\Exception\VerificationException
	 * @expectedExceptionMessage Required privilege 'entity / privilege' is not granted.
	 */
	public function testPrivilegeResourceFalse()
	{
		$rule = new Privilege();
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
		} catch (VerificationException $e) {
			$this->assertSame($rule, $e->getRule());
			throw $e;
		}
	}

	/**
	 * @expectedException \Symfony\Component\PropertyAccess\Exception\NoSuchPropertyException
	 */
	public function testPrivilegeWrongParameter()
	{
		$rule = new Privilege();
		$rule->resource = '$entity';
		$rule->privilege = 'privilege';
		$request = new Request('Admin:Test', 'GET', []);

		$this->handler->checkRule($rule, $request);
	}

	/**
	 * @expectedException \Arachne\SecurityVerification\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Resource '$entity' is not an instance of Nette\Security\IResource.
	 */
	public function testPrivilegedMissingParameter()
	{
		$rule = new Privilege();
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
