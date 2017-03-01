<?php

namespace Tests\Unit;

use Arachne\Security\Authorization\AuthorizatorInterface;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Rules\Privilege;
use Arachne\SecurityVerification\Rules\PrivilegeRuleHandler;
use Arachne\Verifier\Exception\VerificationException;
use Arachne\Verifier\RuleInterface;
use Codeception\Test\Unit;
use Eloquent\Phony\Mock\Handle\InstanceHandle;
use Eloquent\Phony\Phpunit\Phony;
use Nette\Application\Request;
use Nette\Security\IResource;
use Symfony\Component\PropertyAccess\Exception\NoSuchPropertyException;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class PrivilegeRuleTest extends Unit
{
    /**
     * @var PrivilegeRuleHandler
     */
    private $handler;

    /**
     * @var InstanceHandle
     */
    private $authorizatorHandle;

    protected function _before()
    {
        $this->authorizatorHandle = Phony::mock(AuthorizatorInterface::class);

        $authorizatorResolver = Phony::stub();
        $authorizatorResolver
            ->with('Admin')
            ->returns($this->authorizatorHandle->get());

        $this->handler = new PrivilegeRuleHandler($authorizatorResolver);
    }

    public function testPrivilegeTrue()
    {
        $rule = new Privilege();
        $rule->resource = 'resource';
        $rule->privilege = 'privilege';
        $request = new Request('Admin:Test', 'GET', []);

        $this->authorizatorHandle
            ->isAllowed
            ->with('resource', 'privilege')
            ->returns(true);

        $this->handler->checkRule($rule, $request);
    }

    public function testPrivilegeFalse()
    {
        $rule = new Privilege();
        $rule->resource = 'resource';
        $rule->privilege = 'privilege';
        $request = new Request('Admin:Test', 'GET', []);

        $this->authorizatorHandle
            ->isAllowed
            ->with('resource', 'privilege')
            ->returns(false);

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (VerificationException $e) {
            self::assertSame('Required privilege \'resource / privilege\' is not granted.', $e->getMessage());
            self::assertSame($rule, $e->getRule());
        }
    }

    public function testPrivilegeThis()
    {
        $rule = new Privilege();
        $rule->resource = '$this';
        $rule->privilege = 'privilege';
        $request = new Request('Admin:Test', 'GET', []);

        $this->authorizatorHandle
            ->isAllowed
            ->with('Test', 'privilege')
            ->returns(true);

        $this->handler->checkRule($rule, $request);
    }

    public function testPrivilegeThisFalse()
    {
        $rule = new Privilege();
        $rule->resource = '$this';
        $rule->privilege = 'privilege';
        $request = new Request('Admin:Test', 'GET', []);

        $this->authorizatorHandle
            ->isAllowed
            ->with('Test', 'privilege')
            ->returns(false);

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (VerificationException $e) {
            self::assertSame('Required privilege \'Test / privilege\' is not granted.', $e->getMessage());
            self::assertSame($rule, $e->getRule());
        }
    }

    public function testPrivilegeResource()
    {
        $rule = new Privilege();
        $rule->resource = '$entity';
        $rule->privilege = 'privilege';
        $entity = Phony::mock(IResource::class)->get();
        $request = new Request(
            'Admin:Test',
            'GET',
            [
                'entity' => $entity,
            ]
        );

        $this->authorizatorHandle
            ->isAllowed
            ->with($entity, 'privilege')
            ->returns(true);

        $this->handler->checkRule($rule, $request);
    }

    public function testPrivilegeResourceFalse()
    {
        $rule = new Privilege();
        $rule->resource = '$entity';
        $rule->privilege = 'privilege';

        $entityHandle = Phony::mock(IResource::class);
        $entityHandle
            ->getResourceId
            ->returns('entity');

        $entity = $entityHandle->get();

        $request = new Request(
            'Admin:Test',
            'GET',
            [
                'entity' => $entity,
            ]
        );

        $this->authorizatorHandle
            ->isAllowed
            ->with($entity, 'privilege')
            ->returns(false);

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (VerificationException $e) {
            self::assertSame('Required privilege \'entity / privilege\' is not granted.', $e->getMessage());
            self::assertSame($rule, $e->getRule());
        }
    }

    public function testPrivilegeWrongParameter()
    {
        $rule = new Privilege();
        $rule->resource = '$entity';
        $rule->privilege = 'privilege';
        $request = new Request('Admin:Test', 'GET', []);

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (NoSuchPropertyException $e) {
        }
    }

    public function testPrivilegedMissingParameter()
    {
        $rule = new Privilege();
        $rule->resource = '$entity';
        $rule->privilege = 'privilege';
        $entity = Phony::mock()->get();
        $request = new Request(
            'Admin:Test',
            'GET',
            [
                'entity' => $entity,
            ]
        );

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (InvalidArgumentException $e) {
            self::assertSame('Resource \'$entity\' is not an instance of Nette\Security\IResource.', $e->getMessage());
        }
    }

    public function testUnknownRule()
    {
        $rule = Phony::mock(RuleInterface::class)->get();
        $request = new Request('Test', 'GET', []);

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (InvalidArgumentException $e) {
        }
    }
}
