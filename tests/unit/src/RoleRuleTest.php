<?php

namespace Tests\Unit;

use Arachne\Security\Authentication\FirewallInterface;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Rules\Role;
use Arachne\SecurityVerification\Rules\RoleRuleHandler;
use Arachne\Verifier\Exception\VerificationException;
use Arachne\Verifier\RuleInterface;
use Codeception\Test\Unit;
use Eloquent\Phony\Mock\Handle\InstanceHandle;
use Eloquent\Phony\Phpunit\Phony;
use Nette\Application\Request;
use Nette\Security\Identity;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class RoleRuleTest extends Unit
{
    /**
     * @var RoleRuleHandler
     */
    private $handler;

    /**
     * @var InstanceHandle
     */
    private $firewallHandle;

    protected function _before()
    {
        $this->firewallHandle = Phony::mock(FirewallInterface::class);

        $firewallResolver = Phony::stub();
        $firewallResolver
            ->with('Admin')
            ->returns($this->firewallHandle->get());

        $this->handler = new RoleRuleHandler($firewallResolver);
    }

    public function testRoleTrue()
    {
        $rule = new Role();
        $rule->role = 'role';
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(new Identity(null, ['role']));

        $this->handler->checkRule($rule, $request);
    }

    public function testRoleFalse()
    {
        $rule = new Role();
        $rule->role = 'role';
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(new Identity(null, []));

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (VerificationException $e) {
            self::assertSame('Role \'role\' is required for this request.', $e->getMessage());
            self::assertSame($rule, $e->getRule());
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
