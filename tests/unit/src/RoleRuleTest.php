<?php

namespace Tests\Unit;

use Arachne\Security\Authentication\FirewallInterface;
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

    /**
     * @expectedException \Arachne\Verifier\Exception\VerificationException
     * @expectedExceptionMessage Role 'role' is required for this request.
     */
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
        } catch (VerificationException $e) {
            $this->assertSame($rule, $e->getRule());
            throw $e;
        }
    }

    /**
     * @expectedException \Arachne\SecurityVerification\Exception\InvalidArgumentException
     */
    public function testUnknownRule()
    {
        $rule = Phony::mock(RuleInterface::class)->get();
        $request = new Request('Test', 'GET', []);

        $this->handler->checkRule($rule, $request);
    }
}
