<?php

namespace Tests\Unit;

use Arachne\Security\Authentication\FirewallInterface;
use Arachne\SecurityVerification\Rules\NoIdentity;
use Arachne\SecurityVerification\Rules\NoIdentityRuleHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\Test\Unit;
use Eloquent\Phony\Mock\Handle\InstanceHandle;
use Eloquent\Phony\Phpunit\Phony;
use Nette\Application\Request;
use Nette\Security\IIdentity;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class NoIdentityRuleTest extends Unit
{
    /**
     * @var NoIdentityRuleHandler
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

        $this->handler = new NoIdentityRuleHandler($firewallResolver);
    }

    public function testNoIdentityTrue()
    {
        $rule = new NoIdentity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(null);

        $this->assertNull($this->handler->checkRule($rule, $request));
    }

    /**
     * @expectedException \Arachne\Verifier\Exception\VerificationException
     * @expectedExceptionMessage User must not be logged in for this request.
     */
    public function testNoIdentityFalse()
    {
        $rule = new NoIdentity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(Phony::mock(IIdentity::class)->get());

        $this->handler->checkRule($rule, $request);
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
