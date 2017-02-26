<?php

namespace Tests\Unit;

use Arachne\DIHelpers\ResolverInterface;
use Arachne\Security\FirewallInterface;
use Arachne\SecurityVerification\Rules\NoIdentity;
use Arachne\SecurityVerification\Rules\NoIdentityRuleHandler;
use Arachne\Verifier\RuleInterface;
use Codeception\MockeryModule\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;
use Nette\Security\IIdentity;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class NoIdentityRuleTest extends Test
{
    /** @var NoIdentityRuleHandler */
    private $handler;

    /** @var MockInterface */
    private $firewall;

    protected function _before()
    {
        $this->firewall = Mockery::mock(FirewallInterface::class);

        $firewallResolver = Mockery::mock(ResolverInterface::class);
        $firewallResolver
            ->shouldReceive('resolve')
            ->with('Admin')
            ->andReturn($this->firewall);

        $this->handler = new NoIdentityRuleHandler($firewallResolver);
    }

    public function testNoIdentityTrue()
    {
        $rule = new NoIdentity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewall
            ->shouldReceive('getIdentity')
            ->once()
            ->andReturn();

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

        $this->firewall
            ->shouldReceive('getIdentity')
            ->once()
            ->andReturn(Mockery::mock(IIdentity::class));

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
