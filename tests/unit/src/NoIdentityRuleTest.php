<?php

declare(strict_types=1);

namespace Tests\Unit;

use Arachne\Security\Authentication\FirewallInterface;
use Arachne\SecurityVerification\Rules\NoIdentity;
use Arachne\SecurityVerification\Rules\NoIdentityRuleHandler;
use Arachne\Verifier\Exception\VerificationException;
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

    protected function _before(): void
    {
        $this->firewallHandle = Phony::mock(FirewallInterface::class);

        $firewallResolver = Phony::stub();
        $firewallResolver
            ->with('Admin')
            ->returns($this->firewallHandle->get());

        $this->handler = new NoIdentityRuleHandler($firewallResolver);
    }

    public function testNoIdentityTrue(): void
    {
        $rule = new NoIdentity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(null);

        $this->handler->checkRule($rule, $request);
    }

    public function testNoIdentityFalse(): void
    {
        $rule = new NoIdentity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(Phony::mock(IIdentity::class)->get());

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (VerificationException $e) {
            self::assertSame('User must not be logged in for this request.', $e->getMessage());
        }
    }
}
