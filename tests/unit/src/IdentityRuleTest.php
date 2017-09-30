<?php

declare(strict_types=1);

namespace Tests\Unit;

use Arachne\Security\Authentication\FirewallInterface;
use Arachne\SecurityVerification\Exception\InvalidArgumentException;
use Arachne\SecurityVerification\Rules\Identity;
use Arachne\SecurityVerification\Rules\IdentityRuleHandler;
use Arachne\Verifier\Exception\VerificationException;
use Arachne\Verifier\RuleInterface;
use Codeception\Test\Unit;
use Eloquent\Phony\Mock\Handle\InstanceHandle;
use Eloquent\Phony\Phpunit\Phony;
use Nette\Application\Request;
use Nette\Security\IIdentity;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class IdentityRuleTest extends Unit
{
    /**
     * @var IdentityRuleHandler
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

        $this->handler = new IdentityRuleHandler($firewallResolver);
    }

    public function testIdentityTrue(): void
    {
        $rule = new Identity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(Phony::mock(IIdentity::class)->get());

        $this->handler->checkRule($rule, $request);
    }

    public function testIdentityFalse(): void
    {
        $rule = new Identity();
        $request = new Request('Admin:Test', 'GET', []);

        $this->firewallHandle
            ->getIdentity
            ->returns(null);

        try {
            $this->handler->checkRule($rule, $request);
            self::fail();
        } catch (VerificationException $e) {
            self::assertSame('User must be logged in for this request.', $e->getMessage());
        }
    }

    public function testUnknownRule(): void
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
