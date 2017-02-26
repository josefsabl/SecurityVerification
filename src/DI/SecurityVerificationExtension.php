<?php

namespace Arachne\SecurityVerification\DI;

use Arachne\DIHelpers\CompilerExtension;
use Arachne\Security\DI\SecurityExtension;
use Arachne\Verifier\DI\VerifierExtension;
use Nette\Utils\AssertionException;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationExtension extends CompilerExtension
{

    public function loadConfiguration()
    {
        $this->getExtension('Arachne\Security\DI\SecurityExtension');

        $builder = $this->getContainerBuilder();

        $builder->addDefinition($this->prefix('handler.identity'))
            ->setClass('Arachne\SecurityVerification\Rules\IdentityRuleHandler')
            ->addTag(VerifierExtension::TAG_HANDLER, [
                'Arachne\SecurityVerification\Rules\Identity',
            ]);

        $builder->addDefinition($this->prefix('handler.noIdentity'))
            ->setClass('Arachne\SecurityVerification\Rules\NoIdentityRuleHandler')
            ->addTag(VerifierExtension::TAG_HANDLER, [
                'Arachne\SecurityVerification\Rules\NoIdentity',
            ]);

        $builder->addDefinition($this->prefix('handler.privilege'))
            ->setClass('Arachne\SecurityVerification\Rules\PrivilegeRuleHandler')
            ->addTag(VerifierExtension::TAG_HANDLER, [
                'Arachne\SecurityVerification\Rules\Privilege',
            ]);

        $builder->addDefinition($this->prefix('handler.role'))
            ->setClass('Arachne\SecurityVerification\Rules\RoleRuleHandler')
            ->addTag(VerifierExtension::TAG_HANDLER, [
                'Arachne\SecurityVerification\Rules\Role',
            ]);
    }

    public function beforeCompile()
    {
        $builder = $this->getContainerBuilder();

        if ($extension = $this->getExtension('Arachne\DIHelpers\DI\ResolversExtension', false)) {
            $firewallResolver = $extension->get(SecurityExtension::TAG_FIREWALL);
            $authorizatorResolver = $extension->get(SecurityExtension::TAG_AUTHORIZATOR);
        } elseif ($extension = $this->getExtension('Arachne\DIHelpers\DI\DIHelpersExtension', false)) {
            $firewallResolver = $extension->getResolver(SecurityExtension::TAG_FIREWALL);
            $authorizatorResolver = $extension->getResolver(SecurityExtension::TAG_AUTHORIZATOR);
        } else {
            throw new AssertionException('Cannot get resolvers because arachne/di-helpers is not properly installed.');
        }

        $builder->getDefinition($this->prefix('handler.identity'))
            ->setArguments([
                'firewallResolver' => '@' . $firewallResolver,
            ]);

        $builder->getDefinition($this->prefix('handler.noIdentity'))
            ->setArguments([
                'firewallResolver' => '@' . $firewallResolver,
            ]);

        $builder->getDefinition($this->prefix('handler.privilege'))
            ->setArguments([
                'authorizatorResolver' => '@' . $authorizatorResolver,
            ]);

        $builder->getDefinition($this->prefix('handler.role'))
            ->setArguments([
                'firewallResolver' => '@' . $firewallResolver,
            ]);
    }

}
