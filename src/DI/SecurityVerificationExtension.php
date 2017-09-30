<?php

declare(strict_types=1);

namespace Arachne\SecurityVerification\DI;

use Arachne\Security\DI\SecurityExtension;
use Arachne\SecurityVerification\Rules\Identity;
use Arachne\SecurityVerification\Rules\IdentityRuleHandler;
use Arachne\SecurityVerification\Rules\NoIdentity;
use Arachne\SecurityVerification\Rules\NoIdentityRuleHandler;
use Arachne\SecurityVerification\Rules\Privilege;
use Arachne\SecurityVerification\Rules\PrivilegeRuleHandler;
use Arachne\SecurityVerification\Rules\Role;
use Arachne\SecurityVerification\Rules\RoleRuleHandler;
use Arachne\ServiceCollections\DI\ServiceCollectionsExtension;
use Arachne\Verifier\DI\VerifierExtension;
use Nette\DI\CompilerExtension;
use Nette\Utils\AssertionException;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationExtension extends CompilerExtension
{
    public function loadConfiguration(): void
    {
        $this->getExtension(SecurityExtension::class);

        $builder = $this->getContainerBuilder();

        $builder->addDefinition($this->prefix('handler.identity'))
            ->setType(IdentityRuleHandler::class)
            ->addTag(
                VerifierExtension::TAG_HANDLER,
                [
                    Identity::class,
                ]
            );

        $builder->addDefinition($this->prefix('handler.noIdentity'))
            ->setType(NoIdentityRuleHandler::class)
            ->addTag(
                VerifierExtension::TAG_HANDLER,
                [
                    NoIdentity::class,
                ]
            );

        $builder->addDefinition($this->prefix('handler.privilege'))
            ->setType(PrivilegeRuleHandler::class)
            ->addTag(
                VerifierExtension::TAG_HANDLER,
                [
                    Privilege::class,
                ]
            );

        $builder->addDefinition($this->prefix('handler.role'))
            ->setType(RoleRuleHandler::class)
            ->addTag(
                VerifierExtension::TAG_HANDLER,
                [
                    Role::class,
                ]
            );
    }

    public function beforeCompile(): void
    {
        $builder = $this->getContainerBuilder();

        /** @var ServiceCollectionsExtension $serviceCollectionsExtension */
        $serviceCollectionsExtension = $this->getExtension(ServiceCollectionsExtension::class);

        $firewallResolver = $serviceCollectionsExtension->getCollection(
            ServiceCollectionsExtension::TYPE_RESOLVER,
            SecurityExtension::TAG_FIREWALL
        );

        $authorizatorResolver = $serviceCollectionsExtension->getCollection(
            ServiceCollectionsExtension::TYPE_RESOLVER,
            SecurityExtension::TAG_AUTHORIZATOR
        );

        $builder->getDefinition($this->prefix('handler.identity'))
            ->setArguments(
                [
                    'firewallResolver' => '@'.$firewallResolver,
                ]
            );

        $builder->getDefinition($this->prefix('handler.noIdentity'))
            ->setArguments(
                [
                    'firewallResolver' => '@'.$firewallResolver,
                ]
            );

        $builder->getDefinition($this->prefix('handler.privilege'))
            ->setArguments(
                [
                    'authorizatorResolver' => '@'.$authorizatorResolver,
                ]
            );

        $builder->getDefinition($this->prefix('handler.role'))
            ->setArguments(
                [
                    'firewallResolver' => '@'.$firewallResolver,
                ]
            );
    }

    private function getExtension(string $class): CompilerExtension
    {
        $extensions = $this->compiler->getExtensions($class);

        if (!$extensions) {
            throw new AssertionException(
                sprintf('Extension "%s" requires "%s" to be installed.', get_class($this), $class)
            );
        }

        return reset($extensions);
    }
}
