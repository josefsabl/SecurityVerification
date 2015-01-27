<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification\DI;

use Arachne\DIHelpers\CompilerExtension;
use Arachne\Security\DI\SecurityExtension;
use Arachne\Verifier\DI\VerifierExtension;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationExtension extends CompilerExtension
{

	public function loadConfiguration()
	{
		$this->getExtension('Arachne\Security\DI\SecurityExtension');
		$extension = $this->getExtension('Arachne\DIHelpers\DI\DIHelpersExtension');

		$builder = $this->getContainerBuilder();

		$builder->addDefinition($this->prefix('handler.loggedIn'))
			->setClass('Arachne\SecurityVerification\Rules\LoggedInRuleHandler')
			->setArguments([
				'firewallResolver' => '@' . $extension->getResolver(SecurityExtension::TAG_FIREWALL),
			])
			->addTag(VerifierExtension::TAG_HANDLER, [
				'Arachne\SecurityVerification\Rules\LoggedIn',
			]);

		$builder->addDefinition($this->prefix('handler.role'))
			->setClass('Arachne\SecurityVerification\Rules\RoleRuleHandler')
			->setArguments([
				'firewallResolver' => '@' . $extension->getResolver(SecurityExtension::TAG_FIREWALL),
			])
			->addTag(VerifierExtension::TAG_HANDLER, [
				'Arachne\SecurityVerification\Rules\Role',
			]);

		$builder->addDefinition($this->prefix('handler.privilege'))
			->setClass('Arachne\SecurityVerification\Rules\PrivilegeRuleHandler')
			->setArguments([
				'authorizatorResolver' => '@' . $extension->getResolver(SecurityExtension::TAG_AUTHORIZATOR),
			])
			->addTag(VerifierExtension::TAG_HANDLER, [
				'Arachne\SecurityVerification\Rules\Privilege',
			]);
	}

}
