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

		$builder->addDefinition($this->prefix('handler.allowed'))
			->setClass('Arachne\SecurityVerification\Rules\AllowedRuleHandler')
			->setArguments(array(
				'authorizatorResolver' => '@' . $extension->getResolver(SecurityExtension::TAG_AUTHORIZATOR),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\Allowed',
			));

		$builder->addDefinition($this->prefix('handler.inRole'))
			->setClass('Arachne\SecurityVerification\Rules\InRoleRuleHandler')
			->setArguments(array(
				'firewallResolver' => '@' . $extension->getResolver(SecurityExtension::TAG_FIREWALL),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\InRole',
			));

		$builder->addDefinition($this->prefix('handler.loggedIn'))
			->setClass('Arachne\SecurityVerification\Rules\LoggedInRuleHandler')
			->setArguments(array(
				'firewallResolver' => '@' . $extension->getResolver(SecurityExtension::TAG_FIREWALL),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\LoggedIn',
			));
	}

}
