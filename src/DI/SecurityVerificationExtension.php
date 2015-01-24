<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification\DI;

use Arachne\SecurityVerification\Exception\LogicException;
use Arachne\Verifier\DI\VerifierExtension;
use Nette\DI\CompilerExtension;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationExtension extends CompilerExtension
{

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();

		$extensions = $this->compiler->getExtensions('Arachne\Security\DI\SecurityExtension');
		if (count($extensions) !== 1) {
			throw new LogicException('Extension Arachne\Security\DI\SecurityExtension is not installed.');
		}
		$extension = reset($extensions);

		$builder->addDefinition($this->prefix('handler.allowed'))
			->setClass('Arachne\SecurityVerification\Rules\AllowedRuleHandler')
			->setArguments(array(
				'authorizatorResolver' => $extension->prefix('@authorizatorResolver'),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\Allowed',
			));

		$builder->addDefinition($this->prefix('handler.inRole'))
			->setClass('Arachne\SecurityVerification\Rules\InRoleRuleHandler')
			->setArguments(array(
				'firewallResolver' => $extension->prefix('@firewallResolver'),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\InRole',
			));

		$builder->addDefinition($this->prefix('handler.loggedIn'))
			->setClass('Arachne\SecurityVerification\Rules\LoggedInRuleHandler')
			->setArguments(array(
				'firewallResolver' => $extension->prefix('@firewallResolver'),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\LoggedIn',
			));
	}

}
