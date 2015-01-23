<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityVerification\DI;

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
			throw new \Exception();
		}
		$extension = reset($extensions);

		$builder->addDefinition($this->prefix('handler'))
			->setClass('Arachne\SecurityVerification\Rules\SecurityVerificationHandler')
			->setArguments(array(
				'firewallResolver' => $extension->prefix('@firewallResolver'),
				'authorizatorResolver' => $extension->prefix('@authorizatorResolver'),
			))
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\LoggedIn',
				'Arachne\SecurityVerification\Rules\InRole',
				'Arachne\SecurityVerification\Rules\Allowed',
			));
	}

}
