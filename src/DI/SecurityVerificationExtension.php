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
 * @author Jáchym Toušek
 */
class SecurityVerificationExtension extends CompilerExtension
{

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();

		$builder->addDefinition($this->prefix('handler'))
			->setClass('Arachne\SecurityVerification\Rules\SecurityVerificationHandler')
			->addTag(VerifierExtension::TAG_HANDLER, array(
				'Arachne\SecurityVerification\Rules\LoggedIn',
				'Arachne\SecurityVerification\Rules\InRole',
				'Arachne\SecurityVerification\Rules\Allowed',
			));
	}

}
