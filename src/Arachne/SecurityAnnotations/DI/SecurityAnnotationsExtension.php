<?php

/**
 * This file is part of the Arachne Security Annotations extenstion
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityAnnotations\DI;

/**
 * @author Jáchym Toušek
 */
class SecurityAnnotationsExtension extends \Nette\DI\CompilerExtension
{

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();

		$builder->addDefinition($this->prefix('handler'))
			->setClass('Arachne\SecurityAnnotations\SecurityAnnotationHandler');
	}

}
