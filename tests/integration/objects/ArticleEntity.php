<?php

namespace Tests\Integration;

class ArticleEntity extends \Nette\Object implements \Nette\Security\IResource
{

	private $ownerId;

	public function __construct($ownerId)
	{
		$this->ownerId = $ownerId;
	}

	public function getOwnerId()
	{
		return $this->ownerId;
	}

	public function getResourceId()
	{
		return 'Article';
	}

}
