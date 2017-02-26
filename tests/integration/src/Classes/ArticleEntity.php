<?php

namespace Tests\Integration\Classes;

use Nette\Security\IResource;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class ArticleEntity implements IResource
{
    private $ownerId;

    private $parent;

    public function __construct($ownerId, ArticleEntity $parent = null)
    {
        $this->ownerId = $ownerId;
        $this->parent = $parent;
    }

    public function getOwnerId()
    {
        return $this->ownerId;
    }

    public function getParent()
    {
        return $this->parent;
    }

    public function getResourceId()
    {
        return 'Article';
    }
}
