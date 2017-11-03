<?php

declare(strict_types=1);

namespace Tests\Integration\Classes;

use Nette\Security\IResource;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class ArticleEntity implements IResource
{
    /**
     * @var int
     */
    private $ownerId;

    /**
     * @var ArticleEntity|null
     */
    private $parent;

    public function __construct(int $ownerId, ?self $parent = null)
    {
        $this->ownerId = $ownerId;
        $this->parent = $parent;
    }

    public function getOwnerId(): int
    {
        return $this->ownerId;
    }

    public function getParent(): ?self
    {
        return $this->parent;
    }

    public function getResourceId(): string
    {
        return 'Article';
    }
}
