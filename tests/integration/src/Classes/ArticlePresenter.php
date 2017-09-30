<?php

declare(strict_types=1);

namespace Tests\Integration\Classes;

use Arachne\SecurityVerification\Rules\Identity;
use Arachne\SecurityVerification\Rules\Privilege;
use Arachne\SecurityVerification\Rules\Role;
use Arachne\Verifier\Rules\All;
use Nette\Application\UI\Presenter;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 *
 * @Identity
 * @Role("redactor")
 */
class ArticlePresenter extends Presenter
{
    /**
     * @Privilege(resource = "Article", privilege = "edit")
     */
    public function actionEdit($id): void
    {
    }

    /**
     * @Privilege(resource = "Article", privilege = "hide")
     */
    public function actionHide($id): void
    {
    }

    /**
     * @Privilege(resource = "Article", privilege = "hide")
     * @Privilege(resource = "Article", privilege = "edit")
     */
    public function actionDelete($id): void
    {
    }

    /**
     * @Privilege(resource = "$article", privilege = "publish")
     */
    public function actionPublish(ArticleEntity $article): void
    {
    }

    /**
     * @Privilege(resource = "$article.parent", privilege = "publish")
     */
    public function actionPublishParent(ArticleEntity $article): void
    {
    }

    /**
     * @All({
     *   @Identity,
     *   @Role("redactor"),
     *   @Privilege(resource = "Article", privilege = "hide"),
     * })
     */
    public function actionInnerRules(): void
    {
    }
}
