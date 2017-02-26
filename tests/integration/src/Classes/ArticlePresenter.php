<?php

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
    public function actionEdit($id)
    {
    }

    /**
     * @Privilege(resource = "Article", privilege = "hide")
     */
    public function actionHide($id)
    {
    }

    /**
     * @Privilege(resource = "Article", privilege = "hide")
     * @Privilege(resource = "Article", privilege = "edit")
     */
    public function actionDelete($id)
    {
    }

    /**
     * @Privilege(resource = "$article", privilege = "publish")
     */
    public function actionPublish(ArticleEntity $article)
    {
    }

    /**
     * @Privilege(resource = "$article.parent", privilege = "publish")
     */
    public function actionPublishParent(ArticleEntity $article)
    {
    }

    /**
     * @All({
     *   @Identity,
     *   @Role("redactor"),
     *   @Privilege(resource = "Article", privilege = "hide"),
     * })
     */
    public function actionInnerRules()
    {
    }

}
