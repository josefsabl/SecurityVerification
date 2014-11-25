<?php

namespace Tests\Integration\Classes;

use Arachne\SecurityVerification\Allowed;
use Arachne\SecurityVerification\InRole;
use Arachne\SecurityVerification\LoggedIn;
use Nette\Application\UI\Presenter;

/**
 * @author Jáchym Toušek
 *
 * @LoggedIn
 * @InRole("redactor")
 */
class ArticlePresenter extends Presenter
{

	/**
	 * @Allowed(resource = "Article", privilege = "edit")
	 */
	public function actionEdit($id)
	{
	}

	/**
	 * @Allowed(resource = "Article", privilege = "hide")
	 */
	public function actionHide($id)
	{
	}

	/**
	 * @Allowed(resource = "Article", privilege = "hide")
	 * @Allowed(resource = "Article", privilege = "edit")
	 */
	public function actionDelete($id)
	{
	}

	/**
	 * @Allowed(resource = "$article", privilege = "publish")
	 */
	public function actionPublish(ArticleEntity $article)
	{
	}

	/**
	 * @Allowed(resource = "$article.parent", privilege = "publish")
	 */
	public function actionPublishParent(ArticleEntity $article)
	{
	}

}
