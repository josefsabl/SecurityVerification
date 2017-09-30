<?php

namespace Tests\Integration;

use Arachne\Codeception\Module\NetteDIModule;
use Arachne\Verifier\Verifier;
use Codeception\Test\Unit;
use Nette\Application\Request;
use Nette\Application\UI\Presenter;
use Nette\DI\Container;
use Nette\Security\Identity;
use Tests\Integration\Classes\ArticleEntity;
use Tests\Integration\Classes\ArticlePresenter;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 */
class SecurityVerificationTest extends Unit
{
    /**
     * @var NetteDIModule
     */
    protected $tester;

    /**
     * @var Verifier
     */
    private $verifier;

    public function _before(): void
    {
        $this->tester
            ->grabService(Container::class)
            ->getService('arachne.serviceCollections.1.arachne.security.firewall')
            ->__invoke('Admin')
            ->login(new Identity(1, ['redactor']));

        $this->verifier = $this->tester->grabService(Verifier::class);
    }

    public function testActionEdit(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET', [
                Presenter::ACTION_KEY => 'edit',
            ]
        );

        self::assertTrue($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    public function testActionHide(): void
    {
        $request = new Request('Admin:Article', 'GET', [
            Presenter::ACTION_KEY => 'hide',
        ]);

        self::assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    /**
     * This test requires all annotations of the same type to be checked, not just the last one.
     * It will fail if Doctrine\Common\Annotations\IndexedReader is used.
     */
    public function testActionDelete(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET',
            [
                Presenter::ACTION_KEY => 'delete',
            ]
        );

        self::assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    public function testActionPublishAllowed(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET',
            [
                Presenter::ACTION_KEY => 'publish',
                'article' => new ArticleEntity(1),
            ]
        );

        self::assertTrue($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    public function testActionPublishDisallowed(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET',
            [
                Presenter::ACTION_KEY => 'publish',
                'article' => new ArticleEntity(2),
            ]
        );

        self::assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    public function testActionPublishParentAllowed(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET',
            [
                Presenter::ACTION_KEY => 'publishparent',
                'article' => new ArticleEntity(2, new ArticleEntity(1)),
            ]
        );

        self::assertTrue($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    public function testActionPublishParentDisallowed(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET',
            [
                Presenter::ACTION_KEY => 'publishparent',
                'article' => new ArticleEntity(1, new ArticleEntity(2)),
            ]
        );

        self::assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }

    public function testInnerRules(): void
    {
        $request = new Request(
            'Admin:Article',
            'GET',
            [
                Presenter::ACTION_KEY => 'innerrules',
            ]
        );

        self::assertFalse($this->verifier->isLinkVerified($request, new ArticlePresenter()));
    }
}
