<?php

namespace Arachne\SecurityVerification\Rules;

use Arachne\Verifier\Rules\SecurityRule;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 *
 * @Annotation
 */
class NoIdentity extends SecurityRule
{
    /**
     * @var string
     */
    public $firewall;
}
