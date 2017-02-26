<?php

namespace Arachne\SecurityVerification\Rules;

use Arachne\Verifier\Rules\SecurityRule;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 *
 * @Annotation
 */
class Role extends SecurityRule
{

    /** @var string */
    public $role;

    /** @var string */
    public $firewall;

}
