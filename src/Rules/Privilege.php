<?php

namespace Arachne\SecurityVerification\Rules;

use Arachne\Verifier\Rules\SecurityRule;

/**
 * @author Jáchym Toušek <enumag@gmail.com>
 *
 * @Annotation
 */
class Privilege extends SecurityRule
{

    /** @var string */
    public $resource;

    /** @var string */
    public $privilege;

    /** @var string */
    public $authorizator;

}
