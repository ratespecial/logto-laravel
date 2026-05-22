<?php

declare(strict_types=1);

namespace Ratespecial\Logto\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * When the guard creates a new user record.
 *
 * @see LogtoApiResourceGuard
 */
class UserProvisionedEvent
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    public function __construct(public readonly Authenticatable $user) {}
}
