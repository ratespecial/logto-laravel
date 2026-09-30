<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Ratespecial\Logto\Contracts\OAuthScopable;
use Ratespecial\Logto\HasOAuthScopes;

/**
 * In-test Authenticatable model backed by the `users` table the tests create.
 *
 * @property string|null $logto_sub
 * @property string|null $email
 * @property string|null $name
 */
class TestUser extends Model implements Authenticatable, OAuthScopable
{
    use HasOAuthScopes;

    protected $table = 'users';

    protected $guarded = [];

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthIdentifier(): mixed
    {
        return $this->getKey();
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void {}

    public function getRememberTokenName(): string
    {
        return '';
    }
}
