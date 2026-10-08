<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto;

use PHPUnit\Framework\TestCase;
use Ratespecial\Logto\HasOAuthScopes;
use Tests\Ratespecial\Logto\Fixtures\TestUser;

/**
 * @see HasOAuthScopes
 */
class HasOAuthScopesTest extends TestCase
{
    public function testGetOAuthScopesIsEmptyByDefault(): void
    {
        $this->assertSame([], (new TestUser())->getOAuthScopes());
    }

    public function testGetOAuthScopesReturnsScopesFromSpaceSeparatedString(): void
    {
        $user = new TestUser();
        $user->setOAuthScopes(' user:read  user:write ');

        $this->assertSame(['user:read', 'user:write'], $user->getOAuthScopes());
    }

    public function testGetOAuthScopesReturnsListFromArray(): void
    {
        $user = new TestUser();
        $user->setOAuthScopes(['user:read', 'feature:read']);

        $this->assertSame(['user:read', 'feature:read'], $user->getOAuthScopes());
    }

    public function testGetOAuthScopesReflectsLatestSet(): void
    {
        $user = new TestUser();
        $user->setOAuthScopes('user:read user:write');
        $user->setOAuthScopes('admin');

        $this->assertSame(['admin'], $user->getOAuthScopes());
    }
}
