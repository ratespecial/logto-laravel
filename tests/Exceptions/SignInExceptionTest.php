<?php

declare(strict_types=1);

namespace Tests\Ratespecial\Logto\Exceptions;

use Orchestra\Testbench\TestCase;
use Ratespecial\Logto\Exceptions\SignInException;

class SignInExceptionTest extends TestCase
{
    public function testDetailIsHiddenOutsideDebugMode(): void
    {
        config(['app.debug' => false]);

        $ex = new SignInException('Sign-in failed', detail: 'check the resource');

        $this->assertSame('Sign-in failed', $ex->getMessage());
        $this->assertSame('check the resource', $ex->detail);
        $this->assertSame(['detail' => 'check the resource'], $ex->context());
        $this->assertSame(403, $ex->getStatusCode());
    }

    public function testDetailIsAppendedInDebugMode(): void
    {
        config(['app.debug' => true]);

        $ex = new SignInException('Sign-in failed', detail: 'check the resource');

        $this->assertSame('Sign-in failed (check the resource)', $ex->getMessage());
    }

    public function testWithoutDetailMessageIsUnchangedInDebugMode(): void
    {
        config(['app.debug' => true]);

        $ex = new SignInException('Sign-in failed');

        $this->assertSame('Sign-in failed', $ex->getMessage());
        $this->assertNull($ex->detail);
        $this->assertSame([], $ex->context());
    }
}
