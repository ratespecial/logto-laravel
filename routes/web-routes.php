<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Ratespecial\Logto\Controllers\WebAuthController;

/*
 * Browser sign-in routes.  Loaded, under the configured prefix and middleware, when `logto.web.routes` is true.
 * The middleware group must include sessions (the default `web` group does).
 */
Route::middleware(array_filter(explode(',', (string) config('logto.web.middleware'))))
    ->prefix(config('logto.web.prefix'))
    ->group(function () {
        Route::get('sign-in', [WebAuthController::class, 'signIn'])->name('logto.sign-in');
        Route::get('callback', [WebAuthController::class, 'callback'])->name('logto.callback');
        Route::post('sign-out', [WebAuthController::class, 'signOut'])->name('logto.sign-out');
    });
