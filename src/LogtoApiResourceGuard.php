<?php

declare(strict_types=1);

namespace Ratespecial\Logto;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Ratespecial\Logto\Contracts\OAuthScopable;
use Ratespecial\Logto\Events\UserProvisionedEvent;
use Ratespecial\Logto\Services\LogtoTokenValidator;
use Throwable;

/**
 * Ensures:
 * - JWT is valid and signed by Logto application
 * - JWT audience is this Laravel API
 * - JWT scope isn't blank, meaning they have permission to do at least one action here
 *
 * Will JIT provision a user if they don't exist
 */
class LogtoApiResourceGuard implements Guard
{
    use GuardHelpers;

    /**
     * @param  class-string<Authenticatable>  $userModel
     * @param  array<string, string>  $modelAttributes  Mapping of JWT claim name => user model attribute name.
     */
    public function __construct(
        private readonly Request $request,
        private readonly LogtoTokenValidator $validator,
        private readonly string $userModel,
        private readonly array $modelAttributes = [],
    ) {}

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $claims = $this->resolveClaims();
        if ($claims === null) {
            return null;
        }

        $this->user = $this->resolveUser($claims);

        return $this->user;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * @return array<string, mixed>|null
     */
    protected function resolveClaims(): ?array
    {
        $token = $this->request->bearerToken();
        if ($token === null) {
            return null;
        }

        try {
            $claims = $this->validator->validate($token);
        } catch (Throwable $ex) {
            return $this->reject("invalid token: {$ex->getMessage()}");
        }

        if (empty($claims['sub'])) {
            return $this->reject('missing subject');
        }

        // User can get a token for any resource as long as it exists; require at least one scope here
        if (empty($claims['scope'])) {
            return $this->reject('empty scope');
        }

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function resolveUser(array $claims): Authenticatable
    {
        /** @var Model $model */
        $model = new $this->userModel();
        /** @var Authenticatable&Model&OAuthScopable $user */
        $user = $model->newQuery()->updateOrCreate(
            ['logto_sub' => $claims['sub']],
            $this->mapClaimsToAttributes($claims),
        );

        $user->setOAuthScopes((string) $claims['scope']);

        if ($user->wasRecentlyCreated) {
            UserProvisionedEvent::dispatch($user);
        }

        return $user;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    protected function mapClaimsToAttributes(array $claims): array
    {
        $attributes = [];
        foreach ($this->modelAttributes as $claim => $field) {
            if (! empty($claims[$claim])) {
                $attributes[$field] = $claims[$claim];
            }
        }

        return $attributes;
    }

    protected function reject(string $reason): null
    {
        Log::debug("Logto JWT rejected: {$reason}");

        return null;
    }
}
